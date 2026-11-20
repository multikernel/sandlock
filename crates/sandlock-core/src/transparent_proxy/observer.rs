//! Runs the observation callbacks on their own thread.
//!
//! The proxy shares a runtime with the supervisor, so a slow callback there
//! would slow syscall handling. The proxy only sends messages; this thread
//! calls the trait. Mirrors `policy_fn::spawn_policy_fn`.

use std::collections::HashMap;

use hyper::body::Bytes;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::PollSender;

use crate::http::{HttpEnd, HttpExchange, HttpObserver, HttpRequestEvent, HttpResponseEvent};

/// Owned, because it crosses a thread.
pub(crate) struct OwnedRequest {
    pub(crate) method: String,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) headers: crate::http::HeaderMap,
    pub(crate) allowed: bool,
}

pub(crate) enum ObsMsg {
    /// The reply says whether the observer took the exchange.
    Begin {
        id: u64,
        request: Box<OwnedRequest>,
        reply: oneshot::Sender<bool>,
    },
    ReqChunk {
        id: u64,
        bytes: Bytes,
    },
    /// The reply says whether the observer wants the response body.
    Response {
        id: u64,
        status: u16,
        headers: Box<crate::http::HeaderMap>,
        reply: oneshot::Sender<bool>,
    },
    RespChunk {
        id: u64,
        bytes: Bytes,
    },
    End {
        id: u64,
        end: HttpEnd,
    },
    /// Ends the loop. A closed channel cannot: every connection holds a sender.
    Shutdown,
}

pub(crate) type ObsSender = mpsc::Sender<ObsMsg>;

const QUEUE: usize = 64;

/// Joins the worker on drop, so a queued message is still delivered.
pub(crate) struct ObserverWorker {
    tx: ObsSender,
    /// Reserved up front, so `Drop` never waits for a slot.
    shutdown: Option<mpsc::OwnedPermit<ObsMsg>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ObserverWorker {
    pub(crate) fn sender(&self) -> ObsSender {
        self.tx.clone()
    }
}

impl Drop for ObserverWorker {
    fn drop(&mut self) {
        if let Some(p) = self.shutdown.take() {
            p.send(ObsMsg::Shutdown);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub(crate) fn spawn_observer(observer: HttpObserver) -> ObserverWorker {
    let (tx, mut rx) = mpsc::channel::<ObsMsg>(QUEUE);
    let thread = std::thread::Builder::new()
        .name("sandlock-http-observer".to_string())
        .spawn(move || {
            let mut live: HashMap<u64, Box<dyn HttpExchange>> = HashMap::new();
            while let Some(msg) = rx.blocking_recv() {
                match msg {
                    ObsMsg::Begin { id, request, reply } => {
                        let taken = observer(&HttpRequestEvent {
                            method: &request.method,
                            host: &request.host,
                            path: &request.path,
                            headers: &request.headers,
                            allowed: request.allowed,
                        });
                        let took = taken.is_some();
                        if let Some(e) = taken {
                            live.insert(id, e);
                        }
                        let _ = reply.send(took);
                    }
                    ObsMsg::ReqChunk { id, bytes } => {
                        if let Some(e) = live.get_mut(&id) {
                            e.request_chunk(&bytes);
                        }
                    }
                    ObsMsg::Response {
                        id,
                        status,
                        headers,
                        reply,
                    } => {
                        let wants = live
                            .get_mut(&id)
                            .map(|e| {
                                e.response(&HttpResponseEvent {
                                    status,
                                    headers: &headers,
                                })
                            })
                            .unwrap_or(false);
                        let _ = reply.send(wants);
                    }
                    ObsMsg::RespChunk { id, bytes } => {
                        if let Some(e) = live.get_mut(&id) {
                            e.response_chunk(&bytes);
                        }
                    }
                    ObsMsg::End { id, end } => {
                        if let Some(mut e) = live.remove(&id) {
                            e.end(end);
                        }
                    }
                    ObsMsg::Shutdown => break,
                }
            }
            // Close anything still open, rather than leave it without an end.
            for (_, mut e) in live.drain() {
                e.end(HttpEnd::Aborted);
            }
        })
        .expect("failed to spawn http-observer thread");

    ObserverWorker {
        shutdown: tx.clone().try_reserve_owned().ok(),
        tx,
        thread: Some(thread),
    }
}

pub(crate) fn set_outcome(end: &mut Option<EndGuard>, outcome: HttpEnd) {
    if let Some(g) = end.as_mut() {
        g.outcome = outcome;
    }
}

/// Sends `end` wherever it is dropped, so every exit reports once.
/// `Aborted` unless a path sets something better.
pub(crate) struct EndGuard {
    tx: ObsSender,
    id: u64,
    outcome: HttpEnd,
}

impl EndGuard {
    pub(crate) fn new(tx: ObsSender, id: u64) -> Self {
        Self {
            tx,
            id,
            outcome: HttpEnd::Aborted,
        }
    }
}

impl Drop for EndGuard {
    fn drop(&mut self) {
        let (id, end) = (self.id, self.outcome);
        // Queued here where there is room, so it cannot land after `Shutdown`.
        if let Err(mpsc::error::TrySendError::Full(msg)) = self.tx.try_send(ObsMsg::End { id, end })
        {
            let tx = self.tx.clone();
            tokio::spawn(async move { tx.send(msg).await });
        }
    }
}

/// Copies each chunk to the observer thread on its way through.
///
/// Only the response body carries the [`EndGuard`]: on the request body the
/// exchange would end when the upload finished.
pub(crate) struct TeeBody<B> {
    inner: B,
    tx: PollSender<ObsMsg>,
    id: u64,
    is_response: bool,
    end: Option<EndGuard>,
}

impl<B> TeeBody<B> {
    pub(crate) fn new(
        inner: B,
        tx: ObsSender,
        id: u64,
        is_response: bool,
        end: Option<EndGuard>,
    ) -> Self {
        Self {
            inner,
            tx: PollSender::new(tx),
            id,
            is_response,
            end,
        }
    }

    /// `Bytes` is reference counted, so the clone shares the buffer.
    fn chunk(&mut self, data: &Bytes) {
        let id = self.id;
        let bytes = data.clone();
        let _ = self.tx.send_item(if self.is_response {
            ObsMsg::RespChunk { id, bytes }
        } else {
            ObsMsg::ReqChunk { id, bytes }
        });
    }

    fn finish(&mut self, outcome: HttpEnd) {
        if let Some(g) = self.end.as_mut() {
            g.outcome = outcome;
        }
    }
}

impl<B> hyper::body::Body for TeeBody<B>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        // A full queue stops bodies being read, instead of buffering them.
        match this.tx.poll_reserve(cx) {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(Ok(())) => {}
            // Worker gone: forward without observing.
            std::task::Poll::Ready(Err(_)) => {}
        }
        let polled = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
        // Nothing to send, so the slot goes back rather than being held idle.
        if polled.is_pending() {
            this.tx.abort_send();
        }
        match &polled {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.chunk(data);
                }
                // A known-length body is dropped without ever polling to `None`.
                if this.inner.is_end_stream() {
                    this.finish(HttpEnd::Complete);
                }
            }
            std::task::Poll::Ready(None) => this.finish(HttpEnd::Complete),
            std::task::Poll::Ready(Some(Err(_))) => this.finish(HttpEnd::Error),
            std::task::Poll::Pending => {}
        }
        polled
    }

    /// Forwarded, or the upstream request loses the length and switches to chunked.
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}
