# `http_observer`: HTTP observation

`http_observer` is a callback that sees every HTTP request reaching the
transparent proxy, and optionally the bodies in both directions. It observes
only; the ACL decides what is allowed. Rust library API, no CLI flag.

Returning `Some` follows that request, `None` ignores it. Requires the `http`
feature. For HTTPS, see `--http-inject-ca` in
[`sandbox-reference.md`](sandbox-reference.md).

## The exchange

One object per request. Every method is optional.

```rust
pub trait HttpExchange: Send {
    fn request_chunk(&mut self, chunk: &[u8]) {}
    fn response(&mut self, event: &HttpResponseEvent) -> bool { false }
    fn response_chunk(&mut self, chunk: &[u8]) {}
    fn end(&mut self, end: HttpEnd) {}
}
```

| Method | When | Notes |
|---|---|---|
| the observer itself | request line and headers are parsed | gets method, host, path, headers, ACL verdict |
| `request_chunk` | per chunk, as the body is forwarded | nothing is buffered |
| `response` | status and headers are known | return `true` to receive the body |
| `response_chunk` | per chunk, as the body reaches the child | |
| `end` | once, last | `Complete`, `Error`, or `Aborted` |

Finalize in `end`. It is the only call that tells you how the exchange
finished, so a record closed anywhere else cannot tell a whole body from a
truncated one.

## Example

```rust
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use sandlock_core::http::{HttpEnd, HttpExchange, HttpResponseEvent};
use sandlock_core::Sandbox;

/// Dumps each request body, and a response body only when the call failed.
struct Dump {
    path: PathBuf,
    req: File,
    resp: Option<File>,
}

impl Dump {
    fn new(path: PathBuf) -> std::io::Result<Self> {
        let req = File::create(&path)?;
        Ok(Self { path, req, resp: None })
    }
}

impl HttpExchange for Dump {
    fn request_chunk(&mut self, chunk: &[u8]) {
        let _ = self.req.write_all(chunk);
    }

    fn response(&mut self, event: &HttpResponseEvent) -> bool {
        if event.status < 400 {
            return false;
        }
        self.resp = File::create(self.path.with_extension("resp")).ok();
        self.resp.is_some()
    }

    fn response_chunk(&mut self, chunk: &[u8]) {
        if let Some(f) = self.resp.as_mut() {
            let _ = f.write_all(chunk);
        }
    }

    fn end(&mut self, end: HttpEnd) {
        if end != HttpEnd::Complete {
            let _ = std::fs::rename(&self.path, self.path.with_extension("partial"));
        }
    }
}
```

```rust
let seq = Arc::new(AtomicUsize::new(0));
let policy = Sandbox::builder()
    .http_allow("POST api.example.com/*")
    .http_inject_ca("/etc/ssl/certs/ca-certificates.crt")
    .http_observer(Arc::new(move |event| {
        // Metadata only for anything but the API itself.
        if event.host != "api.example.com" {
            return None;
        }
        // A denial has no body and no response, so there is nothing to follow.
        if !event.allowed {
            eprintln!("denied {} {}{}", event.method, event.host, event.path);
            return None;
        }
        let n = seq.fetch_add(1, Ordering::Relaxed);
        let dump = Dump::new(PathBuf::from(format!("/tmp/dumps/{n}.req"))).ok()?;
        Some(Box::new(dump) as Box<dyn HttpExchange>)
    }))
    .build()?;
```

## Coverage

| | |
|---|---|
| Observed | HTTP/1.1 on intercepted ports, and HTTPS, which the proxy decrypts with the injected CA. An HTTP/2 client is negotiated down to 1.1 by ALPN, so it is observed too |
| Denied requests | check `event.allowed` in the observer, the only place the verdict appears; the body is unread and `response` never fires |

## Important

Callbacks run on their own thread, not the proxy runtime, so a slow callback
never delays syscall handling.

That thread is fed by one bounded queue shared by the whole proxy, so a slow
callback does hold up observed traffic. When the queue fills, bodies stop being
read rather than being buffered, and new requests wait before they are
forwarded. **Slow work belongs on a thread of your own, not in the callback.**

Request headers are captured before credential injection, so an observer never
sees an injected secret, only what the child sent itself. Those are still live
credentials: redact before writing them down.
