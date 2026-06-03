// Forwards an allowed request to the real upstream server: HTTPS via rustls
// validating the host's real system roots, or plaintext HTTP. Returns the
// upstream response with a boxed body.

use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Shared upstream client. Built once, cloned cheaply.
#[derive(Clone)]
pub(crate) struct Forwarder {
    https: Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        BoxBody<Bytes, BoxError>,
    >,
}

impl Forwarder {
    pub(crate) fn new() -> std::io::Result<Self> {
        // with_native_roots validates upstream against the host's system trust
        // store (default feature native-tokio). Returns io::Result.
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()?
            .https_or_http()
            .enable_http1()
            .build();
        let https = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self { https })
    }

    /// Forward `req` (which must already carry an absolute URI with scheme/host)
    /// and return the upstream response with a boxed body.
    pub(crate) async fn forward(
        &self,
        req: Request<BoxBody<Bytes, BoxError>>,
    ) -> Result<Response<BoxBody<Bytes, BoxError>>, BoxError> {
        let resp = self.https.request(req).await?;
        Ok(resp.map(|b| b.map_err(|e| Box::new(e) as BoxError).boxed()))
    }
}

/// Adapt a hyper `Incoming` body to the boxed body type used end to end.
pub(crate) fn box_incoming(body: Incoming) -> BoxBody<Bytes, BoxError> {
    body.map_err(|e| Box::new(e) as BoxError).boxed()
}
