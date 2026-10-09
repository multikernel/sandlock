//! Stand-in for the HTTP ACL proxy when sandlock is built without the `http`
//! feature. The builder rejects every HTTP option first; these errors only
//! guard a policy that skipped the builder, such as a deserialized one.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use crate::http::HttpRule;

pub(crate) type OrigDestMap = Arc<std::sync::RwLock<HashMap<SocketAddr, IpAddr>>>;

pub(crate) struct CaMaterial {
    pub(crate) cert_pem: String,
    pub(crate) key_pem: String,
}

pub(crate) struct HttpAclProxyHandle {
    pub(crate) addr: SocketAddr,
    pub(crate) orig_dest: OrigDestMap,
}

fn disabled() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "sandlock was built without the \"http\" feature")
}

pub(crate) fn resolve_ca(_: Option<&Path>, _: Option<&Path>, _: bool) -> io::Result<Option<CaMaterial>> {
    Err(disabled())
}

pub(crate) async fn spawn_transparent_proxy(
    _: Vec<HttpRule>,
    _: Vec<HttpRule>,
    _: Arc<Vec<crate::credential::InjectRule>>,
    _: Option<&str>,
    _: Option<&str>,
    _: Option<Arc<dyn Fn(&str, &str, &str) + Send + Sync>>,
) -> io::Result<HttpAclProxyHandle> {
    Err(disabled())
}
