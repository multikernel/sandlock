//! Stand-in for credential injection when sandlock is built without the
//! `http` feature: injection happens in the HTTP ACL proxy, which is absent.

use crate::error::SandboxError;

#[derive(Debug)]
pub enum InjectRule {}

pub fn resolve_inject_rules(
    credentials: &[String],
    inject: &[String],
) -> Result<(Vec<InjectRule>, Vec<String>), SandboxError> {
    if credentials.is_empty() && inject.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    Err(SandboxError::FeatureDisabled { what: "credential injection".into(), feature: "http" })
}
