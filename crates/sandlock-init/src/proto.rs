//! Control protocol between the daemon and the in-sandbox `sandlock-init`.
//! Newline-delimited JSON; `RunExec` additionally carries 3 SCM_RIGHTS fds.
use serde::{Deserialize, Serialize};

/// Fixed fd number the daemon maps the control channel onto in the child.
pub const CONTROL_FD: i32 = 3;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "req", rename_all = "lowercase")]
pub enum Req {
    RunMain { argv: Vec<String>, env: Vec<(String, String)>, cwd: Option<String> },
    RunExec { argv: Vec<String>, env: Vec<(String, String)>, cwd: Option<String>, detach: bool },
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "resp", rename_all = "lowercase")]
pub enum Resp {
    Started { pid: i32 },
    Exited { pid: i32, code: Option<i32>, signal: Option<i32> },
    Err { msg: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn req_roundtrip() {
        let r = Req::RunExec { argv: vec!["sh".into()], env: vec![("A".into(),"1".into())], cwd: Some("/".into()), detach: false };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("runexec"));
        assert!(matches!(serde_json::from_str::<Req>(&j).unwrap(), Req::RunExec { .. }));
    }
    #[test]
    fn resp_roundtrip() {
        let r = Resp::Exited { pid: 7, code: Some(0), signal: None };
        let j = serde_json::to_string(&r).unwrap();
        assert!(matches!(serde_json::from_str::<Resp>(&j).unwrap(), Resp::Exited { pid: 7, .. }));
    }
}
