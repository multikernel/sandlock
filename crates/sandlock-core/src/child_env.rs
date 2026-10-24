// Environment for a forked child, built without std::env's setters: they take
// a process-wide lock that another thread may hold at fork time, which would
// hang the child before exec.

use std::ffi::{CStr, CString, OsString};
use std::io;
use std::marker::PhantomData;
use std::os::unix::ffi::OsStringExt;

use crate::sandbox::Sandbox;

extern "C" {
    static mut environ: *const *const libc::c_char;
}

/// `KEY=VALUE` entries for a child's environment.
pub struct ChildEnv {
    entries: Vec<CString>,
}

impl ChildEnv {
    pub fn new(vars: impl IntoIterator<Item = (OsString, OsString)>) -> io::Result<Self> {
        let entries = vars
            .into_iter()
            .map(|(key, value)| {
                let mut entry = key.into_vec();
                entry.push(b'=');
                entry.extend(value.into_vec());
                CString::new(entry).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
            })
            .collect::<io::Result<_>>()?;
        Ok(Self { entries })
    }

    /// This process's environment, read through `environ` for a process forked
    /// from a multi-threaded one, which may have inherited std's lock held.
    ///
    /// # Safety
    /// No other thread may modify the environment during the call.
    pub unsafe fn from_environ() -> Self {
        let mut entries = Vec::new();
        let mut p = environ;
        while !p.is_null() && !(*p).is_null() {
            entries.push(CStr::from_ptr(*p).to_owned());
            p = p.add(1);
        }
        Self { entries }
    }

    /// The host environment with the sandbox's `clean_env`, credential strip,
    /// `env` and GPU visibility applied, in that order.
    pub(crate) fn for_sandbox(sandbox: &Sandbox) -> io::Result<Self> {
        let mut env = if sandbox.clean_env {
            Self::new([])?
        } else {
            Self::new(std::env::vars_os())?
        };
        // Drop host vars loaded as credential sources so the agent can't read
        // the real secret, but let a placeholder from `sandbox.env` (SDKs
        // need e.g. OPENAI_API_KEY set to start) through.
        for name in &sandbox.inject_env_strip {
            env.remove(name);
        }
        for (key, value) in &sandbox.env {
            env.set(key, value)?;
        }
        // An empty list means all GPUs are visible: leave the vars unset.
        if let Some(devices) = sandbox.gpu_devices.as_ref().filter(|d| !d.is_empty()) {
            let vis = devices
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(",");
            env.set("CUDA_VISIBLE_DEVICES", &vis)?;
            env.set("ROCR_VISIBLE_DEVICES", &vis)?;
        }
        Ok(env)
    }

    pub fn set(&mut self, key: &str, value: &str) -> io::Result<()> {
        if key.is_empty() || key.contains('=') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid environment variable name {:?}", key),
            ));
        }
        self.remove(key);
        self.entries
            .extend(Self::new([(key.into(), value.into())])?.entries);
        Ok(())
    }

    pub fn remove(&mut self, key: &str) {
        self.entries
            .retain(|e| e.to_bytes().split(|&b| b == b'=').next() != Some(key.as_bytes()));
    }

    pub fn envp(&self) -> Envp<'_> {
        let ptrs = self
            .entries
            .iter()
            .map(|e| e.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        Envp {
            ptrs,
            _entries: PhantomData,
        }
    }
}

/// A NULL-terminated envp array borrowing a [`ChildEnv`]'s entries.
pub struct Envp<'a> {
    ptrs: Vec<*const libc::c_char>,
    _entries: PhantomData<&'a CStr>,
}

impl Envp<'_> {
    pub fn as_ptr(&self) -> *const *const libc::c_char {
        self.ptrs.as_ptr()
    }

    /// Make this the process environment, so getenv and execvp's PATH lookup
    /// see it.
    ///
    /// # Safety
    /// Only in a freshly forked child that never returns past this envp: the
    /// child is single-threaded, so nothing reads `environ` concurrently.
    pub unsafe fn install(&self) {
        environ = self.as_ptr();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(envp: &Envp<'_>) -> Vec<String> {
        let mut out = Vec::new();
        let mut p = envp.as_ptr();
        unsafe {
            while !(*p).is_null() {
                out.push(CStr::from_ptr(*p).to_str().unwrap().to_owned());
                p = p.add(1);
            }
        }
        out
    }

    #[test]
    fn set_overrides_and_remove_matches_whole_key() {
        let mut env = ChildEnv::new([
            ("PATH".into(), "/inherited".into()),
            ("PATHX".into(), "keep".into()),
        ])
        .unwrap();
        env.set("PATH", "/first").unwrap();
        env.set("PATH", "/last").unwrap();
        env.set("NEW", "a=b").unwrap();
        assert_eq!(
            entries(&env.envp()),
            ["PATHX=keep", "PATH=/last", "NEW=a=b"]
        );

        env.remove("PATH");
        assert_eq!(entries(&env.envp()), ["PATHX=keep", "NEW=a=b"]);
    }

    #[test]
    fn set_rejects_invalid_names() {
        let mut env = ChildEnv::new([]).unwrap();
        assert!(env.set("", "v").is_err());
        assert!(env.set("A=B", "v").is_err());
        assert!(env.set("A", "nul\0").is_err());
    }
}
