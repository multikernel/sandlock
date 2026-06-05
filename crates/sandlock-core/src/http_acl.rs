use std::path::Path;

use rcgen::{CertificateParams, KeyPair};

/// Pre-generated dummy CA for HTTP-only mode, avoiding per-spawn keygen cost.
fn dummy_ca() -> std::io::Result<(KeyPair, rcgen::Certificate)> {
    use rcgen::{BasicConstraints, DnType, IsCa};

    let kp = KeyPair::generate().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("keygen failed: {e}"))
    })?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // A distinct subject DN is required: leaf certs minted under this CA must
    // have a subject that differs from their issuer, otherwise an empty-DN leaf
    // looks self-signed (subject == issuer) and clients reject it.
    params.distinguished_name.push(DnType::CommonName, "sandlock MITM CA");
    let cert = params.self_signed(&kp).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("self-sign failed: {e}"))
    })?;
    Ok((kp, cert))
}

/// In-memory CA material (public cert + private key, PEM-encoded).
pub struct CaMaterial {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Resolve the CA used for HTTPS MITM.
///
/// - Both `ca_cert` and `ca_key` set: load them from disk (bring-your-own).
/// - Neither set but `generate` is true: generate an ephemeral in-memory CA.
///   The private key never touches disk.
/// - Otherwise: `None` (HTTP-only; the proxy serves plaintext and does not
///   intercept TLS).
pub fn resolve_ca(
    ca_cert: Option<&Path>,
    ca_key: Option<&Path>,
    generate: bool,
) -> std::io::Result<Option<CaMaterial>> {
    if let (Some(cert_path), Some(key_path)) = (ca_cert, ca_key) {
        let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("failed to read --http-ca {:?}: {e}", cert_path))
        })?;
        let key_pem = std::fs::read_to_string(key_path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("failed to read --http-key {:?}: {e}", key_path))
        })?;
        return Ok(Some(CaMaterial { cert_pem, key_pem }));
    }
    if generate {
        let (kp, cert) = dummy_ca()?;
        return Ok(Some(CaMaterial {
            cert_pem: cert.pem(),
            key_pem: kp.serialize_pem(),
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_ca_generate_produces_parseable_ca() {
        let m = resolve_ca(None, None, true).unwrap().expect("should generate");
        let kp = KeyPair::from_pem(&m.key_pem).expect("key parses");
        let _ = CertificateParams::from_ca_cert_pem(&m.cert_pem)
            .expect("cert parses")
            .self_signed(&kp)
            .expect("re-sign ok");
        assert!(m.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn resolve_ca_none_without_generate() {
        assert!(resolve_ca(None, None, false).unwrap().is_none());
    }
}
