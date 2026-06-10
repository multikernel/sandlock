// Mints and caches per-SNI leaf certificates signed by the active MITM CA,
// producing rustls ServerConfigs for transparent TLS termination.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{Certificate, CertificateParams, DnType, KeyPair};
use rustls::pki_types::PrivateKeyDer;
use rustls::ServerConfig;

/// Holds the CA cert + key and a per-SNI cache of rustls server configs.
pub(crate) struct CertSigner {
    ca_cert: Certificate,
    ca_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertSigner {
    /// Build from the active CA's PEM (cert + key).
    pub(crate) fn new(ca_cert_pem: &str, ca_key_pem: &str) -> std::io::Result<Self> {
        let ca_key = KeyPair::from_pem(ca_key_pem).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("CA key: {e}"))
        })?;
        let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("CA cert: {e}"))
        })?;
        // self_signed consumes the params and rebuilds the CA Certificate object,
        // which we keep as the issuer and to include in the served chain.
        let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("CA rebuild: {e}"))
        })?;
        Ok(Self { ca_cert, ca_key, cache: Mutex::new(HashMap::new()) })
    }

    /// Mint (or cache-hit) a ServerConfig presenting a leaf cert for `sni`.
    pub(crate) fn server_config_for(&self, sni: &str) -> std::io::Result<Arc<ServerConfig>> {
        if let Some(cfg) = self.cache.lock().unwrap().get(sni) {
            return Ok(Arc::clone(cfg));
        }
        let leaf_key = KeyPair::generate().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("leaf keygen: {e}"))
        })?;
        // new(vec![sni]) sets subject_alt_names to a single DnsName(sni) entry.
        let mut params = CertificateParams::new(vec![sni.to_string()]).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("leaf params: {e}"))
        })?;
        // Give the leaf a subject CN distinct from the CA's subject, so the leaf
        // is not mistaken for self-signed (subject == issuer) by clients.
        params.distinguished_name.push(DnType::CommonName, sni);
        // signed_by(public_key, issuer_cert, issuer_key): leaf public key is the
        // leaf KeyPair (impl PublicKeyData), signed by the CA cert + CA key.
        let leaf = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("leaf sign: {e}"))
        })?;

        // Present only the leaf; the CA is the trust anchor in the client's store.
        let chain = vec![leaf.der().clone()];
        // rcgen serialize_der() returns PKCS#8 DER.
        let key_der = PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into());

        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key_der)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("server cfg: {e}")))?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.cache.lock().unwrap().insert(sni.to_string(), Arc::clone(&cfg));
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ca() -> (String, String) {
        // rustls 0.22 ServerConfig::builder() uses crypto::ring::default_provider()
        // directly (no process-wide install needed, unlike rustls 0.23).
        let m = crate::transparent_proxy::resolve_ca(None, None, true).unwrap().unwrap();
        (m.cert_pem, m.key_pem)
    }

    #[test]
    fn mints_distinct_configs_per_sni() {
        let (cert, key) = test_ca();
        let signer = CertSigner::new(&cert, &key).unwrap();
        let a = signer.server_config_for("api.openai.com").unwrap();
        let b = signer.server_config_for("example.com").unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn caches_by_sni() {
        let (cert, key) = test_ca();
        let signer = CertSigner::new(&cert, &key).unwrap();
        let a = signer.server_config_for("example.com").unwrap();
        let b = signer.server_config_for("example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
    }
}
