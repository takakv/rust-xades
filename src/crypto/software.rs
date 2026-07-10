use bergshamra_crypto::sign::SigningKey;
use bergshamra_keys::key::Key;
use bergshamra_keys::loader;

use super::Signer;
use crate::error::{LibError, Result};
use crate::ns;

pub struct SoftwareSigner {
    key: Key,
    cert_der: Vec<u8>,
    algorithm_uri: String,
}

impl SoftwareSigner {
    pub fn from_pkcs12(data: &[u8], password: &str) -> Result<Self> {
        let key = loader::load_pkcs12(data, password)
            .map_err(|e| LibError::Crypto(format!("PKCS#12: {e}")))?;
        let cert_der = key
            .x509_chain
            .first()
            .cloned()
            .ok_or_else(|| LibError::Certificate("PKCS#12 bundle has no certificate".into()))?;
        Self::new(key, cert_der)
    }

    pub fn from_pem(key_pem: &[u8], cert: &[u8], password: Option<&str>) -> Result<Self> {
        let key = loader::load_pem_auto(key_pem, password)
            .map_err(|e| LibError::Crypto(format!("private key: {e}")))?;
        let cert_der = if cert.starts_with(b"-----") {
            pem_rfc7468_decode(cert)?
        } else {
            cert.to_vec()
        };
        Self::new(key, cert_der)
    }

    fn new(key: Key, cert_der: Vec<u8>) -> Result<Self> {
        let signing_key = key
            .to_signing_key()
            .ok_or_else(|| LibError::Crypto("unsupported key".into()))?;
        let algorithm_uri = default_algorithm(&signing_key)?.to_owned();
        Ok(Self {
            key,
            cert_der,
            algorithm_uri,
        })
    }

    pub fn with_algorithm(mut self, uri: impl Into<String>) -> Self {
        self.algorithm_uri = uri.into();
        self
    }
}

impl Signer for SoftwareSigner {
    fn algorithm_uri(&self) -> &str {
        &self.algorithm_uri
    }

    fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signing_key = self
            .key
            .to_signing_key()
            .ok_or_else(|| LibError::Crypto("unsupported key".into()))?;
        let alg = bergshamra_crypto::sign::from_uri(&self.algorithm_uri)?;
        Ok(alg.sign(&signing_key, data)?)
    }
}

fn default_algorithm(key: &SigningKey) -> Result<&'static str> {
    match key {
        SigningKey::Rsa(_) => Ok(ns::RSA_SHA256),
        SigningKey::EcP256(_) => Ok(ns::ECDSA_SHA256),
        SigningKey::EcP384(_) => Ok(ns::ECDSA_SHA384),
        SigningKey::EcP521(_) => Ok(ns::ECDSA_SHA512),
        _ => Err(LibError::Unsupported(
            "only RSA and ECDSA P-256/P-384/P-521 keys are supported".into(),
        )),
    }
}

fn pem_rfc7468_decode(pem: &[u8]) -> Result<Vec<u8>> {
    use der::Encode;
    let certs = x509_cert::Certificate::load_pem_chain(pem)
        .map_err(|e| LibError::Certificate(format!("certificate PEM: {e}")))?;
    let first = certs
        .into_iter()
        .next()
        .ok_or_else(|| LibError::Certificate("no certificate in PEM input".into()))?;
    first
        .to_der()
        .map_err(|e| LibError::Certificate(format!("certificate re-encode: {e}")))
}
