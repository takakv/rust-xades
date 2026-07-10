mod software;

pub use software::SoftwareSigner;

use crate::error::{LibError, Result};
use crate::ns;

pub trait Signer {
    fn algorithm_uri(&self) -> &str;

    fn certificate_der(&self) -> &[u8];

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub(crate) fn signature_digest_uri(sig_uri: &str) -> Result<&'static str> {
    match sig_uri {
        ns::RSA_SHA256 | ns::ECDSA_SHA256 => Ok(ns::SHA256),
        ns::RSA_SHA384 | ns::ECDSA_SHA384 => Ok(ns::SHA384),
        ns::RSA_SHA512 | ns::ECDSA_SHA512 => Ok(ns::SHA512),
        other => Err(LibError::Unsupported(format!(
            "method not supported: {other}"
        ))),
    }
}
