use thiserror::Error;

#[derive(Error, Debug)]
pub enum LibError {
    /// Invalid input.
    #[error("input: {0}")]
    Input(String),

    /// XML is not well-formed or lacks a required element/attribute.
    #[error("xml: {0}")]
    Xml(String),

    /// A certificate could not be parsed.
    #[error("certificate: {0}")]
    Certificate(String),

    /// Cryptographic operation failed.
    #[error("crypto: {0}")]
    Crypto(String),

    /// Signature creation failed.
    #[error("signing: {0}")]
    Signing(String),

    /// Algorithm or feature not supported by the crate.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl From<bergshamra_core::Error> for LibError {
    fn from(e: bergshamra_core::Error) -> Self {
        LibError::Crypto(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, LibError>;
