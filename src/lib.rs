pub mod crypto;
pub mod error;
pub mod ns;
pub mod sig;
pub mod validate;

mod xml;

pub use crypto::{Signer, SoftwareSigner};
pub use error::{LibError, Result};
#[cfg(feature = "network")]
pub use sig::LtConfig;
pub use sig::{prepare_signature, sign, CreatedSignature, PreparedSignature, SigningOptions};
pub use validate::{validate, Profile, SignatureValidation, ValidationOptions};

/// A data object covered by a signature.
#[derive(Debug, Clone, Copy)]
pub struct DataObject<'a> {
    /// File name as stored in the container.
    pub name: &'a str,
    /// Media type, e.g. `application/pdf`.
    pub mime_type: &'a str,
    /// Raw content.
    pub content: &'a [u8],
}
