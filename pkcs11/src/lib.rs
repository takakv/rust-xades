#![cfg(not(target_arch = "wasm32"))]

use std::path::PathBuf;

use tokenkey::TokenkeyError;
use xades::LibError;
use zeroize::Zeroize;

fn scheme_for_certificate(cert_der: &[u8]) -> xades::Result<(tokenkey::SignScheme, &'static str)> {
    let algorithm =
        tokenkey::KeyAlgorithm::from_certificate_der(cert_der).map_err(certificate_err)?;
    match algorithm {
        tokenkey::KeyAlgorithm::Ec(tokenkey::EcCurve::P256) => Ok((
            tokenkey::SignScheme::Ecdsa(tokenkey::Hash::Sha256),
            xades::ns::ECDSA_SHA256,
        )),
        tokenkey::KeyAlgorithm::Ec(tokenkey::EcCurve::P384) => Ok((
            tokenkey::SignScheme::Ecdsa(tokenkey::Hash::Sha384),
            xades::ns::ECDSA_SHA384,
        )),
        tokenkey::KeyAlgorithm::Ec(tokenkey::EcCurve::P521) => Ok((
            tokenkey::SignScheme::Ecdsa(tokenkey::Hash::Sha512),
            xades::ns::ECDSA_SHA512,
        )),
    }
}

#[derive(Debug, Clone)]
pub enum SlotSelector {
    /// PKCS#11 slot id (`CK_SLOT_ID`).
    Id(u64),
    /// Token label (`CKA_LABEL`).
    TokenLabel(String),
}

pub struct Pkcs11Options {
    /// Path to the PKCS#11 module.
    pub module: PathBuf,
    /// Token selection.
    pub slot: Option<SlotSelector>,
    /// User PIN.
    pub pin: String,
    /// `CKA_LABEL` of the private key.
    pub key_label: String,
    /// `CKA_ID` to differentiate between objects sharing a label.
    pub key_id: Option<Vec<u8>>,
    /// DER certificate to use instead of reading it from the token.
    pub certificate_der: Option<Vec<u8>>,
}

impl Drop for Pkcs11Options {
    fn drop(&mut self) {
        self.pin.zeroize();
    }
}

/// A signer backed by a private key on a PKCS#11 token.
pub struct Pkcs11Signer {
    key: tokenkey::TokenKey,
    scheme: tokenkey::SignScheme,
    algorithm_uri: &'static str,
    cert_der: Vec<u8>,
}

impl Pkcs11Signer {
    pub fn open(opts: &Pkcs11Options) -> xades::Result<Self> {
        let slot = match &opts.slot {
            None => tokenkey::SlotSelect::SoleToken,
            Some(SlotSelector::Id(id)) => tokenkey::SlotSelect::Id(*id),
            Some(SlotSelector::TokenLabel(label)) => {
                tokenkey::SlotSelect::TokenLabel(label.clone())
            }
        };
        let key_select = match &opts.key_id {
            Some(id) => tokenkey::KeySelect::LabelAndId(opts.key_label.clone(), id.clone()),
            None => tokenkey::KeySelect::Label(opts.key_label.clone()),
        };
        let locator = tokenkey::KeyLocator {
            module: opts.module.clone(),
            slot,
            key: key_select,
        };

        let key = tokenkey::TokenKey::open(&locator, &opts.pin).map_err(setup_err)?;

        let cert_der = match &opts.certificate_der {
            Some(der) => der.clone(),
            None => key.certificate_der().map(<[u8]>::to_vec).ok_or_else(|| {
                no_certificate_err(&format!("key with label {:?}", opts.key_label))
            })?,
        };

        let (scheme, algorithm_uri) = scheme_for_certificate(&cert_der)?;

        Ok(Self {
            key,
            scheme,
            algorithm_uri,
            cert_der,
        })
    }

    /// Wrap an already opened key.
    pub fn from_token_key(
        key: tokenkey::TokenKey,
        certificate_der: Option<Vec<u8>>,
    ) -> xades::Result<Pkcs11Signer> {
        let cert_der = match certificate_der {
            Some(der) => der,
            None => key
                .certificate_der()
                .map(<[u8]>::to_vec)
                .ok_or_else(|| no_certificate_err("the given key"))?,
        };

        let (scheme, algorithm_uri) = scheme_for_certificate(&cert_der)?;

        Ok(Self {
            key,
            scheme,
            algorithm_uri,
            cert_der,
        })
    }
}

/// Error for a key without a certificate.
fn no_certificate_err(what: &str) -> LibError {
    LibError::Certificate(format!("no certificate available for {what}"))
}

/// Wrap a PKCS#11 setup failure.
fn setup_err(e: TokenkeyError) -> LibError {
    LibError::Crypto(format!("PKCS#11: {e}"))
}

/// Translate a `tokenkey` certificate-parsing failure.
fn certificate_err(e: TokenkeyError) -> LibError {
    match e {
        TokenkeyError::Certificate(msg) => LibError::Certificate(msg),
        TokenkeyError::Unsupported(msg) => LibError::Unsupported(msg),
        other => LibError::Certificate(other.to_string()),
    }
}

/// Wrap a PKCS#11 signing failure.
fn sign_err(e: TokenkeyError) -> LibError {
    LibError::Signing(format!("PKCS#11: {e}"))
}

impl xades::Signer for Pkcs11Signer {
    fn algorithm_uri(&self) -> &str {
        self.algorithm_uri
    }

    fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }

    fn sign(&self, data: &[u8]) -> xades::Result<Vec<u8>> {
        self.key.sign(self.scheme, data).map_err(sign_err)
    }
}
