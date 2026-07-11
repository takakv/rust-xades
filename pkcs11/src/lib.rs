#![cfg(not(target_arch = "wasm32"))]

use std::path::PathBuf;

use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use kryptering::algorithm::{EcCurve, HashAlgorithm, SignatureAlgorithm};
use kryptering::pkcs11::{Pkcs11Provider, Pkcs11Session};
use kryptering::traits::Signer as _;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::Decode;
use zeroize::{Zeroize, Zeroizing};

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

pub(crate) fn algorithm_for_certificate(
    cert_der: &[u8],
) -> xades::Result<(SignatureAlgorithm, &'static str)> {
    let cert = x509_cert::Certificate::from_der(cert_der).map_err(|e| {
        xades::LibError::Certificate(format!("PKCS#11 signing certificate is not valid DER: {e}"))
    })?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let alg_oid = spki.algorithm.oid;

    if alg_oid == OID_EC_PUBLIC_KEY {
        let params = spki.algorithm.parameters.as_ref().ok_or_else(|| {
            xades::LibError::Unsupported("EC signing key has no named curve".into())
        })?;
        let curve: ObjectIdentifier = params.decode_as().map_err(|e| {
            xades::LibError::Certificate(format!("EC named curve is not an OID: {e}"))
        })?;
        if curve == OID_P384 {
            return Ok((
                SignatureAlgorithm::Ecdsa(EcCurve::P384, HashAlgorithm::Sha384),
                xades::ns::ECDSA_SHA384,
            ));
        }
        return Err(xades::LibError::Unsupported(format!(
            "unsupported EC curve {curve} for XAdES signing (P-384 only)"
        )));
    }

    Err(xades::LibError::Unsupported(format!(
        "unsupported signing key algorithm {alg_oid} (P-384 only)"
    )))
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

pub struct Pkcs11Signer {
    // Needed to keep the library loaded for the signer's lifetime.
    #[allow(dead_code)]
    provider: Pkcs11Provider,
    session: Pkcs11Session,
    key_handle: ObjectHandle,
    algorithm: SignatureAlgorithm,
    algorithm_uri: &'static str,
    cert_der: Vec<u8>,
    always_authenticate: bool,
    pin: Zeroizing<String>,
    delegate: Option<kryptering::pkcs11::Pkcs11Signer>,
}

impl Pkcs11Signer {
    pub fn open(opts: &Pkcs11Options) -> xades::Result<Self> {
        let provider = match &opts.slot {
            None => Pkcs11Provider::new(&opts.module),
            Some(SlotSelector::Id(id)) => Pkcs11Provider::new_with_slot_id(&opts.module, *id),
            Some(SlotSelector::TokenLabel(label)) => {
                Pkcs11Provider::new_with_token(&opts.module, label, None)
            }
        }
        .map_err(setup_err)?;

        let session = provider.open_session(&opts.pin).map_err(setup_err)?;

        let key_handle = match &opts.key_id {
            Some(id) => session.find_private_key_by_id(&opts.key_label, id),
            None => session.find_private_key(&opts.key_label),
        }
        .map_err(setup_err)?;

        let cert_der = match &opts.certificate_der {
            Some(der) => der.clone(),
            None => find_certificate_der(&session, &opts.key_label, opts.key_id.as_deref())?,
        };

        let (algorithm, algorithm_uri) = algorithm_for_certificate(&cert_der)?;

        let always_authenticate = read_always_authenticate(&session, key_handle)?;

        let delegate = if always_authenticate {
            None
        } else {
            Some(
                kryptering::pkcs11::Pkcs11Signer::new(&session, &opts.key_label, algorithm)
                    .map_err(setup_err)?,
            )
        };

        Ok(Self {
            provider,
            session,
            key_handle,
            algorithm,
            algorithm_uri,
            cert_der,
            always_authenticate,
            pin: Zeroizing::new(opts.pin.clone()),
            delegate,
        })
    }
}

/// Read the DER certificate object matching `label`.
fn find_certificate_der(
    session: &Pkcs11Session,
    label: &str,
    id: Option<&[u8]>,
) -> xades::Result<Vec<u8>> {
    let mut template = vec![
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    if let Some(id) = id {
        template.push(Attribute::Id(id.to_vec()));
    }

    let sess = session
        .session()
        .lock()
        .map_err(|e| setup_err(format!("session lock poisoned: {e}")))?;
    let mut objects = sess
        .find_objects(&template)
        .map_err(|e| setup_err(format!("C_FindObjects failed: {e}")))?;
    let handle = match objects.len() {
        0 => {
            return Err(setup_err(format!(
                "no certificate object found with label {label:?}{}",
                id.map(|_| " and matching CKA_ID").unwrap_or_default()
            )));
        }
        1 => objects.remove(0),
        n => {
            return Err(setup_err(format!(
                "ambiguous certificate lookup: {n} objects with label {label:?}"
            )));
        }
    };
    let attrs = sess
        .get_attributes(handle, &[AttributeType::Value])
        .map_err(|e| setup_err(format!("C_GetAttributeValue failed: {e}")))?;
    attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::Value(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| setup_err("certificate object has no CKA_VALUE"))
}

/// Read `CKA_ALWAYS_AUTHENTICATE` from the private key.
fn read_always_authenticate(session: &Pkcs11Session, key: ObjectHandle) -> xades::Result<bool> {
    let sess = session
        .session()
        .lock()
        .map_err(|e| setup_err(format!("session lock poisoned: {e}")))?;
    let attrs = sess
        .get_attributes(key, &[AttributeType::AlwaysAuthenticate])
        .map_err(|e| setup_err(format!("C_GetAttributeValue failed: {e}")))?;
    Ok(attrs
        .iter()
        .any(|a| matches!(a, Attribute::AlwaysAuthenticate(true))))
}

fn setup_err(msg: impl std::fmt::Display) -> xades::LibError {
    xades::LibError::Crypto(format!("PKCS#11: {msg}"))
}

impl xades::Signer for Pkcs11Signer {
    fn algorithm_uri(&self) -> &str {
        self.algorithm_uri
    }

    fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }

    fn sign(&self, data: &[u8]) -> xades::Result<Vec<u8>> {
        if self.always_authenticate {
            return self.sign_context_specific(data);
        }
        self.delegate
            .as_ref()
            .expect("delegate is present when the key does not need reauthentication")
            .sign(data)
            .map_err(|e| sign_err(format!("C_Sign failed: {e}")))
    }
}

impl Pkcs11Signer {
    /// Sign with a `CKA_ALWAYS_AUTHENTICATE` key.
    fn sign_context_specific(&self, data: &[u8]) -> xades::Result<Vec<u8>> {
        let (mechanism, input) = self.mechanism_and_input(data)?;

        let sess = self
            .session
            .session()
            .lock()
            .map_err(|e| sign_err(format!("session lock poisoned: {e}")))?;

        sess.sign_init(&mechanism, self.key_handle)
            .map_err(|e| sign_err(format!("C_SignInit failed: {e}")))?;

        match sess.login(
            UserType::ContextSpecific,
            Some(&AuthPin::new(self.pin.as_str().to_owned().into())),
        ) {
            Ok(()) => {}
            Err(cryptoki::error::Error::Pkcs11(
                cryptoki::error::RvError::UserAlreadyLoggedIn,
                _,
            )) => {}
            Err(e) => {
                return Err(sign_err(format!(
                    "CKA_ALWAYS_AUTHENTICATE requires PIN for each signature: {e}"
                )));
            }
        }

        // CKM_ECDSA is formally one-shot, but OpenSC accepts it by buffering.
        sess.sign_update(&input)
            .map_err(|e| sign_err(format!("C_SignUpdate failed: {e}")))?;
        sess.sign_final()
            .map_err(|e| sign_err(format!("C_SignFinal failed: {e}")))
    }

    fn mechanism_and_input(&self, data: &[u8]) -> xades::Result<(Mechanism<'static>, Vec<u8>)> {
        match self.algorithm {
            SignatureAlgorithm::Ecdsa(_, hash) => {
                Ok((Mechanism::Ecdsa, kryptering::digest::digest(hash, data)))
            }
            other => Err(xades::LibError::Unsupported(format!(
                "{other:?} is not supported for PKCS#11 XAdES signing"
            ))),
        }
    }
}

fn sign_err(msg: impl std::fmt::Display) -> xades::LibError {
    xades::LibError::Signing(format!("PKCS#11: {msg}"))
}
