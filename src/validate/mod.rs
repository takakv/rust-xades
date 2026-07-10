mod dsig;
mod ltv;
mod xades;

pub(crate) use dsig::ALLOWED_DIGESTS;

use chrono::{DateTime, Utc};
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::error::{LibError, Result};
use crate::{ns, xml, DataObject};

/// XAdES baseline profile of a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// Signature only
    #[default]
    B,
    /// B with a signature timestamp
    T,
    /// T with validation data (certificate + OCSP response)
    LT,
    // TODO: implement necessary validation for LTA
    // /// LT with archive timestamps for long-term validity.
    // LTA,
}

/// Result of validating one signature.
#[derive(Debug, Default)]
pub struct SignatureValidation {
    /// `Id` attribute of the `ds:Signature` element.
    pub signature_id: Option<String>,
    pub profile: Profile,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    /// DER of the signer certificate from KeyInfo.
    pub signer_cert_der: Option<Vec<u8>>,
    /// Subject of the signer certificate.
    pub signer_subject: Option<String>,
    /// SigningTime as claimed in the signed properties.
    pub claimed_signing_time: Option<String>,
    /// Authenticated time of the signature timestamp (T/LT).
    pub timestamp_time: Option<DateTime<Utc>>,
    /// producedAt of the accepted OCSP proof (LT).
    pub ocsp_time: Option<DateTime<Utc>>,
}

impl SignatureValidation {
    /// A signature is valid when nothing produced an error.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Validation configuration.
pub struct ValidationOptions {
    /// Trusted CA certificates (DER).
    /// Signature, timestamp and OCSP certificates must chain to one of these.
    pub trusted_certs_der: Vec<Vec<u8>>,
    /// Time at which certificate validity is checked for B-level signatures.
    /// Defaults to now.
    pub validation_time: Option<DateTime<Utc>>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            trusted_certs_der: Vec::new(),
            validation_time: None,
        }
    }
}

impl ValidationOptions {
    /// Add trust anchors from PEM data (may contain several certificates).
    pub fn add_trusted_pem(&mut self, pem: &[u8]) -> Result<()> {
        use x509_cert::der::Encode;
        let certs = Certificate::load_pem_chain(pem)
            .map_err(|e| LibError::Certificate(format!("trusted PEM: {e}")))?;
        if certs.is_empty() {
            return Err(LibError::Certificate("no certificates in PEM input".into()));
        }
        for c in certs {
            self.trusted_certs_der.push(
                c.to_der()
                    .map_err(|e| LibError::Certificate(format!("trusted cert: {e}")))?,
            );
        }
        Ok(())
    }
}

/// Validate every `ds:Signature` in a signature document against the given data objects.
pub fn validate(
    signature_xml: &str,
    files: &[DataObject<'_>],
    options: &ValidationOptions,
) -> Result<Vec<SignatureValidation>> {
    let mut results = Vec::new();

    let mut trust = tsp_ltv::trust::TrustStore::new();
    for der in &options.trusted_certs_der {
        trust
            .add_der_certificate(der)
            .map_err(|e| LibError::Certificate(format!("trust anchor: {e}")))?;
    }

    let xmldoc = match bergshamra_xml::XmlDocument::parse(signature_xml.to_owned()) {
        Ok(d) => d,
        Err(e) => {
            return Ok(vec![invalid_document(format!(
                "signature document is not well-formed XML: {e}"
            ))]);
        }
    };
    let doc = match xmldoc.parse_doc() {
        Ok(d) => d,
        Err(e) => {
            return Ok(vec![invalid_document(format!("signature document: {e}"))]);
        }
    };

    // Reject duplicate Ids.
    let id_map = match xmldoc.build_id_map(&doc) {
        Ok(m) => m,
        Err(e) => {
            return Ok(vec![invalid_document(format!("ID attributes: {e}"))]);
        }
    };

    let sig_nodes = xml::descendants(&doc, doc.root(), ns::DSIG, "Signature");
    if sig_nodes.is_empty() {
        return Ok(vec![invalid_document(
            "document contains no ds:Signature".into(),
        )]);
    }
    for sig_node in sig_nodes {
        let mut sv = SignatureValidation {
            signature_id: xml::attr(&doc, sig_node, "Id").map(str::to_owned),
            ..Default::default()
        };

        let core = dsig::verify_core(&doc, &id_map, sig_node, files, &mut sv.errors);
        sv.signer_cert_der = core.cert_der.clone();

        let mut unsigned_node = None;
        if let (Some(sp_node), Some(cert_der)) = (core.sp_node, core.cert_der.as_deref()) {
            let xa = xades::check_signed_properties(
                &doc,
                sig_node,
                sp_node,
                cert_der,
                &mut sv.errors,
                &mut sv.warnings,
            );
            sv.profile = xa.profile;
            sv.claimed_signing_time = xa.claimed_signing_time;
            unsigned_node = xa.unsigned_node;
        } else if core.sp_node.is_none() {
            sv.errors
                .push("SignedProperties could not be resolved".into());
        }

        let leaf = match core.cert_der.as_deref().map(Certificate::from_der) {
            Some(Ok(cert)) => {
                sv.signer_subject = Some(cert.tbs_certificate.subject.to_string());
                Some(cert)
            }
            Some(Err(e)) => {
                sv.errors
                    .push(format!("signer certificate does not parse: {e}"));
                None
            }
            None => None,
        };

        if let Some(leaf) = leaf {
            let keyinfo_extras: Vec<Certificate> = core
                .extra_certs
                .iter()
                .filter_map(|der| match Certificate::from_der(der) {
                    Ok(cert) => Some(cert),
                    Err(_) => {
                        sv.warnings
                            .push("KeyInfo certificate does not parse".into());
                        None
                    }
                })
                .collect();
            let mut pool = keyinfo_extras.clone();

            if matches!(sv.profile, Profile::T | Profile::LT) {
                if let Some(unsigned) = unsigned_node {
                    let out = ltv::verify_unsigned(
                        &doc,
                        sig_node,
                        unsigned,
                        &leaf,
                        &keyinfo_extras,
                        &trust,
                        &mut sv.errors,
                        &mut sv.warnings,
                    );
                    sv.timestamp_time = out.timestamp_time;
                    sv.ocsp_time = out.ocsp_produced_at;
                    pool.extend(out.pool);
                }
                if sv.profile == Profile::T {
                    sv.warnings.push(
                        "T-level signature: no embedded revocation proof for the signer".into(),
                    );
                }
            }

            let at = sv
                .timestamp_time
                .or(options.validation_time)
                .unwrap_or_else(Utc::now);
            check_chain(&leaf, &pool, &trust, at, &mut sv.errors);
        }

        results.push(sv);
    }

    Ok(results)
}

fn invalid_document(error: String) -> SignatureValidation {
    SignatureValidation {
        errors: vec![error],
        ..Default::default()
    }
}

/// Chain the signer certificate to the configured trust anchors.
fn check_chain(
    leaf: &Certificate,
    pool: &[Certificate],
    trust: &tsp_ltv::trust::TrustStore,
    at: DateTime<Utc>,
    errors: &mut Vec<String>,
) {
    if trust.is_empty() {
        errors.push("no trust anchors configured".into());
        return;
    }
    let anchor_subjects: Vec<Vec<u8>> = trust
        .certificates()
        .filter_map(|c| {
            use x509_cert::der::Encode;
            c.tbs_certificate.subject.to_der().ok()
        })
        .collect();
    let chain = match tsp_ltv::trust::build_chain_from_pool(leaf, pool, &anchor_subjects, None) {
        Ok(chain) => chain,
        Err(e) => {
            errors.push(format!("cannot build certificate chain: {e}"));
            return;
        }
    };

    let time = to_der_time(at, errors);
    match trust.verify_chain_for_purpose(&chain, time, tsp_ltv::ltv::CertRole::EndEntity) {
        Ok(_anchor) => {}
        Err(e) => errors.push(format!("certificate chain validation failed: {e}")),
    }
}

fn to_der_time(at: DateTime<Utc>, errors: &mut Vec<String>) -> Option<x509_cert::der::DateTime> {
    match u64::try_from(at.timestamp()).ok().and_then(|secs| {
        x509_cert::der::DateTime::from_unix_duration(std::time::Duration::from_secs(secs)).ok()
    }) {
        Some(t) => Some(t),
        None => {
            errors.push(format!("validation time out of range: {at}"));
            None
        }
    }
}
