use bergshamra_c14n::C14nMode;
use bergshamra_xml::{NodeSet, XmlDocument};
use chrono::{DateTime, SecondsFormat, Utc};

use super::template::{build_signature_xml, encode_reference_uri, Draft, FileRef};
use crate::crypto::{signature_digest_uri, Signer};
use crate::error::{LibError, Result};
use crate::ns;
use crate::DataObject;

/// Options for signature creation.
#[derive(Debug, Clone)]
pub struct SigningOptions {
    /// Defaults to `S0`.
    pub signature_id: Option<String>,
    /// Claimed signing time. Defaults to the current UTC time.
    pub signing_time: Option<DateTime<Utc>>,
    /// Digest method for all references and the certificate digest.
    pub digest_uri: String,
    /// SignedInfo canonicalization method.
    pub c14n_uri: String,
}

impl Default for SigningOptions {
    fn default() -> Self {
        Self {
            signature_id: None,
            signing_time: None,
            digest_uri: ns::SHA256.into(),
            c14n_uri: ns::C14N11.into(),
        }
    }
}

pub struct PreparedSignature {
    draft: Draft,
    /// Canonicalized SignedInfo.
    pub signed_info: Vec<u8>,
    /// Digest of `signed_info`.
    pub digest_to_sign: Vec<u8>,
}

impl PreparedSignature {
    pub fn finalize(mut self, signature: &[u8]) -> Result<CreatedSignature> {
        if signature.is_empty() {
            return Err(LibError::Signing("empty signature value".into()));
        }
        self.draft.signature_value = Some(signature.to_vec());
        let xml = build_signature_xml(&self.draft)?;
        Ok(CreatedSignature {
            draft: self.draft,
            xml,
        })
    }
}

/// B-level signature.
pub struct CreatedSignature {
    pub(crate) draft: Draft,
    pub(crate) xml: String,
}

impl CreatedSignature {
    pub fn xml(&self) -> &str {
        &self.xml
    }

    pub fn into_xml(self) -> String {
        self.xml
    }
}

/// Create a B-level signature.
pub fn sign(
    files: &[DataObject<'_>],
    signer: &dyn Signer,
    options: &SigningOptions,
) -> Result<CreatedSignature> {
    let prepared = prepare_signature(
        files,
        signer.certificate_der(),
        signer.algorithm_uri(),
        options,
    )?;
    let signature = signer.sign(&prepared.signed_info)?;
    prepared.finalize(&signature)
}

/// Compute all digests and the SignedInfo.
pub fn prepare_signature(
    files: &[DataObject<'_>],
    cert_der: &[u8],
    sig_method_uri: &str,
    options: &SigningOptions,
) -> Result<PreparedSignature> {
    if files.is_empty() {
        return Err(LibError::Input("nothing to sign: no data objects".into()));
    }
    if !crate::validate::ALLOWED_DIGESTS.contains(&options.digest_uri.as_str()) {
        return Err(LibError::Unsupported(format!(
            "digest_uri: unsupported digest method: {}",
            options.digest_uri
        )));
    }
    if C14nMode::from_uri(&options.c14n_uri).is_none() {
        return Err(LibError::Unsupported(format!(
            "c14n_uri: unsupported canonicalization method: {}",
            options.c14n_uri
        )));
    }
    let hash_uri = signature_digest_uri(sig_method_uri)?;

    let files = files
        .iter()
        .map(|f| {
            Ok(FileRef {
                uri: encode_reference_uri(f.name),
                mime_type: f.mime_type.to_owned(),
                digest: bergshamra_crypto::digest::digest(&options.digest_uri, f.content)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let signing_time = options
        .signing_time
        .unwrap_or_else(Utc::now)
        .to_rfc3339_opts(SecondsFormat::Secs, true);

    let mut draft = Draft {
        id: options.signature_id.clone().unwrap_or_else(|| "S0".into()),
        c14n_uri: options.c14n_uri.clone(),
        sig_method_uri: sig_method_uri.to_owned(),
        digest_uri: options.digest_uri.clone(),
        files,
        cert_der: cert_der.to_vec(),
        signing_time,
        signed_props_digest: None,
        signature_value: None,
        unsigned: None,
    };

    let xml = build_signature_xml(&draft)?;
    let sp_c14n = canonicalize_subtree(&xml, ns::XADES, "SignedProperties", C14nMode::Inclusive)?;
    draft.signed_props_digest = Some(bergshamra_crypto::digest::digest(
        &draft.digest_uri,
        &sp_c14n,
    )?);

    let xml = build_signature_xml(&draft)?;
    let mode = C14nMode::from_uri(&draft.c14n_uri)
        .ok_or_else(|| LibError::Unsupported(format!("canonicalization: {}", draft.c14n_uri)))?;
    let signed_info = canonicalize_subtree(&xml, ns::DSIG, "SignedInfo", mode)?;
    let digest_to_sign = bergshamra_crypto::digest::digest(hash_uri, &signed_info)?;

    Ok(PreparedSignature {
        draft,
        signed_info,
        digest_to_sign,
    })
}

pub(crate) fn canonicalize_subtree(
    xml: &str,
    ns_uri: &str,
    local: &str,
    mode: C14nMode,
) -> Result<Vec<u8>> {
    let doc = bergshamra_xml::uppsala::parse(xml).map_err(|e| LibError::Xml(e.to_string()))?;
    let node = XmlDocument::find_element(&doc, ns_uri, local)
        .ok_or_else(|| LibError::Xml(format!("missing element: {local}")))?;
    let node_set = NodeSet::tree_without_comments(node, &doc);
    let empty: &[&str] = &[];
    bergshamra_c14n::canonicalize_doc(&doc, mode, Some(&node_set), empty)
        .map_err(|e| LibError::Xml(e.to_string()))
}
