use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bergshamra_c14n::C14nMode;
use bergshamra_xml::{Document, NodeId, NodeSet};
use percent_encoding::percent_decode_str;

use crate::{ns, xml, DataObject};

pub(crate) const ALLOWED_DIGESTS: &[&str] = &[ns::SHA256, ns::SHA384, ns::SHA512];

pub(crate) const ALLOWED_SIGNATURES: &[&str] = &[
    ns::RSA_SHA256,
    ns::RSA_SHA384,
    ns::RSA_SHA512,
    ns::ECDSA_SHA256,
    ns::ECDSA_SHA384,
    ns::ECDSA_SHA512,
];

pub(crate) struct CoreOutcome {
    /// Signer certificate (first in KeyInfo).
    pub cert_der: Option<Vec<u8>>,
    /// Certificate chain (additional certs in KeyInfo).
    pub extra_certs: Vec<Vec<u8>>,
    /// The resolved `xades:SignedProperties` element.
    pub sp_node: Option<NodeId>,
}

/// Canonicalize the subtree rooted at `node`.
pub(crate) fn c14n_node(doc: &Document<'_>, node: NodeId, mode: C14nMode) -> Option<Vec<u8>> {
    let set = NodeSet::tree_without_comments(node, doc);
    let empty: &[&str] = &[];
    bergshamra_c14n::canonicalize_doc(doc, mode, Some(&set), empty).ok()
}

pub(crate) fn verify_core(
    doc: &Document<'_>,
    id_map: &HashMap<String, NodeId>,
    sig_node: NodeId,
    data_files: &[DataObject<'_>],
    errors: &mut Vec<String>,
) -> CoreOutcome {
    let mut outcome = CoreOutcome {
        cert_der: None,
        extra_certs: Vec::new(),
        sp_node: None,
    };

    // KeyInfo certificates.
    if let Some(key_info) = xml::child(doc, sig_node, ns::DSIG, "KeyInfo") {
        for cert_node in xml::descendants(doc, key_info, ns::DSIG, "X509Certificate") {
            match B64.decode(xml::text(doc, cert_node).replace(['\n', '\r', ' '], "")) {
                Ok(der) if outcome.cert_der.is_none() => outcome.cert_der = Some(der),
                Ok(der) => outcome.extra_certs.push(der),
                Err(e) => errors.push(format!("KeyInfo certificate is not valid base64: {e}")),
            }
        }
    }
    if outcome.cert_der.is_none() {
        errors.push("KeyInfo contains no X509Certificate".into());
    }

    let Some(signed_info) = xml::child(doc, sig_node, ns::DSIG, "SignedInfo") else {
        errors.push("missing SignedInfo".into());
        return outcome;
    };

    // Canonicalization and signature methods.
    let c14n_uri = xml::child(doc, signed_info, ns::DSIG, "CanonicalizationMethod")
        .and_then(|n| xml::attr(doc, n, "Algorithm"))
        .unwrap_or("");
    let Some(c14n_mode) = C14nMode::from_uri(c14n_uri) else {
        errors.push(format!("unsupported canonicalization method: {c14n_uri}"));
        return outcome;
    };
    let sig_method = xml::child(doc, signed_info, ns::DSIG, "SignatureMethod")
        .and_then(|n| xml::attr(doc, n, "Algorithm"))
        .unwrap_or("")
        .to_owned();
    if !ALLOWED_SIGNATURES.contains(&sig_method.as_str()) {
        errors.push(format!("unsupported signature method: {sig_method}"));
        return outcome;
    }

    // References.
    let references = xml::children(doc, signed_info, ns::DSIG, "Reference");
    if references.is_empty() {
        errors.push("SignedInfo has no references".into());
    }
    let mut covered_files: Vec<&str> = Vec::new();
    let mut sp_reference_count = 0usize;

    for reference in references {
        let uri = xml::attr(doc, reference, "URI").unwrap_or("").to_owned();
        let ref_type = xml::attr(doc, reference, "Type").unwrap_or("");

        let digest_uri = xml::child(doc, reference, ns::DSIG, "DigestMethod")
            .and_then(|n| xml::attr(doc, n, "Algorithm"))
            .unwrap_or("")
            .to_owned();
        if !ALLOWED_DIGESTS.contains(&digest_uri.as_str()) {
            errors.push(format!(
                "reference {uri}: unsupported digest method: {digest_uri}"
            ));
            continue;
        }
        let Some(expected) = xml::child(doc, reference, ns::DSIG, "DigestValue")
            .map(|n| xml::text(doc, n))
            .and_then(|t| B64.decode(t.replace(['\n', '\r', ' '], "")).ok())
        else {
            errors.push(format!("reference {uri}: missing or malformed DigestValue"));
            continue;
        };

        let transforms: Vec<String> = xml::child(doc, reference, ns::DSIG, "Transforms")
            .map(|t| {
                xml::children(doc, t, ns::DSIG, "Transform")
                    .into_iter()
                    .map(|n| xml::attr(doc, n, "Algorithm").unwrap_or("").to_owned())
                    .collect()
            })
            .unwrap_or_default();

        if let Some(fragment) = uri.strip_prefix('#') {
            if ref_type != ns::TYPE_SIGNED_PROPERTIES {
                errors.push(format!(
                    "same-document reference {uri} is not a SignedProperties reference"
                ));
                continue;
            }
            sp_reference_count += 1;
            let Some(&target) = id_map.get(fragment) else {
                errors.push(format!("reference {uri}: no element with that Id"));
                continue;
            };
            if !xml::is_element(doc, target, ns::XADES, "SignedProperties") {
                errors.push(format!("reference {uri} does not target SignedProperties"));
                continue;
            }
            if !xml::is_within(doc, sig_node, target) {
                errors.push(format!(
                    "reference {uri} targets SignedProperties outside this signature"
                ));
                continue;
            }

            let mode = match transforms.as_slice() {
                [] => C14nMode::Inclusive,
                [one] => match C14nMode::from_uri(one) {
                    Some(m) => m,
                    None => {
                        errors.push(format!("reference {uri}: unsupported transform: {one}"));
                        continue;
                    }
                },
                more => {
                    errors.push(format!(
                        "reference {uri}: unexpected transform chain of length {}",
                        more.len()
                    ));
                    continue;
                }
            };
            let Some(c14n) = c14n_node(doc, target, mode) else {
                errors.push(format!("reference {uri}: canonicalization failed"));
                continue;
            };
            match bergshamra_crypto::digest::digest(&digest_uri, &c14n) {
                Ok(actual) if actual == expected => outcome.sp_node = Some(target),
                Ok(_) => errors.push("SignedProperties digest mismatch".into()),
                Err(e) => errors.push(format!("reference {uri}: digest failed: {e}")),
            }
        } else {
            if !transforms.is_empty() {
                errors.push(format!(
                    "data file reference {uri} must not have transforms"
                ));
                continue;
            }

            let name = match percent_decode_str(&uri).decode_utf8() {
                Ok(n) => n.into_owned(),
                Err(_) => {
                    errors.push(format!("reference URI is not valid UTF-8: {uri}"));
                    continue;
                }
            };

            let Some(file) = data_files.iter().find(|f| f.name == name) else {
                errors.push(format!("signed file is missing from container: {name}"));
                continue;
            };

            match bergshamra_crypto::digest::digest(&digest_uri, file.content) {
                Ok(actual) if actual == expected => {
                    covered_files.push(file.name);
                }
                Ok(_) => errors.push(format!("digest mismatch for data file: {name}")),
                Err(e) => errors.push(format!("reference {uri}: digest failed: {e}")),
            }
        }
    }

    if sp_reference_count != 1 {
        errors.push(format!(
            "expected exactly one SignedProperties reference, found {sp_reference_count}"
        ));
    }
    for file in data_files {
        if !covered_files.contains(&file.name) {
            errors.push(format!(
                "data file is not covered by the signature: {}",
                file.name
            ));
        }
    }

    // Signature value over canonical SignedInfo.
    let Some(sig_value) = xml::child(doc, sig_node, ns::DSIG, "SignatureValue")
        .map(|n| xml::text(doc, n))
        .and_then(|t| B64.decode(t.replace(['\n', '\r', ' '], "")).ok())
        .filter(|v| !v.is_empty())
    else {
        errors.push("missing or malformed SignatureValue".into());
        return outcome;
    };
    let Some(signed_info_c14n) = c14n_node(doc, signed_info, c14n_mode) else {
        errors.push("SignedInfo canonicalization failed".into());
        return outcome;
    };

    let Some(cert_der) = outcome.cert_der.as_deref() else {
        return outcome;
    };
    let verify_key = bergshamra_keys::loader::load_x509_cert_der(cert_der)
        .ok()
        .and_then(|k| k.to_signing_key());
    let Some(verify_key) = verify_key else {
        errors.push("cannot extract a supported public key from the signer certificate".into());
        return outcome;
    };
    match bergshamra_crypto::sign::from_uri(&sig_method) {
        Ok(alg) => match alg.verify(&verify_key, &signed_info_c14n, &sig_value) {
            Ok(true) => {}
            Ok(false) => errors.push("signature value does not verify".into()),
            Err(e) => errors.push(format!("signature verification failed: {e}")),
        },
        Err(e) => errors.push(format!("signature method: {e}")),
    }

    outcome
}
