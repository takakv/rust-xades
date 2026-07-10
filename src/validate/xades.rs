use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bergshamra_xml::{Document, NodeId};

use crate::validate::dsig::ALLOWED_DIGESTS;
use crate::{ns, xml, Profile};

pub(crate) struct XadesOutcome {
    pub profile: Profile,
    pub claimed_signing_time: Option<String>,
    /// `xades:UnsignedSignatureProperties`, when present.
    pub unsigned_node: Option<NodeId>,
}

pub(crate) fn check_signed_properties(
    doc: &Document<'_>,
    sig_node: NodeId,
    sp_node: NodeId,
    cert_der: &[u8],
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> XadesOutcome {
    let mut outcome = XadesOutcome {
        profile: Profile::B,
        claimed_signing_time: None,
        unsigned_node: None,
    };

    let qp = xml::descendants(doc, sig_node, ns::XADES, "QualifyingProperties")
        .into_iter()
        .find(|&n| xml::is_within(doc, n, sp_node));
    match qp {
        Some(qp_node) => {
            let target = xml::attr(doc, qp_node, "Target").unwrap_or("");
            let sig_id = xml::attr(doc, sig_node, "Id").unwrap_or("");
            if target.strip_prefix('#') != Some(sig_id) {
                errors.push(format!(
                    "QualifyingProperties Target {target:?} does not match signature Id {sig_id:?}"
                ));
            }
            outcome.unsigned_node = xml::child(doc, qp_node, ns::XADES, "UnsignedProperties")
                .and_then(|n| xml::child(doc, n, ns::XADES, "UnsignedSignatureProperties"));
        }
        None => errors.push("SignedProperties is not inside QualifyingProperties".into()),
    }

    let Some(ssp) = xml::child(doc, sp_node, ns::XADES, "SignedSignatureProperties") else {
        errors.push("missing SignedSignatureProperties".into());
        return outcome;
    };

    // 5.2.1 - The SigningTime qualifying property
    match xml::child(doc, ssp, ns::XADES, "SigningTime") {
        Some(t) => {
            let value = xml::text(doc, t);
            if chrono::DateTime::parse_from_rfc3339(&value).is_err() {
                errors.push(format!("SigningTime is not a valid timestamp: {value}"));
            }
            outcome.claimed_signing_time = Some(value);
        }
        None => errors.push("missing SigningTime".into()),
    }

    // 5.2.2 - The SigningCertificateV2 qualifying property
    // Estonia still uses SigningCertificate instead of SigningCertificateV2 for some reason...
    let cert_elem = xml::child(doc, ssp, ns::XADES, "SigningCertificate");
    match cert_elem.and_then(|sc| xml::child(doc, sc, ns::XADES, "Cert")) {
        Some(cert_node) => {
            let digest_node = xml::child(doc, cert_node, ns::XADES, "CertDigest");
            // Under SigningCertificateV2 there should also be IssuerSerialV2,
            // but it's omitted here since EE is not using V2. Potential TODO.
            let method = digest_node
                .and_then(|d| xml::child(doc, d, ns::DSIG, "DigestMethod"))
                .and_then(|m| xml::attr(doc, m, "Algorithm"))
                .unwrap_or("");
            let value = digest_node
                .and_then(|d| xml::child(doc, d, ns::DSIG, "DigestValue"))
                .map(|v| xml::text(doc, v))
                .and_then(|t| B64.decode(t.replace(['\n', '\r', ' '], "")).ok());
            if !ALLOWED_DIGESTS.contains(&method) {
                errors.push(format!(
                    "SigningCertificate digest uses unsupported method: {method}"
                ));
            } else {
                match (value, bergshamra_crypto::digest::digest(method, cert_der)) {
                    (Some(expected), Ok(actual)) if expected == actual => {}
                    (Some(_), Ok(_)) => errors.push(
                        "SigningCertificate digest does not match the KeyInfo certificate".into(),
                    ),
                    _ => errors.push("SigningCertificate digest is missing or malformed".into()),
                }
            }
        }
        None => errors.push("missing SigningCertificate".into()),
    }

    if let Some(unsigned) = outcome.unsigned_node {
        let has_tst = xml::child(doc, unsigned, ns::XADES, "SignatureTimeStamp").is_some();
        let has_revocation = xml::child(doc, unsigned, ns::XADES, "RevocationValues").is_some();
        outcome.profile = match (has_tst, has_revocation) {
            (true, true) => Profile::LT,
            (true, false) => Profile::T,
            _ => Profile::B,
        };
    }

    check_data_object_formats(doc, sig_node, sp_node, warnings);

    outcome
}

fn check_data_object_formats(
    doc: &Document<'_>,
    sig_node: NodeId,
    sp_node: NodeId,
    warnings: &mut Vec<String>,
) {
    let Some(signed_info) = xml::child(doc, sig_node, ns::DSIG, "SignedInfo") else {
        return;
    };
    let references = xml::children(doc, signed_info, ns::DSIG, "Reference");
    let data_object_ids: Vec<&str> = references
        .iter()
        .filter(|&&r| xml::attr(doc, r, "Type") != Some(ns::TYPE_SIGNED_PROPERTIES))
        .filter_map(|&r| xml::attr(doc, r, "Id"))
        .collect();

    let formats: Vec<NodeId> = xml::child(doc, sp_node, ns::XADES, "SignedDataObjectProperties")
        .map(|sdop| xml::children(doc, sdop, ns::XADES, "DataObjectFormat"))
        .unwrap_or_default();
    let object_references: Vec<&str> = formats
        .iter()
        .filter_map(|&f| xml::attr(doc, f, "ObjectReference"))
        .collect();

    // Every data-object reference must have a format.
    for &reference in &references {
        if xml::attr(doc, reference, "Type") == Some(ns::TYPE_SIGNED_PROPERTIES) {
            continue;
        }
        let ref_id = xml::attr(doc, reference, "Id").unwrap_or("");
        let expected = format!("#{ref_id}");
        if !object_references.contains(&expected.as_str()) {
            let uri = xml::attr(doc, reference, "URI").unwrap_or("");
            warnings.push(format!(
                "'{uri:?}' not referenced in SignedDataObjectProperties",
            ));
        }
    }

    // Every format must resolve to a reference and have a mimetype.
    for &format in &formats {
        let object_ref = xml::attr(doc, format, "ObjectReference").unwrap_or("");
        let resolves = object_ref
            .strip_prefix('#')
            .is_some_and(|id| data_object_ids.contains(&id));
        if !resolves {
            warnings.push(format!("Unknown ds:Reference '{object_ref:?}'"));
        }
        if xml::child(doc, format, ns::XADES, "MimeType").is_none() {
            warnings.push(format!("No MimeType specified for '{object_ref:?}'"));
        }
    }
}
