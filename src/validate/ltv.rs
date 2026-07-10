use bergshamra_c14n::C14nMode;
use bergshamra_xml::{Document, NodeId};
use chrono::{DateTime, Utc};
use tsp_ltv::ltv::ocsp::check_revocation;
use tsp_ltv::ltv::{parse_ocsp_response, ValidationStatus};
use tsp_ltv::trust::TrustStore;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::validate::dsig::c14n_node;
use crate::{ns, xml};

pub(crate) struct LtvOutcome {
    pub timestamp_time: Option<DateTime<Utc>>,
    pub ocsp_produced_at: Option<DateTime<Utc>>,
    pub pool: Vec<Certificate>,
}

fn decode_b64_element(doc: &Document<'_>, node: NodeId) -> Option<Vec<u8>> {
    xml::decode_b64(&xml::text(doc, node))
}

pub(crate) fn verify_unsigned(
    doc: &Document<'_>,
    sig_node: NodeId,
    unsigned_node: NodeId,
    leaf: &Certificate,
    keyinfo_extras: &[Certificate],
    trust: &TrustStore,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> LtvOutcome {
    let mut outcome = LtvOutcome {
        timestamp_time: None,
        ocsp_produced_at: None,
        pool: Vec::new(),
    };

    // 5.4.2 - The CertificateValues qualifying property
    for node in xml::descendants(doc, unsigned_node, ns::XADES, "EncapsulatedX509Certificate") {
        match decode_b64_element(doc, node).and_then(|der| Certificate::from_der(&der).ok()) {
            Some(cert) => outcome.pool.push(cert),
            None => errors.push("unparseable encapsulated certificate".into()),
        }
    }

    // 5.3 - The SignatureTimeStamp qualifying property
    let tst_nodes = xml::children(doc, unsigned_node, ns::XADES, "SignatureTimeStamp");
    if tst_nodes.is_empty() {
        errors.push("missing SignatureTimeStamp".into());
    } else {
        let mut earliest: Option<DateTime<Utc>> = None;
        let mut failures: Vec<(usize, String)> = Vec::new();
        for (i, &tst_node) in tst_nodes.iter().enumerate() {
            match verify_signature_timestamp(doc, sig_node, tst_node, trust, &outcome.pool) {
                Ok(t) => earliest = Some(earliest.map_or(t, |e| e.min(t))),
                Err(e) => failures.push((i + 1, e)),
            }
        }
        if let Some(t) = earliest {
            outcome.timestamp_time = Some(t);
            for (n, e) in &failures {
                warnings.push(format!("SignatureTimeStamp {n} did not verify: {e}"));
            }
        } else {
            let summary = failures
                .iter()
                .map(|(n, e)| format!("#{n}: {e}"))
                .collect::<Vec<_>>()
                .join("; ");
            errors.push(format!("no SignatureTimeStamp verified ({summary})"));
        }
    }

    let at = outcome.timestamp_time;
    let ocsp_nodes = xml::descendants(doc, unsigned_node, ns::XADES, "EncapsulatedOCSPValue");
    if ocsp_nodes.is_empty() {
        if let Some(revocation_values) =
            xml::child(doc, unsigned_node, ns::XADES, "RevocationValues")
        {
            if xml::child(doc, revocation_values, ns::XADES, "CRLValues").is_some() {
                errors.push("CRLs not supported".into());
            } else {
                errors.push("missing OCSP response".into());
            }
        }
        return outcome;
    }

    let issuer = outcome
        .pool
        .iter()
        .chain(keyinfo_extras.iter())
        .find(|c| c.tbs_certificate.subject == leaf.tbs_certificate.issuer)
        .cloned();
    let Some(issuer) = issuer else {
        errors.push("cannot verify OCSP: issuer certificate is missing".into());
        return outcome;
    };

    if ocsp_nodes.len() > 1 {
        errors.push("multiple OCSP responses not supported".to_string());
    }
    if ocsp_nodes.len() == 1 {
        let Some(der) = decode_b64_element(doc, ocsp_nodes[0]) else {
            errors.push("EncapsulatedOCSPValue is not valid base64".into());
            return outcome;
        };
        match check_revocation(&der, leaf, &issuer, None, at) {
            Ok(ValidationStatus::Valid { .. }) => {
                if let Ok(parsed) = parse_ocsp_response(&der) {
                    outcome.ocsp_produced_at = Some(parsed.produced_at);
                    for cert_der in &parsed.embedded_certs_der {
                        if let Ok(c) = Certificate::from_der(cert_der) {
                            outcome.pool.push(c);
                        }
                    }
                }
            }
            Ok(other) => errors.push(format!("revocation status: {other:?}")),
            Err(e) => errors.push(format!("OCSP response: {e}")),
        }
    }

    if let (Some(ts), Some(ocsp)) = (outcome.timestamp_time, outcome.ocsp_produced_at) {
        if ocsp < ts {
            errors.push(format!(
                "OCSP proof ({ocsp}) predates the signature timestamp ({ts})"
            ));
        }
    }

    outcome
}

fn verify_signature_timestamp(
    doc: &Document<'_>,
    sig_node: NodeId,
    tst_node: NodeId,
    trust: &TrustStore,
    extra_certs: &[Certificate],
) -> Result<DateTime<Utc>, String> {
    let token = xml::child(doc, tst_node, ns::XADES, "EncapsulatedTimeStamp")
        .and_then(|n| decode_b64_element(doc, n))
        .ok_or("SignatureTimeStamp has no usable EncapsulatedTimeStamp")?;

    let mode = match xml::child(doc, tst_node, ns::DSIG, "CanonicalizationMethod")
        .and_then(|n| xml::attr(doc, n, "Algorithm"))
    {
        Some(uri) => {
            C14nMode::from_uri(uri).ok_or_else(|| format!("timestamp canonicalization: {uri}"))?
        }
        None => C14nMode::Inclusive,
    };
    let sig_value = xml::child(doc, sig_node, ns::DSIG, "SignatureValue")
        .ok_or("signature has no SignatureValue")?;
    let input = c14n_node(doc, sig_value, mode).ok_or("SignatureValue canonicalization failed")?;

    let claimed = tsp_ltv::tsp::extract_tst_info(&token)
        .map_err(|e| format!("timestamp token does not parse: {e}"))?;
    let expected_hash = claimed.hash_algorithm.digest(&input);
    let info = tsp_ltv::tsp::verify_timestamp_token(
        &token,
        &expected_hash,
        claimed.hash_algorithm,
        None,
        Some(trust),
        None,
        extra_certs,
    )
    .map_err(|e| format!("signature timestamp invalid: {e}"))?;

    gen_time_utc(&info.gen_time_der).ok_or_else(|| "timestamp genTime does not parse".into())
}

fn gen_time_utc(gen_time_contents: &[u8]) -> Option<DateTime<Utc>> {
    if gen_time_contents.len() > 127 {
        return None;
    }
    let mut tlv = Vec::with_capacity(gen_time_contents.len() + 2);
    tlv.push(0x18);
    tlv.push(gen_time_contents.len() as u8);
    tlv.extend_from_slice(gen_time_contents);
    let t = x509_cert::der::asn1::GeneralizedTime::from_der(&tlv).ok()?;
    DateTime::from_timestamp(
        i64::try_from(t.to_unix_duration().as_secs()).ok()?,
        t.to_unix_duration().subsec_nanos(),
    )
}
