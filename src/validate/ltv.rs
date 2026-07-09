use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bergshamra_c14n::C14nMode;
use bergshamra_xml::{Document, NodeId};
use chrono::{DateTime, Utc};
use tsp_ltv::trust::TrustStore;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::validate::dsig::c14n_node;
use crate::{ns, xml};

pub(crate) struct LtvOutcome {
    pub timestamp_time: Option<DateTime<Utc>>,
    pub pool: Vec<Certificate>,
}

fn decode_b64_element(doc: &Document<'_>, node: NodeId) -> Option<Vec<u8>> {
    B64.decode(xml::text(doc, node).replace(['\n', '\r', ' ', '\t'], ""))
        .ok()
}

pub(crate) fn verify_unsigned(
    doc: &Document<'_>,
    sig_node: NodeId,
    unsigned_node: NodeId,
    trust: &TrustStore,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> LtvOutcome {
    let mut outcome = LtvOutcome {
        timestamp_time: None,
        pool: Vec::new(),
    };

    // 5.3 - The SignatureTimeStamp qualifying property
    match xml::children(doc, unsigned_node, ns::XADES, "SignatureTimeStamp").as_slice() {
        [] => errors.push("missing SignatureTimeStamp".into()),
        [tst_node, rest @ ..] => {
            if !rest.is_empty() {
                warnings.push("multiple SignatureTimeStamps; verifying the first".into());
            }
            verify_signature_timestamp(doc, sig_node, *tst_node, trust, &outcome.pool.clone())
                .map_or_else(|e| errors.push(e), |t| outcome.timestamp_time = Some(t));
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
