use tsp_ltv::ltv::{ocsp_check_revocation, OcspClient, ValidationStatus};
use tsp_ltv::tsp::TsaClient;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::error::{LibError, Result};
use crate::CreatedSignature;

#[derive(Debug, Clone)]
pub struct LtConfig {
    /// RFC 3161 timestamping service URL.
    pub tsa_url: String,
    /// DER certificates completing the signer's chain.
    ///
    /// If empty, the chain is discovered automatically via the `caIssuers` URL.
    pub issuer_certs_der: Vec<Vec<u8>>,
}

impl CreatedSignature {
    async fn request_signature_timestamp(&self, tsa_url: &str) -> Result<Vec<u8>> {
        let input = self.timestamp_input()?;
        let digest_alg = tsp_ltv::crypto::algorithm::DigestAlgorithm::Sha256;
        let hash = digest_alg.digest(&input);
        TsaClient::new(tsa_url)
            .digest_algorithm(digest_alg)
            .timestamp(&hash)
            .await
            .map_err(|e| LibError::Timestamp(format!("TSA {tsa_url}: {e}")))
    }

    pub fn extend_to_t(self, tsa_url: &str) -> Result<CreatedSignature> {
        let token = runtime()?.block_on(self.request_signature_timestamp(tsa_url))?;
        self.extend_to_t_with(token)
    }

    /// Extends the signature to LT level by adding a signature timestamp, the
    /// signer certificate's OCSP response, and the validation issuer certificates.
    pub fn extend_to_lt(self, config: &LtConfig) -> Result<CreatedSignature> {
        let leaf = Certificate::from_der(&self.draft.cert_der)
            .map_err(|e| LibError::Certificate(format!("signer certificate: {e}")))?;

        let runtime = runtime()?;

        let mut candidates = config.issuer_certs_der.clone();
        let issuer = match find_issuer(&leaf, &candidates) {
            Ok(issuer) => issuer,
            Err(_) => {
                let fetched = runtime.block_on(fetch_issuer_chain(&leaf))?;
                candidates = merge_candidates(candidates, fetched);
                find_issuer(&leaf, &candidates).map_err(|_| {
                    LibError::Certificate(format!(
                        "no issuer certificate provided for {} and caIssuers discovery found none",
                        leaf.tbs_certificate.issuer
                    ))
                })?
            }
        };

        // Timestamp must predate OCSP response.
        let token = runtime.block_on(self.request_signature_timestamp(&config.tsa_url))?;
        let ocsp_der = runtime.block_on(request_certificate_status(&leaf, &issuer))?;

        self.extend_to_lt_with(token, vec![ocsp_der], candidates)
    }
}

async fn fetch_issuer_chain(leaf: &Certificate) -> Result<Vec<Vec<u8>>> {
    let chain = tsp_ltv::ltv::ChainBuilder::new()
        .build_chain(leaf, &tsp_ltv::trust::TrustStore::new())
        .await
        .map_err(|e| LibError::Certificate(format!("AIA issuer fetch: {e}")))?;
    Ok(chain.into_iter().skip(1).collect()) // chain[0] is the leaf itself
}

fn merge_candidates(mut candidates: Vec<Vec<u8>>, fetched: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    for der in fetched {
        if !candidates.contains(&der) {
            candidates.push(der);
        }
    }
    candidates
}

fn find_issuer(leaf: &Certificate, candidates_der: &[Vec<u8>]) -> Result<Certificate> {
    for der in candidates_der {
        let cert = Certificate::from_der(der)
            .map_err(|e| LibError::Certificate(format!("issuer certificate: {e}")))?;
        if cert.tbs_certificate.subject == leaf.tbs_certificate.issuer {
            return Ok(cert);
        }
    }
    Err(LibError::Certificate(format!(
        "no issuer certificate provided for {}",
        leaf.tbs_certificate.issuer
    )))
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| LibError::Signing(format!("tokio runtime: {e}")))
}

async fn request_certificate_status(leaf: &Certificate, issuer: &Certificate) -> Result<Vec<u8>> {
    let (ocsp_der, nonce) = OcspClient::new()
        .fetch_ocsp_response_with_nonce(leaf, issuer)
        .await
        .map_err(|e| LibError::Ocsp(format!("OCSP fetch: {e}")))?;
    match ocsp_check_revocation(&ocsp_der, leaf, issuer, Some(&nonce), None) {
        Ok(ValidationStatus::Valid { .. }) => {}
        Ok(other) => {
            return Err(LibError::Ocsp(format!(
                "signer certificate revocation status is not good: {other:?}"
            )));
        }
        Err(e) => return Err(LibError::Ocsp(format!("OCSP response invalid: {e}"))),
    }
    Ok(ocsp_der)
}
