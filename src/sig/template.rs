use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bergshamra_xml::writer::XmlWriter;
use der::{Decode, Encode, Sequence};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::serial_number::SerialNumber;
use x509_cert::Certificate;

use crate::error::{LibError, Result};
use crate::ns;

/// Data needed to build a signature XML.
pub(crate) struct Draft {
    pub id: String,
    /// SignedInfo canonicalization method.
    pub c14n_uri: String,
    pub sig_method_uri: String,
    /// Digest method for references and the certificate digest.
    pub digest_uri: String,
    pub files: Vec<FileRef>,
    pub cert_der: Vec<u8>,
    /// `YYYY-MM-DDThh:mm:ssZ`.
    pub signing_time: String,
    /// Digest over the canonicalized SignedProperties.
    pub signed_props_digest: Option<Vec<u8>>,
    /// Raw signature bytes.
    pub signature_value: Option<Vec<u8>>,
    /// T/LT-level unsigned properties..
    pub unsigned: Option<UnsignedData>,
}

/// Values embedded as `xades:UnsignedSignatureProperties`.
pub(crate) struct UnsignedData {
    pub timestamp_der: Vec<u8>,
    pub timestamp_c14n_uri: String,
    pub cert_values: Vec<Vec<u8>>,
    pub ocsp_values: Vec<Vec<u8>>,
}

/// Signed data file.
pub(crate) struct FileRef {
    pub uri: String,
    pub mime_type: String,
    pub digest: Vec<u8>,
}

impl Draft {
    pub fn signed_properties_id(&self) -> String {
        format!("{}-SignedProperties", self.id)
    }

    fn reference_id(&self, index: usize) -> String {
        format!("{}-RefId{index}", self.id)
    }
}

pub(crate) fn encode_reference_uri(name: &str) -> String {
    const SET: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~')
        .remove(b'/');
    utf8_percent_encode(name, SET).to_string()
}

#[derive(Sequence)]
struct IssuerSerial {
    issuer: GeneralNames,
    serial_number: SerialNumber,
}

fn issuer_serial_v2(cert_der: &[u8]) -> Result<Vec<u8>> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| LibError::Certificate(format!("signing certificate: {e}")))?;
    let issuer_serial = IssuerSerial {
        issuer: vec![GeneralName::DirectoryName(cert.tbs_certificate.issuer)],
        serial_number: cert.tbs_certificate.serial_number,
    };
    issuer_serial
        .to_der()
        .map_err(|e| LibError::Certificate(format!("IssuerSerial encoding: {e}")))
}

/// Serialize the signature document described by `draft`.
pub(crate) fn build_signature_xml(draft: &Draft) -> Result<String> {
    let cert_digest = bergshamra_crypto::digest::digest(&draft.digest_uri, &draft.cert_der)?;
    let issuer_serial = issuer_serial_v2(&draft.cert_der)?;

    let mut w = XmlWriter::new();
    let e = |err: bergshamra_core::Error| LibError::Xml(err.to_string());

    w.write_declaration().map_err(e)?;
    w.start_element(
        "asic:XAdESSignatures",
        &[
            ("xmlns:asic", ns::ASIC),
            ("xmlns:ds", ns::DSIG),
            ("xmlns:xades", ns::XADES),
        ],
    )
    .map_err(e)?;
    w.start_element("ds:Signature", &[("Id", &draft.id)])
        .map_err(e)?;

    // SignedInfo
    w.start_element("ds:SignedInfo", &[]).map_err(e)?;
    w.empty_element(
        "ds:CanonicalizationMethod",
        &[("Algorithm", &draft.c14n_uri)],
    )
    .map_err(e)?;
    w.empty_element(
        "ds:SignatureMethod",
        &[("Algorithm", &draft.sig_method_uri)],
    )
    .map_err(e)?;
    for (i, file) in draft.files.iter().enumerate() {
        w.start_element(
            "ds:Reference",
            &[("Id", draft.reference_id(i).as_str()), ("URI", &file.uri)],
        )
        .map_err(e)?;
        w.empty_element("ds:DigestMethod", &[("Algorithm", &draft.digest_uri)])
            .map_err(e)?;
        write_text_element(&mut w, "ds:DigestValue", &B64.encode(&file.digest))?;
        w.end_element("ds:Reference").map_err(e)?;
    }
    let sp_id = draft.signed_properties_id();
    w.start_element(
        "ds:Reference",
        &[
            ("Type", ns::TYPE_SIGNED_PROPERTIES),
            ("URI", &format!("#{sp_id}")),
        ],
    )
    .map_err(e)?;
    w.empty_element("ds:DigestMethod", &[("Algorithm", &draft.digest_uri)])
        .map_err(e)?;
    write_opt_b64_element(
        &mut w,
        "ds:DigestValue",
        draft.signed_props_digest.as_deref(),
    )?;
    w.end_element("ds:Reference").map_err(e)?;
    w.end_element("ds:SignedInfo").map_err(e)?;

    // SignatureValue
    w.start_element("ds:SignatureValue", &[("Id", &format!("{}-SIG", draft.id))])
        .map_err(e)?;
    if let Some(sig) = &draft.signature_value {
        w.write_text(&B64.encode(sig)).map_err(e)?;
    }
    w.end_element("ds:SignatureValue").map_err(e)?;

    // KeyInfo
    w.start_element("ds:KeyInfo", &[]).map_err(e)?;
    w.start_element("ds:X509Data", &[]).map_err(e)?;
    write_text_element(&mut w, "ds:X509Certificate", &B64.encode(&draft.cert_der))?;
    w.end_element("ds:X509Data").map_err(e)?;
    w.end_element("ds:KeyInfo").map_err(e)?;

    // SignedProperties
    w.start_element("ds:Object", &[]).map_err(e)?;
    w.start_element(
        "xades:QualifyingProperties",
        &[("Target", &format!("#{}", draft.id))],
    )
    .map_err(e)?;
    w.start_element("xades:SignedProperties", &[("Id", sp_id.as_str())])
        .map_err(e)?;

    w.start_element("xades:SignedSignatureProperties", &[])
        .map_err(e)?;
    write_text_element(&mut w, "xades:SigningTime", &draft.signing_time)?;
    w.start_element("xades:SigningCertificateV2", &[])
        .map_err(e)?;
    w.start_element("xades:Cert", &[]).map_err(e)?;
    w.start_element("xades:CertDigest", &[]).map_err(e)?;
    w.empty_element("ds:DigestMethod", &[("Algorithm", &draft.digest_uri)])
        .map_err(e)?;
    write_text_element(&mut w, "ds:DigestValue", &B64.encode(&cert_digest))?;
    w.end_element("xades:CertDigest").map_err(e)?;
    write_text_element(&mut w, "xades:IssuerSerialV2", &B64.encode(&issuer_serial))?;
    w.end_element("xades:Cert").map_err(e)?;
    w.end_element("xades:SigningCertificateV2").map_err(e)?;
    w.end_element("xades:SignedSignatureProperties")
        .map_err(e)?;

    w.start_element("xades:SignedDataObjectProperties", &[])
        .map_err(e)?;
    for (i, file) in draft.files.iter().enumerate() {
        w.start_element(
            "xades:DataObjectFormat",
            &[("ObjectReference", &format!("#{}", draft.reference_id(i)))],
        )
        .map_err(e)?;
        write_text_element(&mut w, "xades:MimeType", &file.mime_type)?;
        w.end_element("xades:DataObjectFormat").map_err(e)?;
    }
    w.end_element("xades:SignedDataObjectProperties")
        .map_err(e)?;

    w.end_element("xades:SignedProperties").map_err(e)?;

    if let Some(unsigned) = &draft.unsigned {
        w.start_element("xades:UnsignedProperties", &[])
            .map_err(e)?;
        w.start_element("xades:UnsignedSignatureProperties", &[])
            .map_err(e)?;

        w.start_element(
            "xades:SignatureTimeStamp",
            &[("Id", &format!("{}-TS", draft.id))],
        )
        .map_err(e)?;
        w.empty_element(
            "ds:CanonicalizationMethod",
            &[("Algorithm", &unsigned.timestamp_c14n_uri)],
        )
        .map_err(e)?;
        write_text_element(
            &mut w,
            "xades:EncapsulatedTimeStamp",
            &B64.encode(&unsigned.timestamp_der),
        )?;
        w.end_element("xades:SignatureTimeStamp").map_err(e)?;

        if !unsigned.cert_values.is_empty() {
            w.start_element("xades:CertificateValues", &[]).map_err(e)?;
            for cert in &unsigned.cert_values {
                write_text_element(
                    &mut w,
                    "xades:EncapsulatedX509Certificate",
                    &B64.encode(cert),
                )?;
            }
            w.end_element("xades:CertificateValues").map_err(e)?;
        }

        if !unsigned.ocsp_values.is_empty() {
            w.start_element("xades:RevocationValues", &[]).map_err(e)?;
            w.start_element("xades:OCSPValues", &[]).map_err(e)?;
            for ocsp in &unsigned.ocsp_values {
                write_text_element(&mut w, "xades:EncapsulatedOCSPValue", &B64.encode(ocsp))?;
            }
            w.end_element("xades:OCSPValues").map_err(e)?;
            w.end_element("xades:RevocationValues").map_err(e)?;
        }

        w.end_element("xades:UnsignedSignatureProperties")
            .map_err(e)?;
        w.end_element("xades:UnsignedProperties").map_err(e)?;
    }

    w.end_element("xades:QualifyingProperties").map_err(e)?;
    w.end_element("ds:Object").map_err(e)?;
    w.end_element("ds:Signature").map_err(e)?;
    w.end_element("asic:XAdESSignatures").map_err(e)?;

    w.into_string().map_err(e)
}

fn write_text_element(w: &mut XmlWriter, tag: &str, text: &str) -> Result<()> {
    let e = |err: bergshamra_core::Error| LibError::Xml(err.to_string());
    w.start_element(tag, &[]).map_err(e)?;
    w.write_text(text).map_err(e)?;
    w.end_element(tag).map_err(e)
}

fn write_opt_b64_element(w: &mut XmlWriter, tag: &str, value: Option<&[u8]>) -> Result<()> {
    let e = |err: bergshamra_core::Error| LibError::Xml(err.to_string());
    w.start_element(tag, &[]).map_err(e)?;
    if let Some(v) = value {
        w.write_text(&B64.encode(v)).map_err(e)?;
    }
    w.end_element(tag).map_err(e)
}
