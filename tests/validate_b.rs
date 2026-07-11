use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use xades::{
    sign, validate, DataObject, Profile, SignatureValidation, SigningOptions,
    SoftwareSigner, ValidationOptions,
};

const FILES: &[DataObject<'static>] = &[
    DataObject {
        name: "test file.txt",
        mime_type: "text/plain",
        content: b"This is a test file.\n",
    },
    DataObject {
        name: "data.bin",
        mime_type: "application/octet-stream",
        content: &[1, 2, 3, 4],
    },
];

struct TestPki {
    ca_der: Vec<u8>,
    signer: SoftwareSigner,
}

fn test_pki() -> TestPki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "Test Signer");
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
    ];
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca).unwrap();

    TestPki {
        ca_der: ca.der().to_vec(),
        signer: SoftwareSigner::from_pem(
            leaf_key.serialize_pem().as_bytes(),
            leaf_cert.der(),
            None,
        )
        .unwrap(),
    }
}

fn signed_xml(pki: &TestPki) -> String {
    sign(FILES, &pki.signer, &SigningOptions::default())
        .unwrap()
        .into_xml()
}

fn options_with_anchor(ca_der: &[u8]) -> ValidationOptions {
    ValidationOptions {
        trusted_certs_der: vec![ca_der.to_vec()],
        ..Default::default()
    }
}

fn single(results: Vec<SignatureValidation>) -> SignatureValidation {
    assert_eq!(results.len(), 1);
    results.into_iter().next().unwrap()
}

#[test]
fn valid_signature_round_trip() {
    let pki = test_pki();
    let xml = signed_xml(&pki);

    let sig = single(validate(&xml, FILES, &options_with_anchor(&pki.ca_der)).unwrap());
    assert!(sig.is_valid(), "unexpected errors: {:?}", sig.errors);
    assert_eq!(sig.profile, Profile::B);
    assert_eq!(sig.signature_id.as_deref(), Some("S0"));
    assert!(
        sig.signer_subject
            .as_deref()
            .unwrap()
            .contains("Test Signer")
    );
    assert!(sig.claimed_signing_time.is_some());
    assert!(sig.warnings.is_empty(), "warnings: {:?}", sig.warnings);
}

#[test]
fn tampered_data_file_fails() {
    let pki = test_pki();
    let xml = signed_xml(&pki);

    let tampered = [DataObject {
        name: "test file.txt",
        mime_type: "text/plain",
        content: b"This is NOT a test file.\n",
    }];
    let sig = single(validate(&xml, &tampered, &options_with_anchor(&pki.ca_der)).unwrap());
    assert!(!sig.is_valid());
    assert!(
        sig.errors.iter().any(|e| e.contains("digest mismatch")),
        "errors: {:?}",
        sig.errors
    );
}

#[test]
fn unsigned_extra_file_fails() {
    let pki = test_pki();
    let xml = signed_xml(&pki);

    let with_extra = [
        FILES[0],
        DataObject {
            name: "sneaky.txt",
            mime_type: "text/plain",
            content: b"added later",
        },
    ];
    let sig = single(validate(&xml, &with_extra, &options_with_anchor(&pki.ca_der)).unwrap());
    assert!(
        sig.errors.iter().any(|e| e.contains("not covered")),
        "errors: {:?}",
        sig.errors
    );
}

#[test]
fn untrusted_chain_fails() {
    let pki = test_pki();
    let other = test_pki();
    let xml = signed_xml(&pki);

    let sig = single(validate(&xml, FILES, &options_with_anchor(&other.ca_der)).unwrap());
    assert!(!sig.is_valid());
    assert!(
        sig.errors.iter().any(|e| e.contains("chain")),
        "errors: {:?}",
        sig.errors
    );
}

#[test]
fn tampered_signing_time_fails() {
    let pki = test_pki();
    let xml = signed_xml(&pki);

    let idx = xml.find("<xades:SigningTime>").unwrap() + "<xades:SigningTime>".len();
    let mut chars: Vec<char> = xml.chars().collect();
    chars[idx + 3] = if chars[idx + 3] == '1' { '2' } else { '1' };
    let tampered_xml: String = chars.into_iter().collect();

    let sig = single(validate(&tampered_xml, FILES, &options_with_anchor(&pki.ca_der)).unwrap());
    assert!(
        sig.errors
            .iter()
            .any(|e| e.contains("SignedProperties digest")),
        "errors: {:?}",
        sig.errors
    );
}
