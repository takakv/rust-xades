use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bergshamra_c14n::C14nMode;
use bergshamra_xml::{NodeSet, XmlDocument};
use xades::{sign, DataObject, SigningOptions, SoftwareSigner};

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

fn test_signer() -> SoftwareSigner {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["Test Signer".to_string()]).unwrap();
    SoftwareSigner::from_pem(signing_key.serialize_pem().as_bytes(), cert.der(), None).unwrap()
}

fn c14n_subtree(xml: &str, ns_uri: &str, local: &str, mode: C14nMode) -> Vec<u8> {
    let doc = bergshamra_xml::uppsala::parse(xml).unwrap();
    let node = XmlDocument::find_element(&doc, ns_uri, local).unwrap();
    let set = NodeSet::tree_without_comments(node, &doc);
    let empty: &[&str] = &[];
    bergshamra_c14n::canonicalize_doc(&doc, mode, Some(&set), empty).unwrap()
}

fn digest_values(xml: &str) -> Vec<Vec<u8>> {
    let doc = bergshamra_xml::uppsala::parse(xml).unwrap();
    XmlDocument::find_elements(&doc, xades::ns::DSIG, "DigestValue")
        .into_iter()
        .map(|n| B64.decode(doc.text_content_deep(n).trim()).unwrap())
        .collect()
}

#[test]
fn signed_document_verifies() {
    let signer = test_signer();
    let options = SigningOptions::default();
    let xml = sign(FILES, &signer, &options).unwrap().into_xml();

    let digests = digest_values(&xml);
    assert_eq!(digests.len(), 4);
    let sha256 = |b: &[u8]| bergshamra_crypto::digest::digest(xades::ns::SHA256, b).unwrap();
    assert_eq!(digests[0], sha256(b"This is a test file.\n"));
    assert_eq!(digests[1], sha256(&[1, 2, 3, 4]));

    let sp_c14n = c14n_subtree(
        &xml,
        xades::ns::XADES,
        "SignedProperties",
        C14nMode::Inclusive,
    );
    assert_eq!(digests[2], sha256(&sp_c14n));

    let signed_info = c14n_subtree(&xml, xades::ns::DSIG, "SignedInfo", C14nMode::Inclusive11);
    let doc = bergshamra_xml::uppsala::parse(&xml).unwrap();
    let sig_node = XmlDocument::find_element(&doc, xades::ns::DSIG, "SignatureValue").unwrap();
    let sig = B64.decode(doc.text_content_deep(sig_node).trim()).unwrap();

    let cert_node = XmlDocument::find_element(&doc, xades::ns::DSIG, "X509Certificate").unwrap();
    let cert_der = B64.decode(doc.text_content_deep(cert_node).trim()).unwrap();
    let cert_key = bergshamra_keys::loader::load_x509_cert_der(&cert_der).unwrap();
    let verify_key = cert_key.to_signing_key().unwrap();

    let alg = bergshamra_crypto::sign::from_uri(xades::ns::ECDSA_SHA256).unwrap();
    assert!(alg.verify(&verify_key, &signed_info, &sig).unwrap());

    assert!(xml.contains(r#"URI="test%20file.txt""#));
}

#[test]
fn container_round_trip_with_signature() {
    let signer = test_signer();
    let xml = sign(FILES, &signer, &SigningOptions::default())
        .unwrap()
        .into_xml();

    let mut container = asice::Container::new();
    for f in FILES {
        container
            .add_file(f.name, f.mime_type, f.content.to_vec())
            .unwrap();
    }
    container.add_signature_xml(xml);

    let reopened = asice::Container::from_bytes(&container.to_bytes().unwrap()).unwrap();
    assert_eq!(reopened.signatures().len(), 1);
    assert!(reopened.signatures()[0].xml.contains("XAdESSignatures"));
}
