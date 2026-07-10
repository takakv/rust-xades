use asice::Container;

use xades::{validate, DataObject, Profile, ValidationOptions};

const XADES_LT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/xades-lt.asice");

// Containers from https://github.com/open-eid/SiVa
const ASICE_XADES_T: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/asiceWithXades-t-level.asice"
);

fn data_objects(container: &Container) -> Vec<DataObject<'_>> {
    container
        .data_files()
        .iter()
        .map(|f| DataObject {
            name: &f.name,
            mime_type: &f.mime_type,
            content: &f.content,
        })
        .collect()
}

fn trust_options() -> ValidationOptions {
    let mut options = ValidationOptions::default();
    options
        .add_trusted_pem(include_bytes!("fixtures/test_roots.pem"))
        .unwrap();
    options
}

#[test]
fn validates_xades_lt_container() {
    let container = Container::open_file(XADES_LT).unwrap();
    let files = data_objects(&container);
    assert_eq!(container.signatures().len(), 1);

    let results = validate(&container.signatures()[0].xml, &files, &trust_options()).unwrap();
    assert_eq!(results.len(), 1);
    let sig = &results[0];
    assert!(
        sig.is_valid(),
        "errors: {:?}, warnings: {:?}",
        sig.errors,
        sig.warnings
    );
    assert_eq!(sig.profile, Profile::LT);
}

#[test]
fn validates_xades_t_container() {
    let container = Container::open_file(ASICE_XADES_T).unwrap();
    let files = data_objects(&container);
    assert_eq!(container.signatures().len(), 1);

    let results = validate(&container.signatures()[0].xml, &files, &trust_options()).unwrap();
    assert_eq!(results.len(), 1);
    let sig = &results[0];
    assert!(
        sig.is_valid(),
        "errors: {:?}, warnings: {:?}",
        sig.errors,
        sig.warnings
    );
    assert_eq!(sig.profile, Profile::T);
}
