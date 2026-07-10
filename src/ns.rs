pub const DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
pub const ASIC: &str = "http://uri.etsi.org/02918/v1.2.1#";

pub const TYPE_SIGNED_PROPERTIES: &str = "http://uri.etsi.org/01903#SignedProperties";

pub const C14N11: &str = "http://www.w3.org/2006/12/xml-c14n11";

// BDOC also allows SHA-1 and SHA-224, but we consider them deprecated.
pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
pub const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

// BDOC also allows RSA with SHA-1 and SHA-224, but we consider them deprecated.
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
pub const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

// BDOC also allows ECDSA with SHA-1 and SHA-224, but we consider them deprecated.
pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
pub const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
pub const ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
