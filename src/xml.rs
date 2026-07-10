use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bergshamra_xml::{Document, NodeId};

pub(crate) fn is_element(doc: &Document<'_>, id: NodeId, ns_uri: &str, local: &str) -> bool {
    doc.element(id).is_some_and(|e| {
        &*e.name.local_name == local && e.name.namespace_uri.as_deref().unwrap_or("") == ns_uri
    })
}

/// First direct child element `{ns_uri}:{local}` of `parent`.
pub(crate) fn child(
    doc: &Document<'_>,
    parent: NodeId,
    ns_uri: &str,
    local: &str,
) -> Option<NodeId> {
    doc.children(parent)
        .into_iter()
        .find(|&id| is_element(doc, id, ns_uri, local))
}

/// All direct child elements `{ns_uri}:{local}` of `parent`.
pub(crate) fn children(
    doc: &Document<'_>,
    parent: NodeId,
    ns_uri: &str,
    local: &str,
) -> Vec<NodeId> {
    doc.children(parent)
        .into_iter()
        .filter(|&id| is_element(doc, id, ns_uri, local))
        .collect()
}

/// All descendant elements `{ns_uri}:{local}` of `root`.
pub(crate) fn descendants(
    doc: &Document<'_>,
    root: NodeId,
    ns_uri: &str,
    local: &str,
) -> Vec<NodeId> {
    doc.descendants(root)
        .into_iter()
        .filter(|&id| is_element(doc, id, ns_uri, local))
        .collect()
}

pub(crate) fn attr<'a>(doc: &'a Document<'_>, id: NodeId, name: &str) -> Option<&'a str> {
    doc.element(id).and_then(|e| e.get_attribute(name))
}

pub(crate) fn text(doc: &Document<'_>, id: NodeId) -> String {
    doc.text_content_deep(id).trim().to_owned()
}

/// Whether `node` is inside the subtree rooted at `root`.
pub(crate) fn is_within(doc: &Document<'_>, root: NodeId, node: NodeId) -> bool {
    doc.descendants(root).into_iter().any(|id| id == node)
}

pub(crate) fn decode_b64(text: &str) -> Option<Vec<u8>> {
    B64.decode(text.replace(['\n', '\r', '\t', ' '], "")).ok()
}
