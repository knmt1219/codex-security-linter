// Safe JavaScript examples - comments mentioning dangerous APIs must not trigger findings
// Note: do not use dangerouslySetInnerHTML unless sanitized by DOMPurify
// Avoid eval() or Function constructor

function renderSafeText(element, message) {
    // textContent safely escapes HTML entities
    element.textContent = message;
}
