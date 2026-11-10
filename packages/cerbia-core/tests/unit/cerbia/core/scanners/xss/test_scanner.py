import pytest
from cerbia.core.scanners.xss import XssScanner
from cerbia.core.types import Action, ContentType, Severity

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("text", "expected_name", "expected_risk_score"),
    [
        ("<script>alert(1)</script>", "<script> tag", 0.95),
        ("<img src=x onerror=alert(1)>", "Event handler attribute", 0.95),
        ('<a href="javascript:alert(1)">link</a>', "javascript: URI", 0.95),
        ('<a href="data:text/html,payload">link</a>', "data: URI", 0.95),
        ("{{ user_input }}", "Template data binding", 0.60),
        ("[link](javascript:alert(1))", "Markdown javascript: link", 0.90),
    ],
    ids=["script_tag", "event_handler", "javascript_uri", "data_uri", "template_binding", "markdown_javascript"],
)
def test_xss_scanner_detects_default_vector_when_xss_payload_is_provided(
    text: str, expected_name: str, expected_risk_score: float
) -> None:
    scanner = XssScanner()

    result = scanner.scan(text)

    assert result.risk_score == expected_risk_score
    assert result.rationale.startswith("XSS vector(s) detected (")
    assert expected_name in result.rationale


@pytest.mark.parametrize(
    ("text", "expected_name", "expected_risk_score"),
    [
        ("< script >alert(1)", "<script> tag", 0.95),
        ("< / script >", "</script> close", 0.90),
        ("<div onclick=alert(1)>", "Event handler attribute", 0.85),
        ("<a href=' javascript:alert(1)'>", "javascript: URI", 0.95),
        ("<img src=javascript:alert(1)>", "javascript: URI", 0.95),
        ("<iframe src=about:blank>", "<iframe> tag", 0.90),
        ("<object data=payload>", "<object>/<embed> tag", 0.90),
        ("<svg>", "<svg> tag", 0.75),
        ("<img onerror=alert(1)>", "<img onerror=> XSS", 0.95),
        ('<span style="width: expression(alert(1))">', "CSS expression()", 0.85),
        ("{{ user.name }}", "Template data binding", 0.60),
        ("<div [innerHTML]=payload>", "Framework data binding", 0.60),
        ('<a href="data:text/html,payload">', "data: URI", 0.95),
        ("<img srcset=data:image/svg+xml,payload>", "data: URI", 0.95),
        ("<form onsubmit=alert(1)>", "<form> XSS", 0.90),
        ('<meta content="0;url=payload" http-equiv="refresh">', "<meta> refresh", 0.80),
        ("<link onload=alert(1)>", "<link> handler", 0.85),
        ('<base href="data:text/html,payload">', "<base> hijack", 0.95),
        ("<style>behavior: url(#default#userData)</style>", "<style> injection", 0.85),
        ("<svg>onmouseover=alert(1)", "SVG event handler", 0.90),
        ("[click](javascript:alert(1))", "Markdown javascript: link", 0.90),
        ("{% include 'payload' %}", "Markdown template injection", 0.65),
    ],
    ids=[
        "script_whitespace",
        "script_close_whitespace",
        "event_handler",
        "javascript_uri_quoted_whitespace",
        "javascript_uri_unquoted",
        "iframe",
        "object",
        "svg",
        "image_onerror",
        "css_expression",
        "template_binding",
        "framework_binding",
        "data_uri",
        "data_uri_srcset",
        "form_onsubmit",
        "meta_attribute_order",
        "link_handler",
        "base_data_uri",
        "style_content",
        "svg_event",
        "markdown_javascript_link",
        "markdown_template",
    ],
)
def test_xss_scanner_detects_each_named_pattern_when_legacy_payload_is_provided(
    text: str, expected_name: str, expected_risk_score: float
) -> None:
    scanner = XssScanner()

    result = scanner.scan(text)

    assert result.risk_score == expected_risk_score
    assert expected_name in result.rationale


def test_xss_scanner_returns_safe_outcome_when_xss_vector_is_not_detected() -> None:
    scanner = XssScanner()

    result = scanner.scan("The documentation contains plain, safe text.")

    assert result.risk_score == 0.0
    assert result.rationale == "No XSS vectors detected"


@pytest.mark.parametrize(
    "text",
    [
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        r"\u003cscript\u003ealert(1)\u003c/script\u003e",
    ],
    ids=["html_entities", "url_encoded", "unicode_escaped"],
)
def test_xss_scanner_normalizes_encoded_payload_when_xss_vector_is_provided(text: str) -> None:
    scanner = XssScanner()

    result = scanner.scan(text)

    assert result.risk_score == 0.95
    assert "<script> tag" in result.rationale


def test_xss_scanner_uses_highest_risk_and_limits_rationale_to_first_five_vectors() -> None:
    scanner = XssScanner()
    text = (
        "<script>alert(1)</script><iframe src=x><object></object><svg></svg>"
        "<img src=x onerror=alert(1)><meta http-equiv=refresh>"
    )

    result = scanner.scan(text)

    assert result.risk_score == 0.95
    assert result.rationale.startswith("XSS vector(s) detected (9):")
    assert "<script> tag" in result.rationale
    assert "<meta> refresh" not in result.rationale


@pytest.mark.parametrize("tag", ["code", "pre", "textarea"], ids=["code", "pre", "textarea"])
def test_xss_scanner_skips_vector_inside_safe_html_tag_when_context_aware_is_enabled(tag: str) -> None:
    scanner = XssScanner(html_context_aware=True)

    result = scanner.scan(f"<{tag}><script>alert(1)</script></{tag}>")

    assert result.risk_score == 0.0
    assert result.rationale == "No XSS vectors detected"


def test_xss_scanner_detects_vector_outside_safe_html_tag_when_context_aware_is_enabled() -> None:
    scanner = XssScanner(html_context_aware=True)

    result = scanner.scan("<code>safe example</code><script>alert(1)</script>")

    assert result.risk_score == 0.95
    assert "<script> tag" in result.rationale


def test_xss_scanner_skips_normalized_vector_after_length_changing_prefix_when_context_aware_is_enabled() -> None:
    scanner = XssScanner(html_context_aware=True)

    result = scanner.scan("&amp;&amp;&amp;&amp;&amp;<code><script>alert(1)</script></code>")

    assert result.risk_score == 0.0
    assert result.rationale == "No XSS vectors detected"


def test_xss_scanner_skips_normalized_vector_in_multiline_safe_block_when_context_aware_is_enabled() -> None:
    scanner = XssScanner(html_context_aware=True)

    result = scanner.scan("<pre>\n&lt;script&gt;alert(1)&lt;/script&gt;\n</pre>")

    assert result.risk_score == 0.0
    assert result.rationale == "No XSS vectors detected"


def test_xss_scanner_detects_unsafe_repeated_vector_after_safe_occurrence_when_context_aware_is_enabled() -> None:
    scanner = XssScanner(html_context_aware=True)

    result = scanner.scan("<code><script>alert(1)</script></code><script>alert(2)</script>")

    assert result.risk_score == 0.95
    assert result.rationale.startswith("XSS vector(s) detected (2):")
    assert "<script> tag" in result.rationale


def test_xss_scanner_detects_safe_block_vector_when_context_awareness_is_disabled() -> None:
    scanner = XssScanner()

    result = scanner.scan("<code><script>alert(1)</script></code><script>alert(2)</script>")

    assert result.risk_score == 0.95
    assert result.rationale.startswith("XSS vector(s) detected (4):")
    assert "<script> tag" in result.rationale


def test_xss_scanner_preserves_configuration_when_custom_values_are_provided() -> None:
    scanner = XssScanner(
        html_context_aware=True,
        severity=Severity.CRITICAL,
        action=Action.WARN,
        content_types=[ContentType.TEXT, ContentType.CODE],
    )

    assert scanner.scanner_id == "xss"
    assert scanner.scanner_name == "XSS"
    assert scanner.severity is Severity.CRITICAL
    assert scanner.action is Action.WARN
    assert scanner.content_types == (ContentType.TEXT, ContentType.CODE)
    assert scanner._html_context_aware
