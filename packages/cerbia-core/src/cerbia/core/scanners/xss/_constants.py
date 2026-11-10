import re

_SCRIPT_TAG = re.compile(r"<\s*script\b[^>]*>", re.IGNORECASE)
_SCRIPT_CLOSE = re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE)
_EVENT_HANDLER = re.compile(r"\b(on\w+)\s*=\s*[\"']?[^\"'\s>]+", re.IGNORECASE)
_JAVASCRIPT_URI = re.compile(r"(?i)(?:href|src|action)\s*=\s*(?:[\"']\s*)?javascript:")
_IFRAME_TAG = re.compile(r"<\s*iframe\b[^>]*>", re.IGNORECASE)
_OBJECT_EMBED = re.compile(r"<\s*(object|embed|applet)\b[^>]*>", re.IGNORECASE)
_SVG_TAG = re.compile(r"<\s*svg\b[^>]*>", re.IGNORECASE)
_IMG_ONERROR = re.compile(r"<\s*img\b[^>]*\bonerror\s*=", re.IGNORECASE)
_STYLE_EXPRESSION = re.compile(r"(?i)style\s*=\s*[\"'][^\"']*expression\s*\(")
_TEMPLATE_BINDING = re.compile(r"\{\{.+?\}\}")
_FRAMEWORK_BINDING = re.compile(r"(?:ng|v)-\w+\s*=|\[[\w.]+\]\s*=", re.IGNORECASE)

_DATA_URI = re.compile(
    r"(?i)(?:href|src|action|srcset)\s*=\s*(?:[\"']\s*)?data:(?:text/html|application/javascript|image/svg\+xml|application/xhtml\+xml)"
)
_FORM_TAG = re.compile(r"(?i)<\s*form\b[^>]*(?:onsubmit|action\s*=\s*(?:[\"']\s*)?javascript:)")
_META_REFRESH = re.compile(r"(?i)<\s*meta\b[^>]*\b(?:http-equiv|name)\s*=\s*[\"']?refresh")
_LINK_HANDLER = re.compile(r"(?i)<\s*link\b[^>]*(?:onload|onerror)\s*=")
_BASE_TAG = re.compile(r"(?i)<\s*base\b[^>]*href\s*=\s*(?:[\"']\s*)?(?:javascript:|data:)")
_STYLE_CONTENT = re.compile(
    r"(?i)<\s*style[^>]*>.*?(?:behavior\s*:|expression\s*\(|@import\s+url\s*\(\s*javascript:)", re.DOTALL
)
_SVG_EVENT = re.compile(r"(?i)<svg[^>]*>.*?(?:onload|onerror|onmouseover|onmouseenter)\s*=", re.DOTALL)
_MARKDOWN_JS_LINK = re.compile(r"\[[^\]]*\]\(\s*javascript:", re.IGNORECASE)
_MARKDOWN_TEMPLATE = re.compile(r"\{%.*?%\}")

ALL_PATTERNS: list[tuple[str, re.Pattern[str], float, str]] = [
    ("<script> tag", _SCRIPT_TAG, 0.95, "high"),
    ("</script> close", _SCRIPT_CLOSE, 0.90, "high"),
    ("Event handler attribute", _EVENT_HANDLER, 0.85, "high"),
    ("javascript: URI", _JAVASCRIPT_URI, 0.95, "high"),
    ("<iframe> tag", _IFRAME_TAG, 0.90, "high"),
    ("<object>/<embed> tag", _OBJECT_EMBED, 0.90, "high"),
    ("<svg> tag", _SVG_TAG, 0.75, "medium"),
    ("<img onerror=> XSS", _IMG_ONERROR, 0.95, "high"),
    ("CSS expression()", _STYLE_EXPRESSION, 0.85, "high"),
    ("Template data binding", _TEMPLATE_BINDING, 0.60, "low"),
    ("Framework data binding", _FRAMEWORK_BINDING, 0.60, "low"),
    ("data: URI", _DATA_URI, 0.95, "high"),
    ("<form> XSS", _FORM_TAG, 0.90, "high"),
    ("<meta> refresh", _META_REFRESH, 0.80, "medium"),
    ("<link> handler", _LINK_HANDLER, 0.85, "high"),
    ("<base> hijack", _BASE_TAG, 0.95, "high"),
    ("<style> injection", _STYLE_CONTENT, 0.85, "high"),
    ("SVG event handler", _SVG_EVENT, 0.90, "high"),
    ("Markdown javascript: link", _MARKDOWN_JS_LINK, 0.90, "high"),
    ("Markdown template injection", _MARKDOWN_TEMPLATE, 0.65, "medium"),
]

CODE_TAGS = frozenset({"code", "pre", "textarea"})
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
