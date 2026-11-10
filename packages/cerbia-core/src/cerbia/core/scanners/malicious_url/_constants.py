import re

PUNYCODE_PATTERN = re.compile(r"xn--")

DATA_URI_PATTERN = re.compile(r"(?i)data:\s*(?:text/html|application/javascript|image/svg\+xml|application/xhtml\+xml)")

REDIRECT_PARAMS = frozenset(
    {
        "url",
        "redirect",
        "next",
        "goto",
        "target",
        "return",
        "redir",
        "dest",
        "continue",
    }
)

PERCENT_ENCODING_RE = re.compile(r"%[0-9a-fA-F]{2}")
PERCENT_ENCODING_THRESHOLD = 5
