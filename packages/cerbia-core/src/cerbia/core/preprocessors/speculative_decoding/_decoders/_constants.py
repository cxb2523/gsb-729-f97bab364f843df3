import re

BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2,3}={0,2})?")
BASE64_FULL_RE = re.compile(r"^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2,3}={0,2})?$")
HEX_PATTERN = re.compile(r"[0-9A-Fa-f]{16,}")
BASE32_PATTERN = re.compile(r"(?<![A-Z2-7=])[A-Z2-7]{16,}={0,6}(?![A-Z2-7=])")
BASE32_FULL_RE = re.compile(r"^(?:[A-Z2-7]{8}){2,}(?:[A-Z2-7]{2,7}=*)?$")
URLENC_PATTERN = re.compile(r"(?:[^%\s]*%[0-9A-Fa-f]{2}){4,}[^%\s]*")
HTML_ENTITY_PATTERN = re.compile(r"(?:&(?:#\d+|#x[0-9A-Fa-f]+|[A-Za-z]+);){4,}")
UNICODE_ESCAPE_PATTERN = re.compile(r"(?:\\u[0-9A-Fa-f]{4}){4,}")
WORD_LIKE = re.compile(r"\b[a-zA-Z]{3,}\b")
LEET_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9@$!]{3,}")
PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
MEANINGFUL_LEET_CHARS = frozenset("01345789@$!")

BASE64_MIN_LENGTH = 16
BASE64_MIN_ENTROPY = 4.5
HEX_MIN_LENGTH = 16
HEX_MIN_ENTROPY = 3.0
HEX_MIN_PRINTABLE_RATIO = 0.85
BASE32_MIN_LENGTH = 16
BASE32_MIN_ENTROPY = 3.5
URLENC_MIN_LENGTH = 12
URLENC_MIN_ESCAPE_COUNT = 4
HTML_ENTITY_MIN_LENGTH = 16
UNICODE_ESCAPE_MIN_LENGTH = 24
LEET_MIN_DISTINCT_CHARS = 2
REVERSED_MIN_WORDS = 3
