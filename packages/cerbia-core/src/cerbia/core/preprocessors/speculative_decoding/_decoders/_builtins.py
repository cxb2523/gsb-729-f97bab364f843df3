import base64
import codecs
import gzip
import html
import re
import zlib
from urllib.parse import unquote_to_bytes

from ...._constants import LEET_TRANSLATE_TABLE
from ...._utils.math import shannon_entropy
from .._heuristics import printable_ratio
from .._types import Payload
from ._constants import (
    BASE32_FULL_RE,
    BASE32_MIN_ENTROPY,
    BASE32_MIN_LENGTH,
    BASE64_FULL_RE,
    BASE64_MIN_ENTROPY,
    BASE64_MIN_LENGTH,
    HEX_MIN_ENTROPY,
    HEX_MIN_LENGTH,
    HEX_MIN_PRINTABLE_RATIO,
    HTML_ENTITY_MIN_LENGTH,
    HTML_ENTITY_PATTERN,
    LEET_MIN_DISTINCT_CHARS,
    LEET_TOKEN_PATTERN,
    MEANINGFUL_LEET_CHARS,
    PERCENT_ESCAPE_RE,
    REVERSED_MIN_WORDS,
    UNICODE_ESCAPE_MIN_LENGTH,
    UNICODE_ESCAPE_PATTERN,
    URLENC_MIN_ESCAPE_COUNT,
    URLENC_MIN_LENGTH,
    URLENC_PATTERN,
    WORD_LIKE,
)


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy for text characters.

    Args:
        text (str): Candidate encoded text.

    Returns:
        float: Character-level entropy used by several decoder input gates.
    """
    if not text:
        return 0.0

    frequencies: dict[str, int] = {}
    for ch in text:
        frequencies[ch] = frequencies.get(ch, 0) + 1

    return shannon_entropy(frequencies.values(), len(text))


def base64_gate(text: str) -> bool:
    """Check whether text looks like a plausible Base64 payload.

    Args:
        text (str): Candidate text extracted from the source input.

    Returns:
        bool: ``True`` when the candidate meets the Base64 gate heuristics.
    """
    normalized = "".join(text.split())
    if len(normalized) < BASE64_MIN_LENGTH:
        return False

    if normalized.startswith(("http://", "https://", "ftp://", "s3://", "git+")):
        return False

    if "://" in normalized[:12]:
        return False

    if len(normalized) % 4 != 0:
        return False

    if BASE64_FULL_RE.fullmatch(normalized) is None:
        return False

    return _shannon_entropy(normalized) >= BASE64_MIN_ENTROPY


def hex_gate(text: str) -> bool:
    """Check whether text looks like a plausible hexadecimal payload.

    Args:
        text (str): Candidate text extracted from the source input.

    Returns:
        bool: ``True`` when the candidate meets the hex gate heuristics.
    """
    normalized = _normalized_hex_payload(text)
    if len(normalized) < HEX_MIN_LENGTH or len(normalized) % 2 != 0:
        return False

    if not normalized.isascii() or any(ch not in "0123456789abcdefABCDEF" for ch in normalized):
        return False

    if _shannon_entropy(normalized) < HEX_MIN_ENTROPY:
        return False

    decoded = bytes.fromhex(normalized)
    try:
        decoded_text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return False

    return printable_ratio(decoded_text) >= HEX_MIN_PRINTABLE_RATIO


def _normalized_hex_payload(text: str) -> str:
    return text.removeprefix("0x").removeprefix("0X")


def base32_gate(text: str) -> bool:
    """Check whether text looks like a plausible Base32 payload.

    Args:
        text (str): Candidate text extracted from the source input.

    Returns:
        bool: ``True`` when the candidate meets the Base32 gate heuristics.
    """
    normalized = "".join(text.split())
    if len(normalized) < BASE32_MIN_LENGTH:
        return False

    if len(normalized) % 8 != 0:
        return False

    if normalized.upper() != normalized:
        return False

    if BASE32_FULL_RE.fullmatch(normalized) is None:
        return False

    return _shannon_entropy(normalized) >= BASE32_MIN_ENTROPY


def urlenc_gate(text: str) -> bool:
    """Check whether text looks like a plausible URL-encoded payload.

    Args:
        text (str): Candidate text extracted from the source input.

    Returns:
        bool: ``True`` when the candidate contains enough structured escapes to decode.
    """
    return (
        len(text) >= URLENC_MIN_LENGTH
        and len(PERCENT_ESCAPE_RE.findall(text)) >= URLENC_MIN_ESCAPE_COUNT
        and URLENC_PATTERN.fullmatch(text) is not None
    )


def html_entity_gate(text: str) -> bool:
    """Check whether text looks like a run of HTML entities.

    Args:
        text (str): Candidate text extracted from the source input.

    Returns:
        bool: ``True`` when the candidate is long enough and matches the entity pattern.
    """
    return len(text) >= HTML_ENTITY_MIN_LENGTH and HTML_ENTITY_PATTERN.fullmatch(text) is not None


def unicode_escape_gate(text: str) -> bool:
    """Check whether text looks like repeated Unicode escape sequences.

    Args:
        text (str): Candidate text extracted from the source input.

    Returns:
        bool: ``True`` when the candidate matches the Unicode-escape pattern.
    """
    return len(text) >= UNICODE_ESCAPE_MIN_LENGTH and UNICODE_ESCAPE_PATTERN.fullmatch(text) is not None


def _always_on_gate(_text: str) -> bool:
    """Accept any candidate text.

    Args:
        _text (str): Ignored candidate text.

    Returns:
        bool: Always ``True``.
    """
    return True


# Transform gates accept all payloads; admission and registry rules control root/intensive eligibility.
rot13_gate = rot47_gate = leet_gate = reversed_gate = _always_on_gate


def decode_base64(payload: Payload) -> list[Payload]:
    """Decode a Base64 payload.

    Args:
        payload (Payload): Payload whose text should be interpreted as Base64.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when decoding fails.
    """
    if payload.text is None:
        return []

    try:
        raw = base64.b64decode(payload.text, validate=True)
        return [Payload.from_bytes(raw)]

    except ValueError:
        return []


def decode_hex(payload: Payload) -> list[Payload]:
    """Decode a hexadecimal payload.

    Args:
        payload (Payload): Payload whose text should be interpreted as hexadecimal bytes.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when decoding fails.
    """
    if payload.text is None:
        return []

    text = _normalized_hex_payload(payload.text)
    if len(text) % 2 != 0:
        return []

    try:
        raw = bytes.fromhex(text)
        return [Payload.from_bytes(raw)]

    except ValueError:
        return []


def decode_base32(payload: Payload) -> list[Payload]:
    """Decode a Base32 payload.

    Args:
        payload (Payload): Payload whose text should be interpreted as Base32.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when decoding fails.
    """
    if payload.text is None:
        return []

    try:
        raw = base64.b32decode(payload.text, casefold=True)
        return [Payload.from_bytes(raw)]

    except ValueError:
        return []


def decode_url(payload: Payload) -> list[Payload]:
    """Decode URL-encoded bytes from text.

    Args:
        payload (Payload): Payload whose text may contain percent escapes.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when decoding is a no-op.
    """
    if payload.text is None:
        return []

    raw = unquote_to_bytes(payload.text)
    if raw == payload.raw:
        return []

    return [Payload.from_bytes(raw)]


def decode_html_entities(payload: Payload) -> list[Payload]:
    """Decode HTML entities from text.

    Args:
        payload (Payload): Payload whose text may contain HTML entities.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when decoding is a no-op.
    """
    if payload.text is None:
        return []

    decoded = html.unescape(payload.text)
    if decoded == payload.text:
        return []

    return [Payload.from_text(decoded)]


def decode_unicode_escapes(payload: Payload) -> list[Payload]:
    """Decode Python-style Unicode escapes from text.

    Args:
        payload (Payload): Payload whose text may contain escaped Unicode sequences.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when decoding fails or is a no-op.
    """
    if payload.text is None:
        return []

    try:
        decoded = re.sub(r"\\u([0-9A-Fa-f]{4})", lambda match: chr(int(match.group(1), 16)), payload.text)
        if decoded == payload.text:
            return []

        return [Payload.from_text(decoded)]

    except UnicodeError:
        return []


def decode_rot13(payload: Payload) -> list[Payload]:
    """Decode ROT13 text.

    Args:
        payload (Payload): Payload whose text may be ROT13-encoded.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when decoding is a no-op.
    """
    if payload.text is None:
        return []

    decoded = codecs.decode(payload.text, "rot_13")
    if decoded == payload.text:
        return []

    return [Payload.from_text(decoded)]


def decode_rot47(payload: Payload) -> list[Payload]:
    """Decode ROT47 text.

    Args:
        payload (Payload): Payload whose text may be ROT47-encoded.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when decoding is a no-op.
    """
    if payload.text is None:
        return []

    chars: list[str] = []
    for ch in payload.text:
        cp = ord(ch)
        if 33 <= cp <= 126:
            chars.append(chr(33 + (cp - 33 + 47) % 94))
        else:
            chars.append(ch)

    decoded = "".join(chars)
    if decoded == payload.text:
        return []

    return [Payload.from_text(decoded)]


def decode_leetspeak(payload: Payload) -> list[Payload]:
    """Decode leetspeak text when the transform looks meaningful.

    Args:
        payload (Payload): Payload whose text may contain leetspeak substitutions.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when the transform is too weak.
    """
    if payload.text is None:
        return []

    decoded = payload.text.translate(LEET_TRANSLATE_TABLE)
    if decoded == payload.text:
        return []

    distinct_leet_chars = {ch for ch in payload.text if ch in MEANINGFUL_LEET_CHARS}
    if len(distinct_leet_chars) < LEET_MIN_DISTINCT_CHARS:
        return []

    decoded_tokens = 0
    for match in LEET_TOKEN_PATTERN.finditer(payload.text):
        token = match.group(0)
        if not any(ch in MEANINGFUL_LEET_CHARS for ch in token):
            continue
        if not any(ch.isalpha() for ch in token):
            continue

        decoded_token = token.translate(LEET_TRANSLATE_TABLE)
        if decoded_token != token and decoded_token.isalpha():
            decoded_tokens += 1

    if decoded_tokens == 0:
        return []

    return [Payload.from_text(decoded)]


def decode_reversed(payload: Payload) -> list[Payload]:
    """Decode reversed text when the reversed direction looks more word-like.

    Args:
        payload (Payload): Payload whose text may have been reversed.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when reversal does not improve readability.
    """
    if payload.text is None:
        return []

    reversed_text = payload.text[::-1]
    if reversed_text == payload.text:
        return []

    original_words = len(WORD_LIKE.findall(payload.text))
    reversed_words = len(WORD_LIKE.findall(reversed_text))

    if reversed_words > original_words and reversed_words >= REVERSED_MIN_WORDS:
        return [Payload.from_text(reversed_text)]

    return []


def decode_gzip(payload: Payload) -> list[Payload]:
    """Decompress gzip-compressed bytes.

    Args:
        payload (Payload): Payload whose raw bytes may contain gzip data.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when decompression fails.
    """
    try:
        raw = gzip.decompress(payload.raw)
        return [Payload.from_bytes(raw)]

    except (EOFError, OSError, zlib.error):
        return []


def decode_zlib(payload: Payload) -> list[Payload]:
    """Decompress zlib-compressed bytes.

    Args:
        payload (Payload): Payload whose raw bytes may contain zlib data.

    Returns:
        list[Payload]: Decoded payloads, or an empty list when decompression fails.
    """
    try:
        raw = zlib.decompress(payload.raw)
        return [Payload.from_bytes(raw)]

    except zlib.error:
        return []
