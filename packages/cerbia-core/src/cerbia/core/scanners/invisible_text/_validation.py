import unicodedata

from ._constants import BIDI_OVERRIDES, INVISIBLE_CODEPOINTS, TAG_CHAR_RANGE


def classify_characters(text: str) -> tuple[tuple[int, int, int, int, int], list[str], list[str]]:
    invisible_count = 0
    bidi_count = 0
    cf_count = 0
    tag_count = 0
    co_cn_count = 0
    found_chars: list[str] = []
    cleaned_chars: list[str] = []

    for ch in text:
        cp = ord(ch)
        detected = _detect_char_type(ch, cp)

        if detected == "invisible":
            invisible_count += 1
        elif detected == "bidi":
            bidi_count += 1
        elif detected == "tag":
            tag_count += 1
        elif detected == "co_cn":
            co_cn_count += 1
        elif detected == "cf":
            cf_count += 1

        if detected:
            if len(found_chars) < 5:
                found_chars.append(f"U+{cp:04X} ({unicodedata.name(ch, 'UNKNOWN')})")
        else:
            cleaned_chars.append(ch)

    return (invisible_count, bidi_count, cf_count, tag_count, co_cn_count), found_chars, cleaned_chars


def _detect_char_type(ch: str, cp: int) -> str | None:
    if cp in INVISIBLE_CODEPOINTS:
        return "invisible"

    if cp in BIDI_OVERRIDES:
        return "bidi"

    if cp in TAG_CHAR_RANGE:
        return "tag"

    category = unicodedata.category(ch)
    if category in ("Co", "Cn"):
        return "co_cn"

    if category == "Cf":
        return "cf"

    return None
