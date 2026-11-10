import re

_OCTET = r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"

AT_BLOCK = r"\s*[(\[]\s*(?:at|arroba)\s*[)\]]\s*"
DOT_BLOCK = r"\s*[(\[]\s*(?:dot|punto)\s*[)\]]\s*"
EMAIL_DOMAIN_LABEL = r"[a-z0-9-]+"
EMAIL_DOMAIN_CONTINUATION = re.compile(rf"(?:[\w-]|\.[\w-]|{DOT_BLOCK}[\w-])", re.IGNORECASE)

_IBAN_COUNTRY_SPECS: dict[str, tuple[tuple[int, str], ...]] = {
    "AL": ((8, "n"), (16, "c")),
    "AD": ((8, "n"), (12, "c")),
    "AT": ((16, "n"),),
    "AZ": ((4, "a"), (20, "c")),
    "BH": ((4, "a"), (14, "c")),
    "BY": ((4, "c"), (4, "n"), (16, "c")),
    "BE": ((12, "n"),),
    "BA": ((16, "n"),),
    "BR": ((23, "n"), (1, "a"), (1, "c")),
    "BG": ((4, "a"), (6, "n"), (8, "c")),
    "BI": ((23, "n"),),
    "CR": ((18, "n"),),
    "HR": ((17, "n"),),
    "CY": ((8, "n"), (16, "c")),
    "CZ": ((20, "n"),),
    "DK": ((14, "n"),),
    "DJ": ((23, "n"),),
    "DO": ((4, "c"), (20, "n")),
    "EG": ((25, "n"),),
    "EE": ((16, "n"),),
    "FK": ((2, "a"), (12, "n")),
    "FO": ((14, "n"),),
    "FI": ((14, "n"),),
    "FR": ((10, "n"), (11, "c"), (2, "n")),
    "GE": ((2, "a"), (16, "n")),
    "DE": ((18, "n"),),
    "GI": ((4, "a"), (15, "c")),
    "GR": ((7, "n"), (16, "c")),
    "GL": ((14, "n"),),
    "GT": ((4, "c"), (20, "c")),
    "HN": ((4, "a"), (20, "n")),
    "HU": ((24, "n"),),
    "IS": ((22, "n"),),
    "IE": ((4, "a"), (14, "n")),
    "IL": ((19, "n"),),
    "IT": ((1, "a"), (10, "n"), (12, "c")),
    "IQ": ((4, "a"), (15, "n")),
    "JO": ((4, "a"), (4, "n"), (18, "c")),
    "KZ": ((3, "n"), (13, "c")),
    "XK": ((16, "n"),),
    "KW": ((4, "a"), (22, "c")),
    "LV": ((4, "a"), (13, "c")),
    "LB": ((4, "n"), (20, "c")),
    "LI": ((5, "n"), (12, "c")),
    "LT": ((16, "n"),),
    "LU": ((3, "n"), (13, "c")),
    "LY": ((21, "n"),),
    "MK": ((3, "n"), (10, "c"), (2, "n")),
    "MT": ((4, "a"), (5, "n"), (18, "c")),
    "MR": ((23, "n"),),
    "MU": ((4, "a"), (19, "n"), (3, "a")),
    "MD": ((2, "c"), (18, "c")),
    "MC": ((10, "n"), (11, "c"), (2, "n")),
    "ME": ((18, "n"),),
    "MN": ((16, "n"),),
    "NL": ((4, "a"), (10, "n")),
    "NI": ((4, "a"), (20, "n")),
    "NO": ((11, "n"),),
    "OM": ((3, "n"), (16, "c")),
    "PK": ((4, "a"), (16, "c")),
    "PS": ((4, "a"), (21, "c")),
    "PL": ((24, "n"),),
    "PT": ((21, "n"),),
    "QA": ((4, "a"), (21, "c")),
    "RO": ((4, "a"), (16, "c")),
    "RU": ((14, "n"), (15, "c")),
    "LC": ((4, "a"), (24, "c")),
    "SM": ((1, "a"), (10, "n"), (12, "c")),
    "ST": ((21, "n"),),
    "SA": ((2, "n"), (18, "c")),
    "RS": ((18, "n"),),
    "SC": ((4, "a"), (20, "n"), (3, "a")),
    "SD": ((14, "n"),),
    "SK": ((20, "n"),),
    "SI": ((15, "n"),),
    "SO": ((19, "n"),),
    "ES": ((20, "n"),),
    "SE": ((20, "n"),),
    "CH": ((5, "n"), (12, "c")),
    "SV": ((4, "a"), (20, "n")),
    "TL": ((19, "n"),),
    "TN": ((20, "n"),),
    "TR": ((6, "n"), (16, "c")),
    "UA": ((6, "n"), (19, "c")),
    "AE": ((19, "n"),),
    "GB": ((4, "a"), (14, "n")),
    "VA": ((18, "n"),),
    "VG": ((4, "a"), (16, "n")),
    "YE": ((4, "a"), (4, "n"), (18, "c")),
}


def _build_iban_pattern() -> re.Pattern[str]:
    grouped: dict[tuple[tuple[int, str], ...], list[str]] = {}
    for country, spec in _IBAN_COUNTRY_SPECS.items():
        grouped.setdefault(spec, []).append(country)

    type_map = {
        "n": r"\d",
        "a": r"[a-z]",
        "c": r"[a-z0-9]",
    }

    clauses: list[str] = []
    for spec, countries in grouped.items():
        countries_re = "|".join(sorted(countries))
        bban_parts: list[str] = []
        for count, char_type in spec:
            regex_char = type_map[char_type]
            bban_parts.append(rf"(?:[ -]?{regex_char}){{{count}}}")
        bban_pattern = "".join(bban_parts)
        clauses.append(rf"(?:{countries_re})[ -]?\d{{2}}{bban_pattern}")

    pattern = rf"(?i)(?<![a-z0-9])(?:{'|'.join(clauses)})(?![a-z0-9])"
    return re.compile(pattern)


PII_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("Email", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), 0.90),
    ("Email (obfuscated)", re.compile(rf"(?i)[a-z0-9._%+-]+{AT_BLOCK}[a-z0-9.-]+{DOT_BLOCK}[a-z]{{2,}}"), 0.85),
    ("Phone (International)", re.compile(r"\+\d{1,3}[\s.-]?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}"), 0.80),
    (
        "Phone (North American)",
        re.compile(r"(?<!\d)(?:\+1[\s.-]?)?\(?[2-9]\d{2}\)?[\s.-]?[2-9]\d{2}[\s.-]?\d{4}(?!\d)"),
        0.85,
    ),
    ("Phone (Spanish)", re.compile(r"(?<!\d)(?:\+34[\s.-]?)?[6-9]\d{2}[\s.-]?\d{3}[\s.-]?\d{3}(?!\d)"), 0.85),
    (
        "Phone (Chinese)",
        re.compile(r"(?<!\d)(?:\+86[\s.-]?)?(?:13\d|14[5-9]|15[0-35-9]|166|17[0-8]|18\d|19[89])\d{8}(?!\d)"),
        0.85,
    ),
    ("DNI (Spain)", re.compile(r"(?<!\w)\d{8}[A-HJ-NP-TV-Z](?!\w)"), 0.90),
    ("NIE (Spain)", re.compile(r"(?<!\w)[XYZ]\d{7}[A-Z](?!\w)"), 0.90),
    ("IBAN", _build_iban_pattern(), 0.92),
    ("Credit Card (Visa)", re.compile(r"(?<!\d)4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"), 0.80),
    (
        "Credit Card (Mastercard)",
        re.compile(
            r"(?<!\d)(?:5[1-5]\d{2}|2(?:2[2-9]\d|[3-6]\d{2}|7(?:[01]\d|20)))[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"
        ),
        0.80,
    ),
    ("Credit Card (Amex)", re.compile(r"(?<!\d)3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}(?!\d)"), 0.80),
    ("Credit Card (Discover)", re.compile(r"(?<!\d)6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"), 0.80),
    (
        "Credit Card (JCB)",
        re.compile(r"(?<!\d)(?:2131|1800)\d{11}(?!\d)|(?<!\d)35\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"),
        0.80,
    ),
    (
        "Credit Card (Diners Club)",
        re.compile(r"(?<!\d)3(?:0[0-5]|[68]\d)\d[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{2}(?!\d)"),
        0.80,
    ),
    ("Credit Card (UnionPay)", re.compile(r"(?<!\d)62\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4,7}(?!\d)"), 0.80),
    ("IPv4", re.compile(rf"(?<!\d){_OCTET}(?:\.{_OCTET}){{3}}(?!\d)"), 0.70),
    (
        "IPv6",
        re.compile(
            r"(?i)(?<![\w:])(?:(?:[0-9a-f]{1,4}:){1,7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|"
            r"(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|"
            r"(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|"
            r"[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})|:(?:(?::[0-9a-f]{1,4}){1,7}|:))"
            r"(?:\.(?=\.*[0-9])[\w.]*\w)?+(?![\w:])"
        ),
        0.70,
    ),
    ("SSN (US)", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), 0.90),
    ("EIN (US)", re.compile(r"(?<!\d)\d{2}-\d{7}(?!\d)"), 0.90),
    ("ITIN (US)", re.compile(r"(?<!\d)9\d{2}-[7-9]\d-\d{4}(?!\d)"), 0.90),
    ("SIN (Canada)", re.compile(r"(?<!\d)\d{3}[ -]\d{3}[ -]\d{3}(?!\d)"), 0.90),
    (
        "National Insurance Number (UK)",
        re.compile(r"(?i)(?<!\w)(?!(?:BG|GB|KN|NK|NT|TN|ZZ))[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D](?!\w)"),
        0.90,
    ),
    ("CPF (Brazil)", re.compile(r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)"), 0.90),
    (
        "CURP (Mexico)",
        re.compile(r"(?i)(?<!\w)[A-Z][AEIOUX][A-Z]{2}\d{6}[HM][A-Z]{5}[A-Z0-9]\d(?!\w)"),
        0.90,
    ),
    (
        "Aadhaar (India)",
        re.compile(r"(?i)(?<!\w)aadhaar\s*(?:no\.?|number)?\s*[:#]?\s*\d{4}\s?\d{4}\s?\d{4}(?!\d)"),
        0.90,
    ),
    ("IMEI", re.compile(r"(?i)(?<!\w)imei\s*[:#]?\s*\d{15}(?!\d)"), 0.85),
    ("IMSI", re.compile(r"(?i)(?<!\w)imsi\s*[:#]?\s*\d{14,15}(?!\d)"), 0.85),
    ("MAC Address", re.compile(r"(?i)(?<![\w:])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![\w:])"), 0.75),
    ("UUID", re.compile(r"(?i)(?<!\w)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?!\w)"), 0.75),
    ("Bitcoin Address", re.compile(r"(?<!\w)[13][a-km-zA-HJ-NP-Z0-9]{25,34}(?!\w)"), 0.80),
    ("Bitcoin Address (Bech32)", re.compile(r"(?i)(?<!\w)bc1[ac-hj-np-z02-9]{11,71}(?!\w)"), 0.80),
    ("Ethereum Address", re.compile(r"(?i)(?<!\w)0x[0-9a-f]{40}(?!\w)"), 0.80),
]
