import pytest
from cerbia.core.scanners.pii._checksums import (
    validate_cpf_checksum,
    validate_dni_checksum,
    validate_iban_checksum,
    validate_imei_checksum,
    validate_luhn_checksum,
    validate_nie_checksum,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("dni", "expected"),
    [
        ("12345678Z", True),
        ("12345678-Z", True),
        ("12345678z", True),
        ("00000000T", True),
        ("00000001R", True),
        ("12345678A", False),
        ("123", False),
        ("1234567890", False),
        ("1234567AZ", False),
        ("123456789", False),
        ("¹²³⁴⁵⁶⁷⁸Z", False),
        ("12345678¹", False),
        ("", False),
    ],
)
def test_validate_dni_checksum(dni: str, expected: bool) -> None:
    assert validate_dni_checksum(dni) is expected


@pytest.mark.parametrize(
    ("nie", "expected"),
    [
        ("X1234567L", True),
        ("X-1234567-L", True),
        ("Y1234567X", True),
        ("Z1234567R", True),
        ("X1234567A", False),
        ("W1234567L", False),
        ("X123", False),
        ("X123456AL", False),
        ("X12345671", False),
        ("X¹²³⁴⁵⁶⁷L", False),
        ("X1234567¹", False),
        ("", False),
    ],
)
def test_validate_nie_checksum(nie: str, expected: bool) -> None:
    assert validate_nie_checksum(nie) is expected


@pytest.mark.parametrize(
    ("card_number", "expected"),
    [
        ("4111 1111 1111 1111", True),
        ("5555 5555 5555 4444", True),
        ("3782 822463 10005", True),
        ("6011 1111 1111 1117", True),
        ("49927398716", True),
        ("490154203237518", True),  # IMEI test vector
        ("4111 1111 1111 1112", False),
        ("49927398717", False),
        ("4", False),
        ("", False),
        ("abc-def", False),
        ("⁴¹¹¹ 1111 1111 1111", False),
    ],
)
def test_validate_luhn_checksum(card_number: str, expected: bool) -> None:
    assert validate_luhn_checksum(card_number) is expected


@pytest.mark.parametrize(
    ("iban", "expected"),
    [
        ("ES9121000418450200051332", True),
        ("ES91 2100 0418 4502 0005 1332", True),
        ("ES9121000418450200051333", False),
        ("ES12", False),
        ("ES" + "1" * 40, False),
        ("1234567890123456", False),
        ("ES91 2100 0418 4502 @@@@", False),
        ("ES⁹¹ 2100 0418 4502 0005", False),
    ],
)
def test_validate_iban_checksum(iban: str, expected: bool) -> None:
    assert validate_iban_checksum(iban) is expected


@pytest.mark.parametrize(
    ("cpf", "expected"),
    [
        ("52998224725", True),
        ("529.982.247-25", True),
        ("123.456.789-01", False),
        ("111.111.111-11", False),
        ("123", False),
        ("52998224726", False),
        ("52998224735", False),
        ("⁵²⁹⁹⁸²²⁴⁷²⁵", False),
    ],
)
def test_validate_cpf_checksum(cpf: str, expected: bool) -> None:
    assert validate_cpf_checksum(cpf) is expected


@pytest.mark.parametrize(
    ("imei", "expected"),
    [
        ("IMEI: 490154203237518", True),
        ("imei 490154203237518", True),
        ("IMEI#490154203237518", True),
        ("490154203237518", True),
        ("49-015420-323751-8", True),
        ("IMEI: 490154203237519", False),
        ("IMEI: 49015420323751", False),
        ("IMEI: 4901542032375188", False),
        ("IMEI: 49015420323751A", False),
        ("IMEI: ⁴⁹⁰¹⁵⁴²⁰³²³⁷⁵¹⁸", False),
        ("", False),
    ],
)
def test_validate_imei_checksum(imei: str, expected: bool) -> None:
    assert validate_imei_checksum(imei) is expected
