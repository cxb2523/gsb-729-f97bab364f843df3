import pytest
from cerbia.core.scanners.xss import _parser
from cerbia.core.scanners.xss._parser import _build_line_offsets, extract_code_ranges

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("text", "expected_offsets"),
    [
        ("", [0]),
        ("one line", [0]),
        ("first\nsecond\nthird", [0, 6, 13]),
    ],
    ids=["empty_text", "single_line", "multiple_lines"],
)
def test_build_line_offsets_returns_start_offset_for_each_line_when_text_is_provided(
    text: str, expected_offsets: list[int]
) -> None:
    result = _build_line_offsets(text)

    assert result == expected_offsets


@pytest.mark.parametrize(
    ("text", "expected_ranges"),
    [
        ("<code>example</code>", [(0, 13)]),
        ("<PRE>example</PRE>", [(0, 12)]),
        ("before\n<textarea>example</textarea>\nafter", [(7, 24)]),
        ("<code>unclosed", []),
        ("<code>first</code><pre>second</pre>", [(0, 11), (18, 29)]),
    ],
    ids=["code_tag", "mixed_case_pre_tag", "multiline_textarea", "unclosed_tag", "multiple_safe_tags"],
)
def test_extract_code_ranges_returns_expected_safe_ranges_when_html_is_provided(
    text: str, expected_ranges: list[tuple[int, int]]
) -> None:
    result = extract_code_ranges(text)

    assert result == expected_ranges


def test_extract_code_ranges_returns_empty_ranges_when_html_parser_raises(mocker) -> None:
    parser = mocker.Mock()
    parser.feed.side_effect = ValueError("Malformed HTML")
    mocker.patch.object(_parser, "_CodeBlockParser", return_value=parser)

    result = extract_code_ranges("<code>malformed")

    assert result == []
