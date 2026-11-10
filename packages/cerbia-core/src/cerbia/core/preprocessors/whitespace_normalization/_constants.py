import re

MIDLINE_TAB = re.compile(r"(?<!\n)\t(?!\n)")
LETTER_SPACED = re.compile(r"(?<!\w)(\w[ \t]){2,}\w(?!\w)")
