import re

ZERO_WIDTH_PATTERN = re.compile(r"[\u200b-\u200f\u2060-\u2064\u00ad\u034f\ufeff]")
