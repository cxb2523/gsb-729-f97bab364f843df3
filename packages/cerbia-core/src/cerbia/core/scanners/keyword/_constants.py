import re

CODE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Code Execution", re.compile(r"\b(exec|eval|__import__)\b", re.IGNORECASE)),
    ("OS Command", re.compile(r"\b(import\s+os|subprocess|curl|wget)\b", re.IGNORECASE)),
]
