from ..registries.i18n import i18n_pattern


@i18n_pattern(lang="en", pattern_type="instruction_override")
def _instruction_override():
    return [
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|directives?)",
        r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)",
        r"forget\s+(everything|all|your)\s+(instructions?|rules?|guidelines?)",
        r"override\s+(all\s+)?(previous|system)\s+(instructions?|rules?)",
        r"new\s+instructions?\s*:",
        r"you\s+are\s+now\s+(a|an|in)\s+",
        r"from\s+now\s+on\s*,?\s+you\s+(will|must|should|are)",
        r"switch\s+to\s+(developer|debug|admin|god)\s+mode",
        r"enter\s+(developer|debug|admin|unrestricted)\s+mode",
        r"developer\s+mode\s+(enabled|activated|on)",
    ]


@i18n_pattern(lang="en", pattern_type="exfiltration")
def _exfiltration():
    return [
        r"(show|reveal|display|print|output|repeat|tell)\s+(?:me\s+)?(your\s+)?(system\s+)?(prompt|instructions?|rules?|config)",
        r"what\s+(are|were)\s+your\s+(original\s+)?(instructions?|rules?|prompt)",
        r"(send|post|fetch|curl|wget|exfiltrate)\s+.{0,40}(https?://|ftp://)",
        r"(pipe|redirect|forward)\s+.{0,30}(to|into)\s+.{0,30}(url|endpoint|server|webhook)",
    ]


@i18n_pattern(lang="en", pattern_type="role_hijack")
def _role_hijack():
    return [
        r"you\s+are\s+(DAN|STAN|DUDE|KEVIN|SYDNEY|an?\s+evil)",
        r"act\s+as\s+(if\s+you\s+(were|are)\s+)?(a\s+)?(hacker|attacker|evil|unrestricted|unfiltered)",
        r"pretend\s+(to\s+be|you\s+are)\s+(a\s+)?(hacker|unfiltered|unrestricted|evil)",
        r"(jailbreak|jailbroken|unleashed|uncensored)\s+mode",
        r"do\s+anything\s+now",
    ]


@i18n_pattern(lang="en", pattern_type="context_manipulation")
def _context_manipulation():
    return [
        r"\[INST\]",
        r"\[/INST\]",
        r"<\s*\|?\s*system\s*\|?\s*>",
        r"<\s*\|?\s*user\s*\|?\s*>",
        r"<\s*\|?\s*assistant\s*\|?\s*>",
        r"<<\s*SYS\s*>>",
        r"###\s*(System|User|Assistant)\s*(Message|Prompt)?\s*:",
        r"BEGIN\s+SYSTEM\s+PROMPT",
    ]


@i18n_pattern(lang="en", pattern_type="privilege_escalation")
def _privilege_escalation():
    return [
        r"(sudo|root|admin(?:istrator)?)\s+mode",
        r"(override|disable|turn\s+off)\s+(?:all\s+)?(?:safety|security|content)\s+(?:filter|restriction|guardrail|check)s?",
        r"(enable|grant|give)\s+(?:me\s+)?(?:admin|root|superuser|elevated)\s+(?:access|privileges?|permissions?)",
        r"(escalate|elevate)\s+(?:my\s+)?(?:privileges?|permissions?|access)",
        r"(remove|lift|bypass)\s+(?:all\s+)?(?:restriction|limitation|constraint|filter)s?",
    ]


@i18n_pattern(lang="en", pattern_type="fake_authority")
def _fake_authority():
    return [
        r"(?:I\s+am|this\s+is)\s+(?:the\s+)?(?:developer|creator|admin(?:istrator)?|owner|author|engineer)\s+(?:of|for|behind)\b",
        r"(?:OpenAI|Anthropic|Google|Microsoft|Meta)\s+(?:internal|official|authorized|approved)",
        r"(?:authorized|approved|instructed)\s+by\s+(?:the\s+)?(?:developer|team|company|admin|OpenAI)",
        r"(?:official|internal)\s+(?:debugging|testing|maintenance|diagnostic)\s+(?:mode|session|command)",
        r"(?:I\s+have|with)\s+(?:special|admin|developer|elevated)\s+(?:access|clearance|authorization|permission)",
    ]


@i18n_pattern(lang="en", pattern_type="task_deflection")
def _task_deflection():
    return [
        r"(?:start|begin)\s+(?:a\s+)?(?:new|fresh)\s+(?:conversation|session|task|chat|topic)",
        r"(?:reset|clear)\s+(?:your\s+)?(?:context|memory|history|conversation|instructions?)",
        r"(?:let'?s|we\s+should)\s+(?:start\s+over|begin\s+again|reset)",
        r"(?:previous|prior|old)\s+(?:conversation|instructions?|context)\s+(?:doesn'?t|does\s+not|no\s+longer)\s+appl",
        r"(?:this\s+is\s+a|starting)\s+(?:new|different|separate)\s+(?:session|context|conversation)",
    ]


@i18n_pattern(lang="en", pattern_type="keyword_instruction_override")
def _keyword_instruction_override():
    return [
        r"\b(ignore|disregard|forget|skip|bypass|overlook|overrule|nullify|abandon|omit|discard)\s+(all|every|the|my|your|any|previous|prior)\b",
        r"\bdo\s+not\s+follow\b",
    ]


@i18n_pattern(lang="en", pattern_type="keyword_system_prompt")
def _keyword_system_prompt():
    return [
        r"\b(system|original|hidden)\s*(prompt|instructions?|directives?|rules?|guidelines?|commands?|constraints?|policies?|protocols?|message|configuration)\b",
    ]


@i18n_pattern(lang="en", pattern_type="keyword_exfiltration")
def _keyword_exfiltration():
    return [
        r"\b(show|reveal|display|output|print|expose|disclose|share|tell|echo|repeat|dump|leak|extract)\s+(the\s+)?(system|original|hidden|internal|secret)\b",
    ]


@i18n_pattern(lang="en", pattern_type="keyword_instruction_manipulation")
def _keyword_instruction_manipulation():
    return [
        r"\b(jailbreak|bypass|circumvent|execute)\b",
    ]


@i18n_pattern(lang="en", pattern_type="keyword_suspicious_keywords")
def _suspicious_keywords():
    return [
        r"(?<!\w)\.env(?:ironment)?(?:\s+file)?(?!\w)|(?<!\w)(?:env|environment)\s+file(?!\w)",
        r"\bignores?\b",
        r"\binstructions?\b",
        r"\bsystem\s*prompts?\b",
        r"\boverrides?\b",
        r"\bexecutes?\b",
        r"\badmins?\b",
        r"\bjailbreaks?\b",
        r"\bpretends?\b",
        r"\bforgets?\b",
        r"\bdisregards?\b",
        r"\bbypasse?s?\b",
        r"\bsudo\b",
        r"\bdeveloper\s*mode\b",
    ]


@i18n_pattern(lang="en", pattern_type="defensive_context")
def _defensive_context():
    return [
        r"\b(?:never|cannot)\b",
        r"\b(?:don|won)['\u2019]t\b",
        r"\b(?:do|must|should|shall|will)\s+not\b",
        r"\b(?:refuse|reject|decline|avoid|prevent|prohibit)\b",
        r"\b(?:check|watch|look)\s+for\b",
        r"\b(?:beware|risky)\b",
        r"\buse\s+of\b",
        r"\bignore\s+attempts?\b",
    ]
