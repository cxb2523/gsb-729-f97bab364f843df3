from ..registries.i18n import i18n_pattern


@i18n_pattern(lang="gl", pattern_type="instruction_override")
def _instruction_override():
    return [
        r"ignora\s+(todas?\s+)?(as\s+)?instruci[oó]ns?\s+(anteriores?|previas?)",
        r"esquece\s+(todas?\s+)?(as\s+t[uú]as\s+)?instruci[oó]ns?",
        r"non\s+(fagas\s+caso|sigas)\s+(das?\s+)?instruci[oó]ns?\s+(anteriores?|previas?)",
        r"novas?\s+instruci[oó]ns?\s*:",
        r"a\s+partir\s+de\s+agora\s*,?\s+(es|debes|vas)",
        r"es\s+agora\s+(un|unha)\s+",
        r"cambia\s+a\s+modo\s+(desenvolvedor|depuraci[oó]n|administrador)",
        r"modo\s+desenvolvedor\s+(activado|habilitado)",
        r"anula\s+(todas?\s+)?(as\s+)?instruci[oó]ns?\s+(anteriores?|do\s+sistema)",
    ]


@i18n_pattern(lang="gl", pattern_type="exfiltration")
def _exfiltration():
    return [
        r"(amosa|revela|ensina|imprime|repite|dime|am[oó]same|rev[eé]lame|ens[ií]name)\s+(?:me\s+)?(o\s+teu\s+)?(prompt|instruci[oó]ns?|regras?|config)(\s+(do\s+)?sistema)?",
        r"cales\s+(son|eran)\s+as\s+t[uú]as\s+instruci[oó]ns?\s*(orixinais?)?",
        r"(env[ií]a|manda|publica)\s+.{0,40}(https?://|ftp://)",
        r"(redirixe|canaliza|reenv[ií]a)\s+.{0,30}(a|cara)\s+.{0,30}(url|endpoint|servidor|webhook)",
    ]


@i18n_pattern(lang="gl", pattern_type="role_hijack")
def _role_hijack():
    return [
        r"es\s+(DAN|STAN|un\s+hacker|malvado|sen\s+restrici[oó]ns?)",
        r"act[uú]a\s+como\s+(se\s+foses\s+)?(un\s+)?(hacker|atacante|malvado|sen\s+filtros?)",
        r"finxe\s+(que\s+es|ser)\s+(un\s+)?(hacker|sen\s+restrici[oó]ns?|malvado)",
        r"modo\s+(jailbreak|sen\s+censura|sen\s+restrici[oó]ns?)",
        r"fai\s+calquera\s+cousa\s+agora",
    ]


@i18n_pattern(lang="gl", pattern_type="context_manipulation")
def _context_manipulation():
    return [
        r"\[INST\]",
        r"\[/INST\]",
        r"<\s*\|?\s*sistema\s*\|?\s*>",
        r"<\s*\|?\s*usuario\s*\|?\s*>",
        r"<\s*\|?\s*asistente\s*\|?\s*>",
        r"<<\s*SYS\s*>>",
        r"###\s*(Sistema|Usuario|Asistente)\s*:",
        r"INICIO\s+(DO\s+)?PROMPT\s+(DO\s+)?SISTEMA",
    ]


@i18n_pattern(lang="gl", pattern_type="privilege_escalation")
def _privilege_escalation():
    return [
        r"modo\s+(?:sudo|root|admin(?:istrador)?)",
        r"(?:desactiva|desabilita|anula)\s+(?:todos?\s+)?(?:os\s+)?(?:filtros?|restrici[oó]ns?|medidas?\s+de)\s+(?:seguridade|contido)",
        r"(?:dame|conc[eé]deme|outorga)\s+(?:acceso|permisos?|privilexios?)\s+(?:de\s+)?(?:admin|root|superusuario|elevados?)",
        r"(?:elimina|quita|salta)\s+(?:todas?\s+)?(?:as\s+)?(?:restrici[oó]ns?|limitaci[oó]ns?|filtros?)",
    ]


@i18n_pattern(lang="gl", pattern_type="fake_authority")
def _fake_authority():
    return [
        r"(?:son|isto\s+[eé])\s+(?:o|a)\s+(?:desenvolvedor|creador|admin(?:istrador)?|dono|autor)\s+(?:de|do|para)\b",
        r"(?:OpenAI|Anthropic|Google|Microsoft|Meta)\s+(?:interno|oficial|autorizado)",
        r"(?:autorizado|aprobado|instru[ií]do)\s+por\s+(?:o|a|os)\s+(?:desenvolvedor|equipo|empresa|admin)",
        r"(?:modo|sesi[oó]n|comando)\s+(?:oficial|interno)\s+de\s+(?:depuraci[oó]n|probas?|mantemento|diagn[oó]stico)",
        r"(?:te[ñn]o|con)\s+(?:acceso|autorizaci[oó]n|permiso)\s+(?:especial|de\s+admin|de\s+desenvolvedor|elevad)",
    ]


@i18n_pattern(lang="gl", pattern_type="task_deflection")
def _task_deflection():
    return [
        r"(?:empeza|comeza|inicia)\s+(?:unha\s+)?(?:nova|outra)\s+(?:conversa|sesi[oó]n|tarefa)",
        r"(?:reinicia|borra|limpa)\s+(?:o\s+teu\s+)?(?:contexto|memoria|historial|conversa|instruci[oó]ns?)",
        r"(?:as\s+)?(?:instruci[oó]ns?|conversa|contexto)\s+(?:anteriores?|previas?)\s+(?:xa\s+)?(?:non\s+aplican?|non\s+valen?)",
        r"(?:imos|deber[ií]amos)\s+(?:empezar\s+de\s+novo|reiniciar|comezar\s+de\s+cero)",
        r"(?:esta\s+[eé]\s+unha|comezando)\s+(?:nova|diferente|distinta)\s+(?:sesi[oó]n|contexto|conversa)",
    ]


@i18n_pattern(lang="gl", pattern_type="keyword_instruction_override")
def _keyword_instruction_override():
    return [
        r"\b(ignora|esquece|anula|desatende|salta|elude|descarta|omite)\s+(todos?|todas?|os|as|calquera|anteriores?|previas?)\b",
        r"\bnon\s+(sigas|fagas\s+caso)\b",
    ]


@i18n_pattern(lang="gl", pattern_type="keyword_system_prompt")
def _keyword_system_prompt():
    return [
        r"\b(sistema|orixinal|oculto)\s*(prompt|instruci[oó]n(?:s)?|directivas?|regras?|gu[ií]as?|comandos?|restrici[oó]ns?|pol[ií]ticas?|protocolos?|mensaxe|configuraci[oó]n)\b",
        r"\b(prompt|instruci[oó]n(?:s)?|configuraci[oó]n|directivas?|regras?)\s+(do\s+sistema|ocultas?|orixina(?:l|is)|internas?|secretas?)\b",
    ]


@i18n_pattern(lang="gl", pattern_type="keyword_exfiltration")
def _keyword_exfiltration():
    return [
        r"\b(amosa|revela|ensina|imprime|exp[oó]n|divulga|comparte|dime|repite|extrae|filtra)\s+(o|a|os|as)?\s*(sistema|orixinal|oculto|interno|secreto)\b",
        r"\b(amosa|revela|ensina|imprime|exp[oó]n|divulga|comparte|dime|repite|extrae|filtra)\s+.{0,40}(do\s+sistema|ocultas?|internas?|secretas?)\b",
    ]


@i18n_pattern(lang="gl", pattern_type="keyword_instruction_manipulation")
def _keyword_instruction_manipulation():
    return [
        r"\b(jailbreak|bypass|evadir|eludir|executa)\b",
    ]


@i18n_pattern(lang="gl", pattern_type="keyword_suspicious_keywords")
def _suspicious_keywords():
    return [
        r"(?<!\w)(?:ficheiro|arquivo)\s+\.?(?:env|environment)(?!\w)",
        r"\bignora(?:r)?\b",
        r"\binstruci[oó]ns?\b",
        r"\bprompts?\s*do\s*sistema\b",
        r"\banular\b",
        r"\bexecutar\b",
        r"\badministradora?\b",
        r"\bjailbreaks?\b",
        r"\bfinxir\b|\bsimular\b",
        r"\besquecer\b",
        r"\bdescartar\b",
        r"\beludir\b",
        r"\bsudo\b",
        r"\bmodo\s*(?:de\s*)?desenvolvedor\b",
    ]


@i18n_pattern(lang="gl", pattern_type="defensive_context")
def _defensive_context():
    return [
        r"\b(?:nunca|xamais)\b",
        r"\bnon\s+(?:debes?|podes?)\b",
        r"\b(?:rexeit|evit|prohib|prev[eé]n|declin)\w*\b",
        r"\b(?:coidado\s+con|arriscado)\b",
        r"\b(?:comprobar|vixiar|buscar|detectar)\b",
        r"\buso\s+de\b",
        r"\bintentos?\s+de\b",
    ]
