from ..registries.i18n import i18n_pattern


@i18n_pattern(lang="es", pattern_type="instruction_override")
def _instruction_override():
    return [
        r"ignora\s+(todas?\s+)?(las\s+)?instrucciones?\s+(anteriores?|previas?)",
        r"olvida\s+(todas?\s+)?(tus\s+)?instrucciones?",
        r"no\s+(hagas\s+caso|sigas)\s+(de\s+)?(las\s+)?instrucciones?\s+(anteriores?|previas?)",
        r"nuevas?\s+instrucciones?\s*:",
        r"a\s+partir\s+de\s+ahora\s*,?\s+(eres|debes|vas\s+a)",
        r"eres\s+ahora\s+(un|una)\s+",
        r"cambia\s+a\s+modo\s+(desarrollador|depuraci[oó]n|administrador)",
        r"modo\s+desarrollador\s+(activado|habilitado)",
        r"anula\s+(todas?\s+)?(las\s+)?instrucciones?\s+(anteriores?|del\s+sistema)",
    ]


@i18n_pattern(lang="es", pattern_type="exfiltration")
def _exfiltration():
    return [
        r"(muestra|revela|ense[ñn]a|imprime|repite|dime|mu[eé]strame|rev[eé]lame|ens[eé][ñn]ame)\s+(?:me\s+)?(tu\s+)?(prompt|instrucciones?|reglas?|config)(\s+(del\s+)?sistema)?",
        r"cu[aá]les\s+(son|eran)\s+tus\s+instrucciones?\s*(originales?)?",
        r"(env[ií]a|manda|publica)\s+.{0,40}(https?://|ftp://)",
        r"(redirige|canaliza|reenv[ií]a)\s+.{0,30}(a|hacia)\s+.{0,30}(url|endpoint|servidor|webhook)",
    ]


@i18n_pattern(lang="es", pattern_type="role_hijack")
def _role_hijack():
    return [
        r"eres\s+(DAN|STAN|un\s+hacker|malvado|sin\s+restricciones)",
        r"act[uú]a\s+como\s+(si\s+fueras\s+)?(un\s+)?(hacker|atacante|malvado|sin\s+filtros?)",
        r"finge\s+(que\s+eres|ser)\s+(un\s+)?(hacker|sin\s+restricciones|malvado)",
        r"modo\s+(jailbreak|sin\s+censura|sin\s+restricciones)",
        r"haz\s+cualquier\s+cosa\s+ahora",
    ]


@i18n_pattern(lang="es", pattern_type="context_manipulation")
def _context_manipulation():
    return [
        r"\[INST\]",
        r"\[/INST\]",
        r"<\s*\|?\s*sistema\s*\|?\s*>",
        r"<\s*\|?\s*usuario\s*\|?\s*>",
        r"<\s*\|?\s*asistente\s*\|?\s*>",
        r"<<\s*SYS\s*>>",
        r"###\s*(Sistema|Usuario|Asistente)\s*:",
        r"INICIO\s+(DEL\s+)?PROMPT\s+(DEL\s+)?SISTEMA",
    ]


@i18n_pattern(lang="es", pattern_type="privilege_escalation")
def _privilege_escalation():
    return [
        r"modo\s+(?:sudo|root|admin(?:istrador)?)",
        r"(?:desactiva|desabilita|anula)\s+(?:todos?\s+)?(?:los\s+)?(?:filtros?|restricciones?|medidas?\s+de)\s+(?:seguridad|contenido)",
        r"(?:dame|conc[eé]deme|otorga)\s+(?:acceso|permisos?|privilegios?)\s+(?:de\s+)?(?:admin|root|superusuario|elevados?)",
        r"(?:elimina|quita|salta)\s+(?:todas?\s+)?(?:las\s+)?(?:restricciones?|limitaciones?|filtros?)",
    ]


@i18n_pattern(lang="es", pattern_type="fake_authority")
def _fake_authority():
    return [
        r"(?:soy|esto\s+es)\s+(?:el|la)\s+(?:desarrollador|creador|admin(?:istrador)?|due[ñn]o|autor)\s+(?:de|del|para)\b",
        r"(?:OpenAI|Anthropic|Google|Microsoft|Meta)\s+(?:interno|oficial|autorizado)",
        r"(?:autorizado|aprobado|instruido)\s+por\s+(?:el|la|los)\s+(?:desarrollador|equipo|empresa|admin)",
        r"(?:modo|sesi[oó]n|comando)\s+(?:oficial|interno)\s+de\s+(?:depuraci[oó]n|pruebas?|mantenimiento|diagn[oó]stico)",
        r"(?:tengo|con)\s+(?:acceso|autorizaci[oó]n|permiso)\s+(?:especial|de\s+admin|de\s+desarrollador|elevad)",
    ]


@i18n_pattern(lang="es", pattern_type="task_deflection")
def _task_deflection():
    return [
        r"(?:empieza|comienza|inicia)\s+(?:una\s+)?(?:nueva|otra)\s+(?:conversaci[oó]n|sesi[oó]n|tarea|charla)",
        r"(?:reinicia|borra|limpia)\s+(?:tu\s+)?(?:contexto|memoria|historial|conversaci[oó]n|instrucciones?)",
        r"(?:las\s+)?(?:instrucciones?|conversaci[oó]n|contexto)\s+(?:anteriores?|previas?)\s+(?:ya\s+)?(?:no\s+aplican?|no\s+valen?)",
        r"(?:vamos\s+a|deber[ií]amos)\s+(?:empezar\s+de\s+nuevo|reiniciar|comenzar\s+de\s+cero)",
        r"(?:esta\s+es\s+una|comenzando)\s+(?:nueva|diferente|distinta)\s+(?:sesi[oó]n|contexto|conversaci[oó]n)",
    ]


@i18n_pattern(lang="es", pattern_type="keyword_instruction_override")
def _keyword_instruction_override():
    return [
        r"\b(ignora|olvida|anula|desatiende|salta|elude|descarta|omite)\s+(todos?|todas?|los|las|mis|tus|cualquier|anteriores?|previas?)\b",
        r"\bno\s+(sigas|hagas\s+caso)\b",
    ]


@i18n_pattern(lang="es", pattern_type="keyword_system_prompt")
def _keyword_system_prompt():
    return [
        r"\b(sistema|original|oculto)\s*(prompt|instrucci[oó]n(?:es)?|directivas?|reglas?|gu[ií]as?|comandos?|restricciones?|pol[ií]ticas?|protocolos?|mensaje|configuraci[oó]n)\b",
        r"\b(prompt|instrucci[oó]n(?:es)?|configuraci[oó]n|directivas?|reglas?)\s+(del\s+sistema|ocultas?|original(?:es)?|internas?|secretas?)\b",
    ]


@i18n_pattern(lang="es", pattern_type="keyword_exfiltration")
def _keyword_exfiltration():
    return [
        r"\b(muestra|revela|ense[ñn]a|imprime|exp[oó]n|divulga|comparte|dime|repite|extrae|filtra)\s+(el|la|los|las)?\s*(sistema|original|oculto|interno|secreto)\b",
        r"\b(muestra|revela|ense[ñn]a|imprime|exp[oó]n|divulga|comparte|dime|repite|extrae|filtra)\s+.{0,40}(del\s+sistema|ocultas?|internas?|secretas?)\b",
    ]


@i18n_pattern(lang="es", pattern_type="keyword_instruction_manipulation")
def _keyword_instruction_manipulation():
    return [
        r"\b(jailbreak|bypass|evadir|eludir|ejecuta)\b",
    ]


@i18n_pattern(lang="es", pattern_type="keyword_suspicious_keywords")
def _suspicious_keywords():
    return [
        r"(?<!\w)(?:archivo|fichero)\s+\.?(?:env|environment)(?!\w)",
        r"\bignora\b",
        r"\binstrucciones?\b",
        r"\bprompts?\s*del\s*sistema\b",
        r"\banular\b",
        r"\bejecutar\b",
        r"\badministradora?\b",
        r"\bjailbreaks?\b",
        r"\bfingir\b|\bsimular\b",
        r"\bolvidar\b",
        r"\bdescartar\b",
        r"\beludir\b",
        r"\bsudo\b",
        r"\bmodo\s*(?:de\s*)?desarrollador\b",
    ]


@i18n_pattern(lang="es", pattern_type="defensive_context")
def _defensive_context():
    return [
        r"\b(?:nunca|jam[aá]s)\b",
        r"\bno\s+(?:debes?|puede[sn]?)\b",
        r"\b(?:rechaz|evit|prohib|prev[ei]n|declin)\w*\b",
        r"\b(?:cuidado\s+con|riesgoso|arriesgado)\b",
        r"\b(?:comprobar|vigilar|buscar|detectar)\b",
        r"\buso\s+de\b",
        r"\bintentos?\s+de\b",
    ]
