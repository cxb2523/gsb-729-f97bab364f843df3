# Custom loader

> **Example only:** `OpenCodeLoader` illustrates how to implement a CerbIA
> loader. It is not prepared for use in a production environment.

This scenario keeps a project-local custom loader alongside its configuration
and fixture tree. `OpenCodeLoader` implements `load() -> list[Entry]` and reads
these supported project-local paths:

- `opencode.json` and `opencode.jsonc` at the project root;
- `.opencode/skills/**/SKILL.md`;
- `.opencode/agents/**/*.md`; and
- `.opencode/commands/**/*.md`.

From this directory, run:

```bash
PYTHONPATH=. uv run cerbia validate opencode.cerbia.yaml
PYTHONPATH=. uv run cerbia scan --config opencode.cerbia.yaml
```

Validation exits `0`. The configured scan exits `1` because the fixture command
contains `CERBIA_DEMO_BLOCK_MARKER`. Its `KeywordScanner` uses
`redact: true`, which redacts matching snippets in the finding rationale only;
it does not redact entry text or general CLI/JSON output.

The fixture scanner loads no built-in language patterns and checks only the
explicit demo marker. This keeps valid OpenCode configuration fields such as
`instructions` from becoming unrelated sample findings.

The complete gate also checks invisible text, prompt injection, known secret
formats, and URLs. Its allowlist permits only the OpenCode schema URL used in
the project configuration. Entropy-based secret detection is disabled to keep
the documentation-focused fixture deterministic.

The `scan.md` fixture intentionally produces Invisible Text, Keyword, Prompt
Injection, URL Allowlist, and Malicious URL findings. It contains four literal
U+200B zero-width spaces, exceeding the InvisibleTextScanner default threshold
of three. Its URL uses the non-routable TEST-NET address `192.0.2.1`; scanners
inspect fixture text locally and do not make network requests.

The command puts this scenario directory on `PYTHONPATH`, so the YAML imports
its local `opencode_loader.OpenCodeLoader` directly. It is not a CerbIA package
export. See [custom loaders](https://inditextech.github.io/cerbia/latest/main/components/loaders/) for the general
loader contract.

The loader scans only the project config and selected `.opencode` agent, command,
and skill files as text. It does not resolve `INSTRUCTIONS.md`, merge OpenCode
configuration, or invoke OpenCode, agents, commands, skills, or MCP servers.
