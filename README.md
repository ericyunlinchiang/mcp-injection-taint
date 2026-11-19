# MCP Injection Taint Rules (Semgrep)

Static-analysis Semgrep rules that detect **injection-direction taint** in an MCP
server's Python source: a tool handler's untrusted input reaching a dangerous
sink — command injection, path traversal, and SSRF.

- `injection-taint-py.yml` — the rules (mode: taint).
- `MAPPING.md` — mapping to the SAFE-MCP (SAF) technique catalog (SAF-T1101,
  SAF-T1105; SSRF raised as a catalog gap).

Run: `semgrep --config injection-taint-py.yml <path-to-mcp-server-source>`

Scope and known limits are documented in the rule file's header and in MAPPING.md
(intraprocedural; `@*.tool` / `@*.call_tool` sources; Python only).

License: Apache-2.0.
