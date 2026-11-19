# SAFE-MCP (SAF) technique mapping — evidence

These Semgrep rules (`injection-taint-py.yml`) detect **injection-direction taint**
in an MCP server's **Python source code**: an MCP tool handler's untrusted input
flowing into a dangerous sink. Detection is **static** (source is examined, not
executed), which is the SAF registry's currently unrepresented native modality
(`static`: 0 native mappings across 78 techniques).

## Mappings

| rule | SAF-T | relationship | modality | why |
|---|---|---|---|---|
| `mcp-tool-input-command-injection` | **SAF-T1101** Command Injection | `partial` | `static` | tainted tool-handler input → `os.system` / `os.popen` / `eval` / `exec` / `subprocess(shell=True)` |
| `mcp-tool-input-path-traversal` | **SAF-T1105** Path Traversal via File Tool | `partial` | `static` | tainted tool-handler input → `open` / `Path.read_text|write_text|open` / `os.open` / `os.remove` / `os.rename` |

**`partial`, not `direct`**: these rules represent a bounded subset of each
technique — one language (Python), intraprocedural taint, and tool-entry sources
anchored on `@*.tool` / `@*.call_tool` decorators. They do not observe runtime
execution (the existing native rules' modality) and do not cover every
implementation.

## Evidence
- Self-test: 10 true positives / 0 false positives across positive and negative
  fixtures (real Semgrep run).
- Independent cross-check: the same rules were diffed, site-by-site, against an
  independent AST-based taint implementation on a 7-repo public MCP-server census.
  On the MCP-tool surface, every site within the rules' documented scope was
  caught, with zero false positives; misses were confined to the documented
  recall limits below.

## Known limits (honest scope)
- **Intraprocedural**: taint that flows through a helper function is not followed.
- **Source scope**: sources are `@*.tool` / `@*.call_tool` handler parameters;
  undecorated / low-level (`types.Tool` + central `call_tool` dispatch, imperative
  `add_tool`, class-based `Tool(handler=...)`) registration is not covered.
- **Python only.**
- **Sink lists are representative, not exhaustive**: command sinks are
  os.system / os.popen / eval / exec / subprocess(shell=True); path sinks are
  open / pathlib read-write-open / os.open / os.remove / os.rename. A sink
  outside these is not matched.
- An independent interprocedural cross-check found additional sites that these
  intraprocedural rules do not reach; those misses are exactly the
  intraprocedural limit above, not in-scope false negatives.

## SSRF — a catalog gap (not mapped here)
The ruleset also detects SSRF (tainted tool input → a named HTTP client URL), but
the SAF catalog has **no dedicated SSRF technique**. Rather than force a mismatch,
this is raised as a catalog gap for maintainers (propose a technique, or map
partially under an unsafe-tool-implementation technique with explicit evidence).
