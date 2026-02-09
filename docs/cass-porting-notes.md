# CASS Porting Notes

casr adapts connector and model logic from [coding_agent_session_search](https://github.com/Dicklesworthstone/coding_agent_session_search) (CASS). This document tracks what was ported, what changed, and why casr carries no runtime dependency on CASS.

## No-Runtime-Dependency Architecture

casr copies and adapts relevant CASS source code ("vendoring") rather than depending on the CASS crate at build time. Rationale:

1. **CASS is a search/indexing tool; casr is a conversion CLI.** Different optimization targets (throughput vs latency), different dependency trees.
2. **casr adds writers.** CASS only reads sessions; casr reads *and writes*. The writer code is entirely new.
3. **Decoupled release cycles.** CASS may make breaking changes to its model types that casr shouldn't be forced to absorb immediately.
4. **Smaller binary.** casr ships as a single static binary with no transitive CASS deps (SQLite, tantivy, etc.).

## Source Files Adapted

| CASS source | casr destination | What changed |
|-------------|-----------------|--------------|
| `src/model/types.rs` | `src/model.rs` | Subset of fields; `Agent` → `Assistant` role; dropped `approx_tokens`, `source_id`, `Snippet` |
| `src/connectors/claude_code.rs` | `src/providers/claude_code.rs` | Added writer; unified role/content cascades |
| `src/connectors/codex.rs` | `src/providers/codex.rs` | Added writer; retroactive `token_count` attachment |
| `src/connectors/gemini.rs` | `src/providers/gemini.rs` | Added writer; 3-strategy workspace extraction |
| `src/connectors/mod.rs` | `src/model.rs` (helpers) | `flatten_content`, `parse_timestamp`, `reindex_messages` ported as shared helpers |
| `src/sources/probe.rs` | `src/discovery.rs` | Adapted provider detection probes with env var overrides |

## Behavioral Deltas

- **Role naming:** CASS uses `Agent`; casr uses `Assistant`. `normalize_role()` maps `"agent"` → `Assistant`.
- **Timestamp heuristic:** Same 100-billion threshold for seconds-vs-millis detection.
- **Workspace extraction (Gemini):** Same 3-strategy cascade; casr adds writer that reproduces the directory hash.
- **External ID (Claude Code):** Same filename-based derivation (not `sessionId` field).

## License

CASS is MIT-licensed. Adapted code retains MIT license compliance per the terms of the original license.
