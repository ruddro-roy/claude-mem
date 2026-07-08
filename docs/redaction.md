# Capture-Time Secret Redaction

Claude-Mem records tool use, observer output, and session summaries so they can be searched and injected back into future sessions. That data can accidentally include API keys, tokens, or other secrets from tool output. Capture-time redaction masks secret-shaped content before it is stored, sent to LLM providers, or injected into context.

## What Claude-Mem Stores and Where Data Flows

Claude-Mem persists structured memory in SQLite (`claude-mem.db` under your data directory). Observations and session summaries are the primary text stores:

- **observations**: title, subtitle, narrative, facts, concepts, files_read, files_modified, and related metadata
- **session_summaries**: request, investigated, learned, completed, next_steps, notes
- **pending_messages**: queued tool payloads (tool_input, tool_response) before the observer runs

Data flows through these stages:

1. **Hooks / CLI** capture tool use and POST to the worker (`/api/sessions/observations`).
2. **SQLite** holds the canonical memory store. Search, timeline context, and the viewer read from here.
3. **Chroma** (optional) receives embeddings synced from SQLite for semantic search. Vector text is derived from the same observation and summary fields.
4. **LLM providers** (Claude, Gemini, OpenRouter, or server-side generation) receive observer prompts built from queued tool payloads and return XML observations that are persisted.

Redaction runs on the worker side at each boundary where free-form text crosses a trust boundary: capture, prompt build, persist, and context injection.

## How Redaction Works

Redaction is implemented in `src/shared/content-redaction.ts`. Secret-shaped substrings are replaced with typed tokens such as `[REDACTED:api_key]` or `[REDACTED:email]`. Telemetry callers collapse typed tokens to plain `[REDACTED]` for backward compatibility.

### Capture (ingest)

When `ingestObservation` receives a tool payload, it JSON-serializes `toolInput` and `toolResponse`, strips memory tags, then runs `applyRedaction` before enqueueing the message. Secrets in raw tool output never enter the pending queue in cleartext.

### Prompt build

`buildObservationPrompt` redacts tool input and output fields (after JSON parse and before truncation) before assembling the observer prompt. This is defense in depth: even if a caller bypassed ingest redaction, the LLM provider still does not receive raw keys in the prompt.

### Persist

`ResponseProcessor` calls `redactObservationFields` on parsed observer XML before `storeObservations` writes to SQLite. Generated titles, narratives, facts, and related fields are masked at write time.

Server-side generation (`processGeneratedResponse`) applies the same redaction before Postgres or compat storage writes.

### Context injection

`ContextBuilder` runs `applyRedaction` on the assembled SessionStart / UserPromptSubmit context string before hooks return it to the IDE. Injected timeline text and summary fields do not leak stored secrets back into the active session.

## Settings

`CLAUDE_MEM_REDACTION` controls redaction behavior. Set it in `settings.json` or via environment variable.

| Value | Behavior |
|-------|----------|
| `off` | No secret masking. Use only when you accept the risk of secrets persisting in SQLite and Chroma. |
| `standard` | Default. Masks emails, JWTs, provider API keys (`sk-`, `phc_`, `github_pat_`, and similar), AWS key IDs, Bearer tokens, PEM private keys, connection strings, UUIDs, long hex blobs, high-entropy env assignments, and IPv4 addresses. Does not apply the bare high-entropy token heuristic. |
| `strict` | Everything in `standard`, plus bare high-entropy tokens (32+ alphanumeric characters with at least one digit). |

Invalid values fall back to `standard`.

Example `settings.json` fragment:

```json
{
  "CLAUDE_MEM_REDACTION": "standard"
}
```

## Retroactive Cleanup: doctor --scan-secrets and --fix

Content redacted at capture time does not rewrite rows written before the feature was enabled. Use the doctor subcommands to audit and fix existing data.

```bash
npx claude-mem doctor --scan-secrets
```

Read-only scan of `observations` and `session_summaries` in SQLite. Reports per-project hit counts, affected fields, secret kinds, and sample row IDs. Exits `0` when no hits are found, `1` when secret-shaped content remains.

```bash
npx claude-mem doctor --scan-secrets --fix
```

Rewrites affected rows with `redactContent` (using your current `CLAUDE_MEM_REDACTION` setting), then re-syncs updated documents to Chroma when vector search is enabled. Exits `0` after a successful fix pass.

`doctor --fix` mutates SQLite and triggers Chroma re-indexing. Run `--scan-secrets` first to review scope.

## False Positives and Allowlists

Redaction uses shape-based heuristics, not secret validation. Some benign strings can match patterns; others are explicitly preserved.

**Git commit SHAs (allowlisted).** Lowercase hex strings (7 to 40 characters) in git context are preserved. Context includes prefixes such as `commit`, `sha`, `hash`, or `ref` (with optional `:` or `=`). Example: `commit abc1234567890abcdef1234567890abcdef1234` is not masked. The same hex string outside git context (for example a bare digest field) may still be redacted as `[REDACTED:hex]`.

**Version numbers.** Three-part dotted versions (for example `13.6.2`) are not treated as IPv4 addresses.

**Low-entropy environment values.** Assignments like `NODE_ENV=production` are left unchanged. High-entropy values (mixed case, digits, and symbols) in `KEY=value` form are masked.

**Typed tokens are idempotent.** Rows already containing `[REDACTED:...]` tokens are not reported as hits by `--scan-secrets`.

If redaction hides content you need for debugging, set `CLAUDE_MEM_REDACTION=off` temporarily, or use `<private>...</private>` tags on specific user prompts to suppress observation generation for sensitive turns.

## Related Documentation

- [security.md](./security.md) for API key auth, storage boundaries, and telemetry scrubbing
- [architecture-overview.md](./architecture-overview.md) for the end-to-end data flow