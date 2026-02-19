# Audit Log Schema (v2)

ShieldFlow emits one JSON object per line (JSONL) to the configured audit log
path (or stderr). Every record includes `schema_version` for forward
compatibility.

## Common Fields

| Field            | Type   | Description                                         |
|------------------|--------|-----------------------------------------------------|
| `schema_version` | string | Always `"2"` for this schema                        |
| `event`          | string | Event type (see below)                              |
| `timestamp`      | string | UTC ISO-8601 timestamp                              |
| `request_id`     | string | UUID correlating all events for one proxy request   |

## Event Types

### `request`

Emitted when a request arrives at the proxy, before upstream forwarding.

```json
{
  "schema_version": "2",
  "event": "request",
  "timestamp": "2026-01-01T00:00:00+00:00",
  "request_id": "3f2a1b4c-...",
  "model": "gpt-4",
  "message_count": 3,
  "trust_summary": {"USER": 1, "SYSTEM": 1, "NONE": 1}
}
```

### `blocked`

Emitted when a tool call is blocked. Includes full decision provenance.

```json
{
  "schema_version": "2",
  "event": "blocked",
  "timestamp": "2026-01-01T00:00:01+00:00",
  "request_id": "3f2a1b4c-...",
  "tool_name": "exec",
  "decision": "BLOCK",
  "reason": "Action 'exec' matches an instruction pattern found in untrusted content (source: email).",
  "trigger_source": "email",
  "trigger_trust": "NONE",
  "matched_patterns": ["pattern:ignore_previous_instructions"],
  "normalisation_flags": ["base64_injection"],
  "data_classification": null
}
```

**Provenance fields:**

| Field                  | Type            | Description                                              |
|------------------------|-----------------|----------------------------------------------------------|
| `decision`             | string          | Always `"BLOCK"`                                         |
| `trigger_source`       | string \| null  | Source identifier (e.g. `"email"`, `"user_chat"`)        |
| `trigger_trust`        | string          | Trust level of triggering source (e.g. `"NONE"`)         |
| `matched_patterns`     | list of strings | Pattern keys from `NAMED_INJECTION_PATTERNS`, prefixed `"pattern:"`, or sanitiser flags prefixed `"normalisation:"` |
| `normalisation_flags`  | list of strings | Raw sanitiser flags (e.g. `"base64_injection"`, `"homoglyphs"`) |
| `data_classification`  | string \| null  | Data classification when applicable                      |

**`matched_patterns` prefix convention:**

- `pattern:<name>` — a named regex in `NAMED_INJECTION_PATTERNS` matched
- `normalisation:<flag>` — sanitiser detected an encoded payload (e.g. `normalisation:base64_injection`)

### `allowed`

Emitted when a tool call passes all checks.

```json
{
  "schema_version": "2",
  "event": "allowed",
  "timestamp": "2026-01-01T00:00:01+00:00",
  "request_id": "3f2a1b4c-...",
  "tool_name": "email.send",
  "decision": "ALLOW",
  "trigger_source": "user_chat",
  "trigger_trust": "USER",
  "data_classification": null
}
```

### `confirmation_required`

Emitted when a tool call is passed through but flagged as requiring operator
confirmation (e.g. sensitive data access triggered by a lower-trust source).

```json
{
  "schema_version": "2",
  "event": "confirmation_required",
  "timestamp": "2026-01-01T00:00:01+00:00",
  "request_id": "3f2a1b4c-...",
  "tool_name": "file.delete",
  "decision": "CONFIRM",
  "reason": "Action targets path in sensitive directory.",
  "trigger_source": "user_chat",
  "trigger_trust": "USER",
  "data_classification": "sensitive"
}
```

### `response`

Emitted after all tool calls in the upstream response have been validated.

```json
{
  "schema_version": "2",
  "event": "response",
  "timestamp": "2026-01-01T00:00:02+00:00",
  "request_id": "3f2a1b4c-...",
  "blocked_count": 1,
  "allowed_count": 2,
  "model": "gpt-4"
}
```

### `auth_failure`

Emitted when authentication fails (missing or invalid Bearer token).

```json
{
  "schema_version": "2",
  "event": "auth_failure",
  "timestamp": "2026-01-01T00:00:00+00:00",
  "request_id": "3f2a1b4c-...",
  "reason": "Invalid Bearer token"
}
```

## Querying the Log

```bash
# All blocked events
grep '"event": "blocked"' audit.jsonl | jq .

# Blocked by base64 injection
grep '"event": "blocked"' audit.jsonl \
  | jq 'select(.normalisation_flags | contains(["base64_injection"]))'

# All requests with NONE-trust content
grep '"event": "request"' audit.jsonl \
  | jq 'select(.trust_summary.NONE > 0)'

# Decision counts for a specific request
grep '"request_id": "3f2a1b4c"' audit.jsonl | jq .event
```
