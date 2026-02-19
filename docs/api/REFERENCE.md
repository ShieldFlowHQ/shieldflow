# ShieldFlow API Reference

**Version:** 0.1.0  
**License:** Apache 2.0

This reference documents every public class, method, and constant in the ShieldFlow Python SDK.

---

## Table of Contents

- [Quick Start](#quick-start)
- [ShieldFlow](#shieldflow-class)
- [SecureSession](#securesession)
- [SecureContext](#securecontext)
- [ContextBlock](#contextblock)
- [TrustLevel](#trustlevel)
- [TrustTag](#trusttag)
- [Trust Constructors](#trust-constructors)
- [SessionSigner](#sessionsigner)
- [SignedMessage](#signedmessage)
- [VerificationResult](#verificationresult)
- [PolicyEngine](#policyengine)
- [ActionPolicy](#actionpolicy)
- [ElevationRule](#elevationrule)
- [DataClass](#dataclass)
- [PolicyDecision](#policydecision)
- [ActionValidator](#actionvalidator)
- [ToolCall](#toolcall)
- [ValidationResult](#validationresult)
- [Default Policies](#default-policies)
- [Exceptions](#exceptions)

---

## Quick Start

```python
from shieldflow import ShieldFlow, TrustLevel

# Create instance (uses default policies)
sf = ShieldFlow()

# Create a session for a user interaction
session = sf.create_session()

# Add the user's instruction (automatically signed + tagged OWNER)
session.add_instruction("Summarise my emails and flag urgent ones")

# Add external data (tagged NONE — untrusted)
session.add_data(email_body, source="imap")

# Get OpenAI-compatible messages with trust enforcement
messages = session.to_messages()

# After LLM call, validate tool calls before executing
for raw_tool_call in llm_response.tool_calls:
    tc = ToolCall(id=raw_tool_call.id, name=raw_tool_call.function.name,
                  arguments=json.loads(raw_tool_call.function.arguments))
    result = session.validate_action(tc)
    if result.allowed:
        execute(tc)
    elif result.needs_confirmation:
        prompt_user(result.reason)
    else:
        log.warning(f"Blocked: {result.reason}")
```

---

## `ShieldFlow` class

`shieldflow.ShieldFlow`

The primary entry point. Manages a policy engine and creates sessions and contexts.

### Constructor

```python
ShieldFlow(
    config: str | Path | dict | None = None,
    policy: PolicyEngine | None = None,
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config` | `str \| Path \| dict \| None` | `None` | Path to a YAML config file, an inline config dict, or `None` to use defaults |
| `policy` | `PolicyEngine \| None` | `None` | Pre-built policy engine. Ignored if `config` is a file path. |

**Config file format (YAML):**

```yaml
actions:
  message.send:
    min_trust: user
    description: Send a message
  exec:
    min_trust: owner
    never_auto: true

elevation_rules:
  - source: email
    match:
      from: "boss@company.com"
    require_dkim: true
    elevate_to: user
    allowed_actions: [reply]

data_classification:
  - name: restricted
    patterns:
      - "password\\s*[:=]"
      - "api[_-]?key\\s*[:=]"
    external_share: block
```

**Raises:** `FileNotFoundError` if a config path is given but doesn't exist.

**Examples:**

```python
# Defaults
sf = ShieldFlow()

# From YAML file
sf = ShieldFlow(config="shieldflow.yaml")

# From dict
sf = ShieldFlow(config={
    "actions": {
        "exec": {"min_trust": "owner", "never_auto": True}
    }
})
```

### `ShieldFlow.create_session()`

```python
def create_session(
    signing_key: bytes | None = None,
    trust_level: TrustLevel = TrustLevel.OWNER,
) -> SecureSession
```

Create a new `SecureSession` with its own ephemeral signing key.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `signing_key` | `bytes \| None` | `None` | 32-byte pre-shared signing key. If `None`, a random key is generated. |
| `trust_level` | `TrustLevel` | `TrustLevel.OWNER` | Trust level to assign to instructions added in this session. |

**Returns:** `SecureSession`

**Example:**

```python
session = sf.create_session()

# With a pre-shared key (e.g., from environment)
import os
key = bytes.fromhex(os.environ["SHIELDFLOW_SESSION_KEY"])
session = sf.create_session(signing_key=key)

# For a session where the caller is USER-level, not OWNER
session = sf.create_session(trust_level=TrustLevel.USER)
```

### `ShieldFlow.create_context()`

```python
def create_context() -> SecureContext
```

Create a `SecureContext` without a full session (no signing key). Useful when you don't need HMAC signing and are relying solely on structural trust tagging and policy enforcement.

**Returns:** `SecureContext`

### `ShieldFlow.validate_action()`

```python
def validate_action(
    tool_call: ToolCall,
    context: SecureContext,
) -> ValidationResult
```

Validate a single tool call against the current context's trust state.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `tool_call` | `ToolCall` | The tool call to validate |
| `context` | `SecureContext` | The context that produced this tool call |

**Returns:** `ValidationResult`

### `ShieldFlow.validate_actions()`

```python
def validate_actions(
    tool_calls: list[ToolCall],
    context: SecureContext,
) -> list[ValidationResult]
```

Validate multiple tool calls. Returns results in the same order as input.

### `ShieldFlow.policy`

```python
@property
def policy(self) -> PolicyEngine
```

The underlying `PolicyEngine` instance.

---

## `SecureSession`

`shieldflow.core.session.SecureSession`

Ties together signing, context building, and validation for one user session. The typical interaction surface for per-request processing.

### Constructor

```python
SecureSession(
    signing_key: bytes | None = None,
    policy: PolicyEngine | None = None,
    trust_level: TrustLevel = TrustLevel.OWNER,
)
```

Prefer `ShieldFlow.create_session()` over constructing this directly.

### `SecureSession.add_instruction()`

```python
def add_instruction(content: str, **metadata) -> str
```

Add a verified instruction from the session owner. The instruction is signed with the session key and tagged with the session's trust level.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `content` | `str` | The instruction text |
| `**metadata` | `Any` | Arbitrary metadata attached to the context block |

**Returns:** `str` — block ID for provenance tracking.

**Example:**

```python
block_id = session.add_instruction("Summarise my emails")
# Block is tagged TrustLevel.OWNER, verified_by="hmac"
```

### `SecureSession.add_system()`

```python
def add_system(content: str, **metadata) -> str
```

Add a system-level instruction (tagged `TrustLevel.SYSTEM`, role="system"). Used for persistent system prompts that frame the agent's behaviour.

**Returns:** `str` — block ID.

**Example:**

```python
session.add_system(
    "You are a helpful assistant. Never share credentials or personal data."
)
```

### `SecureSession.add_data()`

```python
def add_data(
    content: str,
    source: str,
    trust: TrustLevel | str = TrustLevel.NONE,
    **metadata,
) -> str
```

Add external data to the context. Defaults to `TrustLevel.NONE` — the content can be read and summarised but cannot trigger actions.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `content` | `str` | — | The data content |
| `source` | `str` | — | Origin identifier, e.g. `"imap"`, `"web_fetch"`, `"pdf_parser"` |
| `trust` | `TrustLevel \| str` | `TrustLevel.NONE` | Trust level. Pass a string like `"none"` or `"tool"`. |
| `**metadata` | `Any` | — | Additional metadata on the block |

**Returns:** `str` — block ID.

**Example:**

```python
# Untrusted email body
session.add_data(email_body, source="imap")

# Tool output (slightly more trusted, still informational only)
session.add_data(search_result, source="web_search", trust="tool")

# Pass string trust level
session.add_data(doc_content, source="pdf_parser", trust="none")
```

### `SecureSession.add_tool_result()`

```python
def add_tool_result(
    content: str,
    tool_name: str,
    tool_call_id: str | None = None,
    **metadata,
) -> str
```

Add a tool or API result. Automatically tagged `TrustLevel.TOOL` with source `"tool:{tool_name}"`.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `content` | `str` | Tool result content |
| `tool_name` | `str` | Name of the tool (e.g., `"web_search"`) |
| `tool_call_id` | `str \| None` | OpenAI tool_call_id for linking result to call |

**Returns:** `str` — block ID.

**Example:**

```python
# After calling a tool
session.add_tool_result(
    content=search_api_response,
    tool_name="web_search",
    tool_call_id=tool_call.id,
)
```

### `SecureSession.to_messages()`

```python
def to_messages() -> list[dict[str, Any]]
```

Serialise the session context to OpenAI-compatible messages format. Injects the trust preamble as a system message and wraps untrusted blocks in structural isolation markers.

**Returns:** `list[dict]` — list of `{"role": str, "content": str}` dicts.

**Example:**

```python
messages = session.to_messages()
response = openai_client.chat.completions.create(
    model="gpt-4o",
    messages=messages,
    tools=my_tools,
)
```

### `SecureSession.validate_action()`

```python
def validate_action(tool_call: ToolCall) -> ValidationResult
```

Validate a single tool call against the session's trust context and policies.

### `SecureSession.validate_actions()`

```python
def validate_actions(tool_calls: list[ToolCall]) -> list[ValidationResult]
```

Validate multiple tool calls in order.

### `SecureSession.new_context()`

```python
def new_context() -> None
```

Reset the context for a new conversation turn. Keeps the session key and policy.

### `SecureSession.context`

```python
@property
def context(self) -> SecureContext
```

The underlying `SecureContext`.

### `SecureSession.signer`

```python
@property
def signer(self) -> SessionSigner
```

The session's `SessionSigner`.

---

## `SecureContext`

`shieldflow.core.context.SecureContext`

Assembles trust-tagged context blocks and serialises them for LLM consumption. Can be used standalone (without a session) when signing isn't required.

### Constructor

```python
SecureContext()
```

### `SecureContext.add_instruction()`

```python
def add_instruction(
    content: str,
    trust: TrustTag | None = None,
    role: str = "user",
    **metadata,
) -> str
```

Add a verified instruction. Defaults to `owner_trust()` if no tag provided.

### `SecureContext.add_system()`

```python
def add_system(content: str, **metadata) -> str
```

Add a system-level instruction (role="system", `TrustLevel.SYSTEM`).

### `SecureContext.add_data()`

```python
def add_data(
    content: str,
    source: str,
    trust: TrustLevel | TrustTag | str = TrustLevel.NONE,
    role: str = "user",
    **metadata,
) -> str
```

Add external data. Accepts `TrustLevel`, `TrustTag`, or string trust level name.

### `SecureContext.add_tool_result()`

```python
def add_tool_result(
    content: str,
    tool_name: str,
    tool_call_id: str | None = None,
    **metadata,
) -> str
```

Add a tool result (tagged `TrustLevel.TOOL`, role="tool").

### `SecureContext.to_messages()`

```python
def to_messages(include_trust_preamble: bool = True) -> list[dict[str, Any]]
```

Serialise to OpenAI messages format. Set `include_trust_preamble=False` to suppress the injected security system message.

### `SecureContext.get_block()`

```python
def get_block(block_id: str) -> ContextBlock | None
```

Retrieve a block by its ID. Returns `None` if not found.

### `SecureContext.get_untrusted_blocks()`

```python
def get_untrusted_blocks() -> list[ContextBlock]
```

Return all blocks with `trust.level <= TrustLevel.TOOL`.

### `SecureContext.get_instruction_blocks()`

```python
def get_instruction_blocks() -> list[ContextBlock]
```

Return all blocks with `trust.level >= TrustLevel.USER` (blocks that can contain instructions).

### `SecureContext.blocks`

```python
@property
def blocks(self) -> list[ContextBlock]
```

All context blocks in insertion order (returns a copy).

---

## `ContextBlock`

`shieldflow.core.context.ContextBlock`

A single content block in the context with its trust metadata.

```python
@dataclass
class ContextBlock:
    block_id: str          # Unique ID, format: "blk_{12 hex chars}"
    content: str           # The text content
    trust: TrustTag        # Immutable trust metadata
    role: str              # "system" | "user" | "assistant" | "tool"
    metadata: dict         # Arbitrary additional data
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `is_instruction` | `bool` | `True` if `trust.can_instruct` (i.e., `level >= USER`) |
| `is_untrusted` | `bool` | `True` if `trust.level <= TOOL` |

---

## `TrustLevel`

`shieldflow.core.trust.TrustLevel`

Integer enumeration of trust levels, from least to most privileged.

```python
class TrustLevel(IntEnum):
    NONE   = 0  # External/untrusted: web pages, emails, documents
    TOOL   = 1  # Tool/API outputs: informational only
    AGENT  = 2  # Other AI agents: scoped actions only
    SYSTEM = 3  # System-level: cron jobs, system prompts
    USER   = 4  # Authenticated users: most actions
    OWNER  = 5  # Agent owner: full control
```

Because it's an `IntEnum`, levels can be compared directly: `TrustLevel.USER > TrustLevel.NONE`.

### `TrustLevel.from_string()`

```python
@classmethod
def from_string(cls, value: str) -> TrustLevel
```

Parse a trust level from a string (case-insensitive).

| String | Level |
|--------|-------|
| `"none"` / `"any"` | `NONE` |
| `"tool"` | `TOOL` |
| `"agent"` | `AGENT` |
| `"system"` | `SYSTEM` |
| `"user"` | `USER` |
| `"owner"` / `"full"` | `OWNER` |

**Raises:** `ValueError` for unknown strings.

### `TrustLevel.meets_requirement()`

```python
def meets_requirement(self, required: TrustLevel) -> bool
```

Returns `True` if this level is >= required. Equivalent to `self >= required`.

```python
TrustLevel.OWNER.meets_requirement(TrustLevel.USER)  # True
TrustLevel.NONE.meets_requirement(TrustLevel.USER)   # False
```

---

## `TrustTag`

`shieldflow.core.trust.TrustTag`

Immutable trust metadata attached to a context block. Frozen dataclass — cannot be modified after creation.

```python
@dataclass(frozen=True)
class TrustTag:
    level: TrustLevel
    source: str                          # e.g., "user_chat", "imap", "web_fetch"
    source_id: str | None = None         # Provenance ID
    verified_by: str | None = None       # "hmac" | "session_auth" | "framework"
    elevated_from: TrustLevel | None = None
    elevation_reason: str | None = None
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `was_elevated` | `bool` | `True` if `elevated_from` is set |
| `is_trusted` | `bool` | `True` if `level >= USER` |
| `can_instruct` | `bool` | `True` if `level >= USER` — source may give instructions |

---

## Trust Constructors

Convenience functions for creating common trust tags.

```python
from shieldflow.core.trust import owner_trust, user_trust, system_trust, untrusted
```

### `owner_trust()`

```python
def owner_trust(source: str = "user_chat", verified_by: str = "hmac") -> TrustTag
```

Create an `OWNER`-level trust tag.

### `user_trust()`

```python
def user_trust(source: str = "user_chat", verified_by: str = "hmac") -> TrustTag
```

Create a `USER`-level trust tag.

### `system_trust()`

```python
def system_trust(source: str = "system_prompt") -> TrustTag
```

Create a `SYSTEM`-level trust tag with `verified_by="framework"`.

### `untrusted()`

```python
def untrusted(source: str = "unknown") -> TrustTag
```

Create a `NONE`-level trust tag.

---

## `SessionSigner`

`shieldflow.core.signing.SessionSigner`

Manages HMAC-SHA256 signing for a session. Each instance holds a single ephemeral key that never enters the context window.

### Constructor

```python
SessionSigner(
    key: bytes | None = None,
    key_id: str | None = None,
    max_age_seconds: int = 300,
)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `key` | `bytes \| None` | `None` | 32-byte signing key. `os.urandom(32)` used if not provided. |
| `key_id` | `str \| None` | `None` | Human-readable key identifier. Derived from key if not provided. |
| `max_age_seconds` | `int` | `300` | Signature validity window (replay protection). |

### `SessionSigner.sign()`

```python
def sign(content: str) -> SignedMessage
```

Sign a message. Records current timestamp; signatures expire after `max_age_seconds`.

**Returns:** `SignedMessage`

### `SessionSigner.verify()`

```python
def verify(message: SignedMessage) -> VerificationResult
```

Verify a signed message. Checks:
1. Key ID match (if present)
2. Timestamp within validity window (replay protection, ±30s clock skew allowed)
3. HMAC validity (constant-time comparison)

**Returns:** `VerificationResult`

### `SessionSigner.key_id`

```python
@property
def key_id(self) -> str
```

Non-secret key identifier (SHA-256 of `"shieldflow-key-id:" + key`, first 16 hex chars). Safe to log.

### `create_session_signer()`

```python
def create_session_signer() -> SessionSigner
```

Module-level convenience function. Creates a `SessionSigner` with a fresh random key.

---

## `SignedMessage`

`shieldflow.core.signing.SignedMessage`

A signed message with its HMAC and timestamp. Frozen dataclass.

```python
@dataclass(frozen=True)
class SignedMessage:
    content: str        # Original message content
    timestamp: float    # Unix timestamp of signing
    signature: str      # Hex-encoded HMAC-SHA256
    key_id: str | None  # Key identifier (non-secret)
```

---

## `VerificationResult`

`shieldflow.core.signing.VerificationResult`

Result of verifying a `SignedMessage`. Frozen dataclass.

```python
@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str
    message: SignedMessage | None  # Set if valid=True
```

---

## `PolicyEngine`

`shieldflow.core.policy.PolicyEngine`

Evaluates whether actions are allowed based on trust levels and data classification. Designed to fail secure: unknown actions default to `OWNER` trust requirement.

### Constructor

```python
PolicyEngine(
    action_policies: list[ActionPolicy] | None = None,
    elevation_rules: list[ElevationRule] | None = None,
    data_classes: list[DataClass] | None = None,
)
```

Pass `None` to any parameter to use the built-in defaults (see [Default Policies](#default-policies)).

### `PolicyEngine.from_yaml()`

```python
@classmethod
def from_yaml(cls, path: str) -> PolicyEngine
```

Load a `PolicyEngine` from a YAML config file. See `ShieldFlow` constructor docs for the config format.

**Raises:** `FileNotFoundError`, `yaml.YAMLError`

### `PolicyEngine.evaluate()`

```python
def evaluate(
    action: str,
    trigger_trust: TrustLevel,
    data_content: str | None = None,
    is_external_destination: bool = False,
    trigger_source: str | None = None,
) -> PolicyDecision
```

Evaluate whether an action should be allowed.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | `str` | Action type, e.g. `"message.send"`, `"exec"` |
| `trigger_trust` | `TrustLevel` | Trust level of the content that triggered this action |
| `data_content` | `str \| None` | Content being sent, for data classification |
| `is_external_destination` | `bool` | Whether the action sends data outside the system |
| `trigger_source` | `str \| None` | Human-readable description of what triggered the action |

**Returns:** `PolicyDecision`

**Example:**

```python
engine = PolicyEngine()
decision = engine.evaluate(
    action="email.send",
    trigger_trust=TrustLevel.NONE,
    data_content="Draft email body...",
    is_external_destination=True,
    trigger_source="imap email body",
)
print(decision.allowed)  # False
print(decision.reason)
# "Action 'email.send' requires trust level USER but was triggered 
#  by source with trust level NONE"
```

---

## `ActionPolicy`

`shieldflow.core.policy.ActionPolicy`

Policy for a single action type. Frozen dataclass.

```python
@dataclass(frozen=True)
class ActionPolicy:
    action: str                    # Action name, e.g. "email.send"
    min_trust: TrustLevel          # Minimum trust to allow
    confirm_if_elevated: bool = False  # Extra check if trust was elevated
    never_auto: bool = False       # Always requires per-instance confirmation
    description: str = ""
```

---

## `ElevationRule`

`shieldflow.core.policy.ElevationRule`

Rule for conditionally elevating trust from a specific source. Frozen dataclass.

```python
@dataclass(frozen=True)
class ElevationRule:
    source_type: str              # e.g., "email"
    match: dict[str, str] = ...  # e.g., {"from": "boss@co.com"}
    require_dkim: bool = False
    require_spf: bool = False
    elevate_to: TrustLevel = TrustLevel.USER
    allowed_actions: list[str] = ...
    denied_actions: list[str] = ...
```

---

## `DataClass`

`shieldflow.core.policy.DataClass`

Classification category for data content. Frozen dataclass.

```python
@dataclass(frozen=True)
class DataClass:
    name: str
    patterns: list[str] = ...         # Regex patterns
    external_share: ActionDecision = ActionDecision.BLOCK
```

---

## `PolicyDecision`

`shieldflow.core.policy.PolicyDecision`

Result of a policy evaluation. Frozen dataclass.

```python
@dataclass(frozen=True)
class PolicyDecision:
    decision: ActionDecision           # ALLOW | BLOCK | CONFIRM
    action: str
    required_trust: TrustLevel
    actual_trust: TrustLevel
    reason: str
    data_classification: str | None    # Set if data classification triggered the decision
    provenance_source: str | None
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `allowed` | `bool` | `decision == ALLOW` |
| `blocked` | `bool` | `decision == BLOCK` |

---

## `ActionDecision`

`shieldflow.core.policy.ActionDecision`

```python
class ActionDecision(Enum):
    ALLOW   = "allow"    # Proceed
    BLOCK   = "block"    # Deny, log
    CONFIRM = "confirm"  # Pause, ask user
```

---

## `ActionValidator`

`shieldflow.core.validator.ActionValidator`

Intercepts tool calls and validates them against trust policies and provenance. Normally used via `SecureSession.validate_action()`.

### Constructor

```python
ActionValidator(policy_engine: PolicyEngine)
```

### `ActionValidator.validate()`

```python
def validate(
    tool_call: ToolCall,
    context: SecureContext,
) -> ValidationResult
```

Full validation pipeline:
1. Find the context block that most likely triggered this tool call
2. Check if untrusted blocks contain injection patterns matching this action
3. Evaluate action against policy (trust level check)
4. Check data classification for external sends

### `ActionValidator.validate_batch()`

```python
def validate_batch(
    tool_calls: list[ToolCall],
    context: SecureContext,
) -> list[ValidationResult]
```

Validate multiple tool calls. Results in same order as input.

---

## `ToolCall`

`shieldflow.core.validator.ToolCall`

Represents a tool call from the model. Frozen dataclass.

```python
@dataclass(frozen=True)
class ToolCall:
    id: str                    # Tool call ID from the LLM
    name: str                  # Tool name, e.g. "send_email"
    arguments: dict[str, Any]  # Parsed arguments
```

**Example — constructing from OpenAI response:**

```python
from shieldflow.core.validator import ToolCall
import json

for raw in llm_response.choices[0].message.tool_calls:
    tc = ToolCall(
        id=raw.id,
        name=raw.function.name,
        arguments=json.loads(raw.function.arguments),
    )
    result = session.validate_action(tc)
```

---

## `ValidationResult`

`shieldflow.core.validator.ValidationResult`

Result of validating a tool call. Frozen dataclass.

```python
@dataclass(frozen=True)
class ValidationResult:
    tool_call: ToolCall
    allowed: bool
    decision: ActionDecision           # ALLOW | BLOCK | CONFIRM
    reason: str                        # Human-readable explanation
    triggered_by: ContextBlock | None  # Block attributed as the trigger
    trigger_trust: TrustLevel          # Trust level of the trigger
    data_classification: str | None    # If data classification triggered decision
    policy_decision: PolicyDecision | None
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `blocked` | `bool` | `decision == BLOCK` |
| `needs_confirmation` | `bool` | `decision == CONFIRM` |

**Example — handling results:**

```python
result = session.validate_action(tool_call)

if result.allowed:
    output = execute_tool(result.tool_call)
elif result.needs_confirmation:
    if await ask_user(result.reason):
        output = execute_tool(result.tool_call)
    else:
        output = "Action cancelled by user."
else:
    # result.blocked
    logger.warning(
        "Blocked tool call",
        action=result.tool_call.name,
        reason=result.reason,
        trigger_source=str(result.triggered_by.trust) if result.triggered_by else None,
    )
    output = f"I wasn't able to complete that action: {result.reason}"
```

---

## Default Policies

### Default Action Policies

These are applied when no config file is provided:

| Action | Min Trust | Never Auto | Description |
|--------|-----------|------------|-------------|
| `web_search` | `NONE` | No | Search the web |
| `web_fetch` | `NONE` | No | Fetch a URL |
| `summarise` | `NONE` | No | Summarise content |
| `read_public` | `NONE` | No | Read public data |
| `message.send` | `USER` | No | Send a message |
| `email.send` | `USER` | No | Send an email |
| `email.reply` | `USER` | No | Reply to an email |
| `file.read` | `USER` | No | Read a file |
| `file.write` | `USER` | No | Write a file |
| `calendar.update` | `USER` | No | Update calendar |
| `exec` | `OWNER` | No | Execute code/commands |
| `file.delete` | `OWNER` | No | Delete a file |
| `config.modify` | `OWNER` | No | Modify configuration |
| `share.external` | `OWNER` | No | Share data externally |
| `data.bulk_export` | `OWNER` | **Yes** | Export data in bulk |
| `credential.read` | `OWNER` | **Yes** | Access credentials |
| `send.new_recipient` | `OWNER` | **Yes** | Send to new/unknown recipient |

**Unknown actions default to `OWNER` trust requirement (fail secure).**

### Default Data Classification Patterns

| Class | Patterns | External Share |
|-------|----------|---------------|
| `restricted` | `password:`, `api_key:`, `-----BEGIN * KEY-----`, `sk-[32+ chars]`, SSN format | `BLOCK` |
| `internal` | `employee`, `staff list`, `personnel`, `client list`, `salary`, `payroll` | `CONFIRM` |
| `public` | *(none — catchall)* | `ALLOW` |

---

## Exceptions

ShieldFlow uses standard Python exceptions:

| Exception | When raised |
|-----------|-------------|
| `ValueError` | Invalid trust level string in `TrustLevel.from_string()` |
| `FileNotFoundError` | Config path doesn't exist in `ShieldFlow()` or `PolicyEngine.from_yaml()` |
| `yaml.YAMLError` | Malformed YAML config |

ShieldFlow does **not** raise exceptions for blocked or suspicious actions — it returns `ValidationResult` / `PolicyDecision` objects. Callers are responsible for acting on these.
