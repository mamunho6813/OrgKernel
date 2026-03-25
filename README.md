# OrgKernel

<p align="center">
  <strong>Enterprise Trust Layer for AI Agents</strong><br/>
  Cryptographically secure identity, scoped execution, and tamper-evident audit trails —<br/>
  transparent by design, not by promise.
</p>

<p align="center">
  <a href="https://github.com/MetapriseAI/OrgKernel/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" />
  </a>
  <a href="https://github.com/MetapriseAI/OrgKernel/stargazers">
    <img src="https://img.shields.io/github/stars/MetapriseAI/OrgKernel?style=flat&color=yellow" alt="GitHub Stars" />
  </a>
  <a href="https://github.com/MetapriseAI/OrgKernel/issues">
    <img src="https://img.shields.io/github/issues/MetapriseAI/OrgKernel" alt="GitHub Issues" />
  </a>
  <a href="https://github.com/MetapriseAI/OrgKernel/pulls">
    <img src="https://img.shields.io/github/issues-pr/MetapriseAI/OrgKernel" alt="Pull Requests" />
  </a>
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/FastAPI-supported-009688?logo=fastapi" alt="FastAPI" />
  <img src="https://img.shields.io/badge/PostgreSQL-18.1-336791?logo=postgresql" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/tests-61%20passed-brightgreen" alt="61 Tests Passed" />
  <img src="https://img.shields.io/badge/coverage-100%25-brightgreen" alt="Coverage 100%" />
</p>

<p align="center">
  <b>8</b> Core Modules &nbsp;·&nbsp; <b>61</b> Test Cases &nbsp;·&nbsp; <b>5</b> Build Phases &nbsp;·&nbsp; PostgreSQL Persistence
</p>

---

## Overview

**OrgKernel** is the security and governance foundation for the AI Agent system. It ensures every agent has a verifiable cryptographic identity, every mission operates within strict boundaries, and every action leaves a tamper-evident audit trail — all without a running AI model.

| Capability | Description |
|---|---|
| **Cryptographic Identity (PKI)** | Ed25519 keypairs, Org CA signing, and challenge-response verification — all running in-memory without external dependencies |
| **Scoped Execution Tokens** | Mission-scoped permission tokens with tool allowlists, numeric parameter bounds, and Ed25519 signatures to prevent token grafting |
| **8-State Mission Lifecycle** | Full mission lifecycle from launch through approval to close, with enforced state transitions and integrated constraint materialization |
| **Hash-Chained Audit Trail** | Three-layer audit (Business / Execution / Compliance) persisted to PostgreSQL with SHA-256 hash chaining and integrity verification |
| **Policy Engine** | Declarative policy CRUD with version history, evaluation rules, and real-time constraint derivation at mission approval time |
| **Authority Graph** | Org hierarchy traversal, approval level determination, spend authority resolution, and tool authorization — all at runtime |

---

## Build Phases

| Phase | Scope |
|---|---|
| Phase 1 | Core primitives: Identity, Token, Audit |
| Phase 2 | Mission lifecycle with state machine |
| Phase 3 | Gateway, Policy, Authority, Classifier |
| Phase 4 | Full DB persistence & version history |
| Phase 5 | Optimization & Iteration |

---

## System Architecture

OrgKernel orchestrates eight services across a five-phase mission execution flow. Every phase writes to a specific audit layer before proceeding.

### Complete Flow — Five Phases

| Phase | Component(s) Called | Audit Layer | Key Behavior |
|---|---|---|---|
| **1 Mission Launch** | `MissionService.launch()` | L1 Business | Validates AgentIdentity -> creates Mission record -> writes `mission_launched` to L1 with `agent_id`, `org_id`, `initiated_by`, `objective` -> state auto-transitions `CREATED -> PLANNING` |
| **2 State Transition** | `MissionService.submit()` -> `_transition_state()` | L2 Execution | Pushes mission into approval queue; state `PLANNING -> WAITING_APPROVAL`. Writes `state_transition_submit` to L2, recording `from_state` and `to_state` |
| **3 Triple Review** | `PolicyEngineService` + `AuthorityGraphService` + `DataClassifierService` | L2 Execution | Three constraint services evaluated sequentially. Results frozen into `MissionBoundary` snapshot. `ExecutionTokenService.mint()` issues Ed25519-signed token. Writes `approval_granted` to L2. State -> `APPROVED` |
| **4 Tool Execution** | `ToolGatewayService.validate_tool_call()` | L2 Execution | Every tool call passes five gateway checks: token exists + not expired, CA signature valid, `token.agent_id == caller.agent_id`, tool in scope, tool not forbidden. Writes L2 on every call |
| **5 Mission Close** | `MissionService.close()` | L2 Execution | Writes `MissionOutcome` -> marks `ExecutionToken` as used -> state -> `CLOSED`. Writes `state_transition_close` to L2 |
| **6 Escalation** *(optional)* | `MissionService.escalate()` | L3 Compliance | Triggered when human compliance review is required. **This is the only write path for L3.** |

### Three-Layer Audit Semantics

| Audit Layer | Triggered By | Semantics |
|---|---|---|
| **L1 Business** | `MissionService.launch()` | Business perspective: who, in which org, wants to accomplish what task |
| **L2 Execution** | All state transitions + every tool call + approval + close | Execution perspective: every behavior the system performed |
| **L3 Compliance** | Only `MissionService.escalate()` | Compliance perspective: what triggered human compliance intervention |

### Architecture Diagram

```
Mission Launch
  MissionService.launch()
    |-- validates identity --> AgentIdentityService.get_active_identity()
    |-- writes L1 Business --> audit_chain_db_log.l1_business()
    v
  MissionService.submit()
    |-- writes L2 Execution --> state_transition_submit
    v
  MissionService.approve()   [Triple Review]
    |-- PolicyEngineService.evaluate_for_mission()
    |-- AuthorityGraphService.resolve_authority()
    |-- DataClassifierService.classify_for_mission()
    |-- produces --> MissionBoundary snapshot (frozen, immutable)
    |-- mints   --> ExecutionTokenService.mint()  [Ed25519 signed]
    |-- writes L2 Execution --> approval_granted
    v
  Agent Execution
    |-- every tool call --> ToolGatewayService.validate_tool_call()
    |-- writes L2 Execution --> every call (ALLOWED or BLOCKED)
    v
  Mission Close / Escalate
    |-- MissionService.close()    --> L2 close
    |-- MissionService.escalate() --> L3 escalation (ONLY path to L3)
```

### Challenge-Response Authentication

| Step | Party | Action |
|---|---|---|
| 1 | Verifier | Calls `AgentIdentityService.request_challenge(agent_id, issued_by)` - generates random nonce + `challenge_id`, stored in memory with 5-minute TTL |
| 2 | Verifier -> Agent | Sends nonce to the target Agent |
| 3 | Agent | Signs the nonce with its Ed25519 private key, constructs `ChallengeResponse(challenge_id, nonce, public_key, signature)` |
| 4 | Verifier | Calls `verify_challenge(response)` - validates: nonce one-time use (anti-replay), Ed25519 signature correct, certificate ACTIVE and not expired |

**Attack vectors prevented:** Replay attack (nonce consumed after one use), Private key theft (signature must match nonce), Token Grafting (`ToolGateway` verifies `token.agent_id == caller.agent_id`).

---

## Core Modules

### Module 01 — Agent Identity *(Phase 1)*

PKI lifecycle management for AI agents. Generates Ed25519 keypairs, issues X.509-style certificates signed by an Org CA, and manages the revoke / suspend / reactivate lifecycle.

**Tags:** `Ed25519` `CSR` `Challenge-Response` `Revocation`

### Module 02 — Execution Token *(Phase 1)*

Scoped, time-bounded permission tokens for mission execution. Each token carries a tool allowlist, numeric parameter bounds, and an Ed25519 signature to prevent token grafting attacks.

**Tags:** `Tool Scope` `Bounded Params` `Ed25519 Sig` `Expiry`

### Module 03 — Mission Lifecycle *(Phase 2)*

8-state mission state machine: `CREATED -> PLANNING -> WAITING_APPROVAL -> APPROVED -> PENDING_EXECUTION -> IN_PROGRESS -> EXECUTED -> CLOSED`. Materializes boundaries at approval time.

**Tags:** `8 States` `State Transitions` `Boundary Snapshot` `REST API`

### Module 04 — Tool Gateway *(Phase 3)*

Enforces token scope before every external tool call. Validates the token signature, checks tool in scope, verifies bounded params, and writes execution audit entries. Prevents Token Grafting attacks at runtime.

**Tags:** `Scope Guard` `Token Grafting Prevention` `Param Bounds` `ALLOWED/BLOCKED/PARTIAL`

### Module 05 — Policy Engine *(Phase 3)*

Declarative policy CRUD with version history and audit trail. Evaluates rules at mission approval time to derive forbidden tools, time restrictions, spend limits, and dual-approval requirements.

**Tags:** `Policy CRUD` `Version History` `Rule Evaluation` `6 Policy Types`

### Module 06 — Authority Graph *(Phase 3)*

Org hierarchy traversal and approval level resolution. Maps agents to org units, determines L0-L5 approval requirements, builds multi-step approval chains, and resolves spend authority for mission authorization.

**Tags:** `Org Hierarchy` `L0-L5 Approval` `Spend Authority` `Approval Chain`

### Module 07 — Data Classifier *(Phase 3)*

Classifies data sources accessed by a mission's tools using rule-based classification. Produces a routing classification (PUBLIC to TOP_SECRET) and data scope constraints for the `MissionBoundary`.

**Tags:** `5 Tiers` `5 Scopes` `Rule Engine` `Data Constraints`

### Module 08 — Audit Chain *(Phase 1)*

Three-layer, hash-chained audit logging persisted to PostgreSQL. Each layer (Business, Execution, Compliance) maintains its own SHA-256 hash chain with integrity verification. REST API exposes chain query and cryptographic integrity checks.

**Tags:** `3 Audit Layers` `SHA-256 Chain` `Integrity Verify` `REST API`

---

## Mission 8-State Lifecycle

Every mission follows this state machine. Invalid transitions raise `InvalidStateTransitionError`. All transitions are audited via the L2 Execution layer.

### Valid Transitions

| From State | Allowed Transitions | How It Happens |
|---|---|---|
| `CREATED` | -> `PLANNING` | Only path — set by `launch()` internally |
| `PLANNING` | -> `WAITING_APPROVAL` or -> `APPROVED` | `submit()` goes to `WAITING_APPROVAL`; L0 agents can self-approve -> `APPROVED` directly |
| `WAITING_APPROVAL` | -> `APPROVED` or -> `CLOSED` | `approve()` -> `APPROVED`; `reject()` or `close(CANCELLED)` -> `CLOSED` |
| `APPROVED` | -> `PENDING_EXECUTION` or -> `IN_PROGRESS` | `start_execution()` skips queue -> `IN_PROGRESS` directly; otherwise -> `PENDING_EXECUTION` |
| `PENDING_EXECUTION` | -> `IN_PROGRESS` or -> `WAITING_APPROVAL` or -> `CLOSED` | Normal start -> `IN_PROGRESS`; rollback -> `WAITING_APPROVAL`; `close(CANCELLED)` -> `CLOSED` |
| `IN_PROGRESS` | -> `EXECUTED` or -> `WAITING_APPROVAL` or -> `CLOSED` | `complete_execution()` -> `EXECUTED`; rollback -> `WAITING_APPROVAL`; `close()` or `escalate()` -> `CLOSED` |
| `EXECUTED` | -> `CLOSED` | Only path — `close()` with `SUCCESS` or `FAILED` |
| `CLOSED` | none | Terminal — no further transitions allowed |

### State Diagram

```
CREATED --> PLANNING --> WAITING_APPROVAL
                |              |
                |         reject/close(CANCELLED)
                |              |
                +-----> APPROVED <-----------+
                (L0 self-approval)           |
                                 |           |
                                 v           |
                        PENDING_EXECUTION    |
                                 |      rollback
                                 v           |
                           IN_PROGRESS ------+
                                 |
                                 v
                            EXECUTED --> CLOSED (terminal)

Escape to CLOSED from: WAITING_APPROVAL, PENDING_EXECUTION, IN_PROGRESS
Only escalate() writes L3 Compliance -- all other CLOSE writes L2
```

---

## Security Model

### Token Grafting Prevention

The Execution Token is Ed25519-signed by the Org CA covering the full payload (scope, bounds, expiry). Any modification invalidates the signature. The ToolGateway verifies this on every call.

### Challenge-Response Authentication

Agents prove identity via Ed25519 challenge-response with one-time nonces. Certificates are verified against the Org CA's public key. Revocation and expiry are enforced at verification time.

### Tamper-Evident Audit Chain

Every L1/L2/L3 entry carries a SHA-256 hash of its content and a `prev_hash` linking to the previous entry. The integrity API recomputes all hashes and detects any deleted, modified, or reordered entries.

### Audit Chain Integrity Checks

| Check | Detects |
|---|---|
| Hash present | Hash stripped by attacker |
| Sequence continuity (IDs increment by 1) | Entry deletion |
| `prev_hash` linkage | Entry modification or reordering |
| Content hash match (stored == recomputed SHA-256) | Entry content tampering |

---

## Quick Start

### Python

```python
pip install orgkernel

from orgkernel import OrgKernel

kernel = OrgKernel.init(org_id="acme-corp", sso_provider="okta")

identity = kernel.create_identity(
    name="compliance-agent",
    org_unit="legal/compliance",
    ttl="24h"
)

token = kernel.issue_token(
    identity=identity,
    tools=["doc_reader", "email_sender"],
    authority_level=2
)

valid = kernel.audit_chain.verify()  # True
```

### TypeScript

```typescript
import { OrgKernel } from "@metaprise/orgkernel";

const kernel = await OrgKernel.init({ orgId: "acme-corp", ssoProvider: "okta" });

const identity = await kernel.createIdentity({
  name: "compliance-agent",
  orgUnit: "legal/compliance",
  ttl: "24h",
});

const token = await kernel.issueToken({
  identity,
  tools: ["doc_reader", "email_sender"],
  authorityLevel: 2,
});

const valid = await kernel.auditChain.verify(); // true
```

### Rust

```rust
use orgkernel::{OrgKernel, IdentityConfig, TokenConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let kernel = OrgKernel::init("acme-corp", "okta").await?;

    let identity = kernel.create_identity(IdentityConfig {
        name: "compliance-agent".into(),
        org_unit: "legal/compliance".into(),
        ttl: "24h".into(),
    }).await?;

    let token = kernel.issue_token(TokenConfig {
        identity: &identity,
        tools: vec!["doc_reader", "email_sender"],
        authority_level: 2,
    }).await?;

    let valid = kernel.audit_chain().verify().await?; // true
    Ok(())
}
```

---

## Schema Reference

### AgentIdentity

| Field | Type | Description |
|---|---|---|
| `agent_id` | string | Unique ID prefixed `aid_`, validated as `^aid_[a-z0-9]+$` |
| `agent_name` | string | Validated as `^[a-z][a-z0-9_-]*$` — unique per org |
| `org_id` | string | Organization identifier, validated as `^[a-z][a-z0-9-]*$` |
| `public_key` | string | Ed25519 public key in Base64url encoding (43-44 chars) |
| `org_ca_fingerprint` | string | SHA-256 hex fingerprint of Org CA public key (64 chars) |
| `issued_at`, `valid_until` | datetime | Certificate validity window |
| `status` | enum | `ACTIVE`, `SUSPENDED`, `REVOKED`, `EXPIRED` |
| `revoked_at`, `revoked_by`, `revocation_reason` | mixed | Set only when `status = REVOKED` |

### ExecutionToken

| Field | Type | Description |
|---|---|---|
| `token_id` | string | Unique ID prefixed `tok_` |
| `execution_scope` | list[string] | Allowlisted tool names, min 1 item |
| `immutable_params` | dict | Key=value pairs that must match exactly at call time |
| `bounded_params` | list[BoundedParam] | Named numeric bounds: `upper_bound` and `lower_bound` per param |
| `token_signature` | string | Ed25519 EdDSA signature (Base64url, 86-88 chars) over canonical JSON payload |
| `expires_at` | datetime | Token expiry |
| `used` | bool | One-time consumption flag |

### MissionBoundary — Frozen Execution Constraints

| Field | Source |
|---|---|
| `authority_constraints` | `AuthorityGraphService.resolve_authority()` |
| `policy_constraints` | `PolicyEngineService.evaluate_for_mission()` |
| `data_constraints` | `DataClassifierService.classify_for_mission()` |
| `runtime_constraints` | MissionDefinition + PolicyEngine `max_tool_calls` |
| `authority_graph_version` | Snapshot version of authority graph at approval |
| `policy_engine_version` | Snapshot version of policy engine at approval |

### Audit Chain — Three-Layer Hash Chain

| Layer | Triggered By | Content |
|---|---|---|
| **L1 Business** | `MissionService.launch()` | Mission objective, org, initiated_by |
| **L2 Execution** | State transitions + `ToolGateway.validate_tool_call()` | Tool name, params, status, violations |
| **L3 Compliance** | Only `MissionService.escalate()` | Escalation reason, escalated_to, from_state |

### Enums

```
AgentIdentityStatus:  ACTIVE | SUSPENDED | REVOKED | EXPIRED

MissionState:         CREATED | PLANNING | WAITING_APPROVAL | APPROVED |
                      PENDING_EXECUTION | IN_PROGRESS | EXECUTED | CLOSED

ApprovalLevel:        L0 (no approval) | L1 (self) | L2 (team) |
                      L3 (department) | L4 (executive) | L5 (board/C-level)

ClassificationTier:   PUBLIC | INTERNAL | CONFIDENTIAL | SECRET | TOP_SECRET

PolicyType:           TOOL_RESTRICTION | DATA_ACCESS | RATE_LIMIT |
                      SPEND_LIMIT | TIME_RESTRICTION | CUSTOM
```

---

## Test Results

61 independent test cases across 8 modules. All tests run as standalone Python scripts with no external services required (DB tests use the remote PostgreSQL configured in `env/.env.dev`).

| Module | Tests | Coverage |
|---|---|---|
| `agent_identity` | 7 | PKI: Ed25519, CSR, Cert, Challenge-Response, Lifecycle |
| `execution_token` | 9 | Scope, Bounds, Immutable Params, Expiry, Signatures |
| `mission` | 10 | 8 States, Transitions, Schemas, DB Session |
| `tool_gateway` | 7 | ALLOWED/BLOCKED/PARTIAL, Severity, ToolCallStatus |
| `policy_engine` | 9 | PolicyType, PolicyEffect, Rules, EvaluationRequest |
| `authority_graph` | 7 | NodeType, EdgeType, ApprovalLevel, CheckRequest |
| `data_classifier` | 7 | ClassificationTier, Rules, ClassificationRequest |
| `audit_chain` | 5 | L1/L2/L3, Header persist, Body layer verification |
| **Total** | **61** | **ALL PASSED — 0 failed, 0 skipped** |

### Running the Tests

```bash
python tests/module_orgkernel/test_agent_identity.py
python tests/module_orgkernel/test_execution_token.py
python tests/module_orgkernel/test_mission.py
python tests/module_orgkernel/test_tool_gateway.py
python tests/module_orgkernel/test_policy_engine.py
python tests/module_orgkernel/test_authority_graph.py
python tests/module_orgkernel/test_data_classifier.py
python tests/module_orgkernel/test_audit_chain.py   # requires PostgreSQL
```

---

## Contributing

We welcome contributions from the community. OrgKernel is the cryptographic trust foundation of an enterprise agent platform — quality and security are paramount.

### How to Contribute

1. **Fork** the repository and create your branch from `main`
2. **Write tests** for any new functionality — we maintain 100% test coverage
3. **Ensure** all existing tests pass before submitting
4. **Document** any new public APIs or modules
5. **Submit** a Pull Request with a clear description of the change and its motivation

### Reporting Security Issues

If you discover a security vulnerability, **do not open a public issue**. Please disclose responsibly by emailing [developer@metaprise.ai](mailto:developer@metaprise.ai). We will acknowledge receipt within 48 hours and provide a remediation timeline.

### Reporting Bugs & Feature Requests

Open an [issue](https://github.com/MetapriseAI/OrgKernel/issues) and use the appropriate template. Please include:

- A clear and descriptive title
- Steps to reproduce (for bugs)
- Expected vs. actual behavior
- Environment details (OS, Python version, PostgreSQL version)

### Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). We are committed to providing a welcoming and inclusive environment for everyone.

---

## License

OrgKernel is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full text.

> The trust foundation you depend on is fully open-source. Inspect every line, audit the cryptography, fork for your own infrastructure, and contribute improvements back to the community. No vendor lock-in, no black boxes.

---

<p align="center">
  Built by <a href="https://www.metaprise.ai">Metaprise</a> &nbsp;·&nbsp;
  <a href="https://www.trymetaprise.com/aura/orgkernel.html">Documentation</a> &nbsp;·&nbsp;
  <a href="https://github.com/MetapriseAI/OrgKernel/issues">Issues</a> &nbsp;·&nbsp;
  <a href="mailto:developer@metaprise.ai">Contact</a><br/>
  <sub>Python 3.12 · FastAPI · PostgreSQL 18.1</sub>
</p>
