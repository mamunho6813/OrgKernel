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
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?logo=python" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/FastAPI-supported-009688?logo=fastapi" alt="FastAPI" />
  <img src="https://img.shields.io/badge/PostgreSQL-supported-336791?logo=postgresql" alt="PostgreSQL" />
</p>

<p align="center">
  <b>3</b> Core Modules (Phase 1) &nbsp;·&nbsp; <b>27</b> REST Endpoints &nbsp;·&nbsp; <b>5</b> Build Phases &nbsp;·&nbsp; PostgreSQL / MySQL / SQLite Persistence
</p>

---

## Overview

**OrgKernel** is the security and governance foundation for the AI Agent system. It ensures every agent has a verifiable cryptographic identity, every mission operates within strict boundaries, and every action leaves a tamper-evident audit trail — all without a running AI model.

Phase 1 delivers the three cryptographic primitives. Phases 2–5 add mission lifecycle, policy engine, authority graph, and tool gateway.

| Capability | Status | Description |
|---|---|---|
| **Cryptographic Identity (PKI)** | ✅ Phase 1 | Ed25519 keypairs, Org CA signing, CSR, and challenge-response verification |
| **Scoped Execution Tokens** | ✅ Phase 1 | Mission-scoped permission tokens with tool allowlists, numeric parameter bounds, and Ed25519 signatures to prevent token grafting |
| **Hash-Chained Audit Trail** | ✅ Phase 1 | Three-layer audit (IDENTITY / EXECUTION / COMPLIANCE) persisted to PostgreSQL with SHA-256 hash chaining and integrity verification |
| **Mission Lifecycle** | 🔲 Phase 2 | 8-state mission state machine with enforced transitions |
| **Tool Gateway** | 🔲 Phase 3 | Token scope enforcement before every external tool call |
| **Policy Engine** | 🔲 Phase 3 | Declarative policy CRUD with version history and constraint derivation |
| **Authority Graph** | 🔲 Phase 3 | Org hierarchy traversal, approval level determination, spend authority resolution |
| **Data Classifier** | 🔲 Phase 3 | Rule-based data classification producing routing tiers and scope constraints |

---

## Build Phases

| Phase | Status | Scope |
|---|---|---|
| Phase 1 | ✅ Complete | Core primitives: Identity, Token, Audit |
| Phase 2 | 🔲 Planned | Mission lifecycle with state machine |
| Phase 3 | 🔲 Planned | Gateway, Policy, Authority, Classifier |
| Phase 4 | 🔲 Planned | Full DB persistence & version history |
| Phase 5 | 🔲 Planned | Optimization & Iteration |

---

## System Architecture

OrgKernel currently orchestrates three services (Phase 1). When Phases 2–5 are complete, the full flow will be: Mission Launch → Approval → Tool Execution → Close/Escalate, with every phase writing to a specific audit layer.

### Complete Flow — Five Phases (Phases 2–5 not yet implemented)

| Phase | Component(s) Called | Audit Layer | Key Behavior |
|---|---|---|---|
| **1 Mission Launch** *(Phase 1 available)* | `AgentIdentityService` | L1 Business | Validates agent identity before any operation |
| **2 State Transition** *(Phase 2 — planned)* | `MissionService.submit()` | L2 Execution | Mission enters approval queue |
| **3 Triple Review** *(Phase 3 — planned)* | `PolicyEngine` + `AuthorityGraph` + `DataClassifier` | L2 Execution | Constraints frozen into `MissionBoundary`. `ExecutionTokenService.mint()` issues signed token |
| **4 Tool Execution** *(Phase 3 — planned)* | `ToolGatewayService.validate_tool_call()` | L2 Execution | Five gateway checks on every call: token valid, CA signature correct, agent_id match, tool in scope, tool not forbidden |
| **5 Mission Close** *(Phase 2 — planned)* | `MissionService.close()` | L2 Execution | Token consumed, state → CLOSED |
| **6 Escalation** *(Phase 2 — planned)* | `MissionService.escalate()` | L3 Compliance | Only path to L3 audit layer |

### Three-Layer Audit Semantics (Phase 1)

| Audit Layer | Triggered By | Semantics |
|---|---|---|
| **L1 Business** | `AuditChainService.initialize()` | Business perspective: who, in which org, for which mission |
| **L2 Execution** | Every tool call + state transition + approval + close | Execution perspective: every behavior the system performed |
| **L3 Compliance** | Only `MissionService.escalate()` (Phase 2) | Compliance perspective: what triggered human compliance intervention |

### Architecture Diagram (Phase 1)

```
Agent Platform
    |
    |-- CSR submitted --> AgentIdentityService.submit_csr()
    |                      |-- validates duplicate
    |                      v
    |-- CSR issued -----> AgentIdentityService.issue_from_csr()
    |                      |-- generates Ed25519 keypair (server-side)
    |                      |-- signs certificate with Org CA
    |                      |-- returns certificate + private_key_pem ONCE
    |                      |-- persists identity record (NO private key)
    |                      v
    |                  AgentCertificate + AgentIdentity
    |
    |-- token mint ----> ExecutionTokenService.mint()
    |                      |-- Ed25519-signed by Org CA (prevents Token Grafting)
    |                      |-- tool allowlist + numeric bounds
    |                      v
    |                  ExecutionToken
    |
    |-- scope check ---> ExecutionTokenService.check_scope()
    |                      |-- tool in scope?
    |                      |-- bounded params within limits?
    |                      v
    |                  ScopeCheckResponse (ALLOWED or BLOCKED)
    |
    |-- audit init ----> AuditChainService.initialize()
    |                      |-- writes genesis IDENTITY entry (SHA-256)
    |                      v
    |-- audit append ---> AuditChainService.append()
    |                      |-- SHA-256 prev_hash chain
    |                      v
    |-- audit verify ---> AuditChainService.verify_integrity()
                           |-- recomputes all hashes
                           |-- detects deletion / tampering / reorder
```

### Challenge-Response Authentication (Phase 1)

| Step | Party | Action |
|---|---|---|
| 1 | Verifier | Calls `AgentIdentityService.request_challenge(agent_id, issued_by)` — generates random nonce + `challenge_id`, stored in memory with 5-minute TTL |
| 2 | Verifier → Agent | Sends nonce to the target Agent |
| 3 | Agent | Signs the nonce with its Ed25519 private key, constructs `ChallengeResponse(challenge_id, nonce, public_key, signature)` |
| 4 | Verifier | Calls `AgentIdentityService.verify_challenge(response)` — validates: nonce one-time use (anti-replay), Ed25519 signature correct, certificate ACTIVE and not expired |

**Attack vectors prevented:** Replay attack (nonce consumed after one use), private key theft (signature must match nonce), Token Grafting (`token.agent_id == caller.agent_id` verified at every scope check).

---

## Core Modules

### Module 01 — Agent Identity ✅ Phase 1

PKI lifecycle management for AI agents. Generates Ed25519 keypairs, issues certificates signed by an Org CA, and manages the full revoke / suspend / reactivate lifecycle.

**Tags:** `Ed25519` `CSR` `Challenge-Response` `Revocation`

### Module 02 — Execution Token ✅ Phase 1

Scoped, time-bounded permission tokens for mission execution. Each token carries a tool allowlist, numeric parameter bounds, and an Ed25519 signature to prevent token grafting attacks.

**Tags:** `Tool Scope` `Bounded Params` `Ed25519 Sig` `Expiry`

### Module 03 — Mission Lifecycle 🔲 Phase 2

8-state mission state machine: `CREATED → PLANNING → WAITING_APPROVAL → APPROVED → PENDING_EXECUTION → IN_PROGRESS → EXECUTED → CLOSED`. Materializes boundaries at approval time.

**Tags:** `8 States` `State Transitions` `Boundary Snapshot` `REST API`

### Module 04 — Tool Gateway 🔲 Phase 3

Enforces token scope before every external tool call. Validates the token signature, checks tool in scope, verifies bounded params, and writes execution audit entries. Prevents Token Grafting attacks at runtime.

**Tags:** `Scope Guard` `Token Grafting Prevention` `Param Bounds` `ALLOWED/BLOCKED/PARTIAL`

### Module 05 — Policy Engine 🔲 Phase 3

Declarative policy CRUD with version history and audit trail. Evaluates rules at mission approval time to derive forbidden tools, time restrictions, spend limits, and dual-approval requirements.

**Tags:** `Policy CRUD` `Version History` `Rule Evaluation` `6 Policy Types`

### Module 06 — Authority Graph 🔲 Phase 3

Org hierarchy traversal and approval level resolution. Maps agents to org units, determines L0-L5 approval requirements, builds multi-step approval chains, and resolves spend authority for mission authorization.

**Tags:** `Org Hierarchy` `L0-L5 Approval` `Spend Authority` `Approval Chain`

### Module 07 — Data Classifier 🔲 Phase 3

Classifies data sources accessed by a mission's tools using rule-based classification. Produces a routing classification (PUBLIC to TOP_SECRET) and data scope constraints for the `MissionBoundary`.

**Tags:** `5 Tiers` `5 Scopes` `Rule Engine` `Data Constraints`

### Module 08 — Audit Chain ✅ Phase 1

Three-layer, hash-chained audit logging persisted to the database. Each layer (IDENTITY, EXECUTION, COMPLIANCE) maintains its own SHA-256 hash chain with integrity verification. REST API exposes chain query and cryptographic integrity checks.

**Tags:** `3 Audit Layers` `SHA-256 Chain` `Integrity Verify` `REST API`

---

## Mission 8-State Lifecycle 🔲 Phase 2 (planned)

Every mission follows this state machine once Phase 2 is implemented. Invalid transitions raise `InvalidStateTransitionError`. All transitions are audited via the L2 Execution layer.

### Valid Transitions

| From State | Allowed Transitions | How It Happens |
|---|---|---|
| `CREATED` | → `PLANNING` | Only path — set by `launch()` internally |
| `PLANNING` | → `WAITING_APPROVAL` or → `APPROVED` | `submit()` goes to `WAITING_APPROVAL`; L0 agents can self-approve → `APPROVED` directly |
| `WAITING_APPROVAL` | → `APPROVED` or → `CLOSED` | `approve()` → `APPROVED`; `reject()` or `close(CANCELLED)` → `CLOSED` |
| `APPROVED` | → `PENDING_EXECUTION` or → `IN_PROGRESS` | `start_execution()` skips queue → `IN_PROGRESS` directly; otherwise → `PENDING_EXECUTION` |
| `PENDING_EXECUTION` | → `IN_PROGRESS` or → `WAITING_APPROVAL` or → `CLOSED` | Normal start → `IN_PROGRESS`; rollback → `WAITING_APPROVAL`; `close(CANCELLED)` → `CLOSED` |
| `IN_PROGRESS` | → `EXECUTED` or → `WAITING_APPROVAL` or → `CLOSED` | `complete_execution()` → `EXECUTED`; rollback → `WAITING_APPROVAL`; `close()` or `escalate()` → `CLOSED` |
| `EXECUTED` | → `CLOSED` | Only path — `close()` with `SUCCESS` or `FAILED` |
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
Only escalate() writes L3 Compliance — all other CLOSE writes L2
```

---

## Security Model

### Token Grafting Prevention

The Execution Token is Ed25519-signed by the Org CA covering the full payload (scope, bounds, expiry). Any modification invalidates the signature. The scope check verifies `token.agent_id == caller.agent_id` on every call.

### Challenge-Response Authentication

Agents prove identity via Ed25519 challenge-response with one-time nonces. Certificates are verified against the Org CA's public key. Revocation and expiry are enforced at verification time.

### Tamper-Evident Audit Chain

Every audit entry carries a SHA-256 hash of its content and a `prev_hash` linking to the previous entry. The integrity API recomputes all hashes and detects any deleted, modified, or reordered entries.

### Audit Chain Integrity Checks

| Check | Detects |
|---|---|
| Hash present | Hash stripped by attacker |
| Sequence continuity (IDs increment by 1) | Entry deletion |
| `prev_hash` linkage | Entry modification or reordering |
| Content hash match (stored == recomputed SHA-256) | Entry content tampering |

---

## Quick Start

### Install

Requires Python 3.10+. From a local checkout:

```bash
cd /path/to/orgkernel
pip install -e ".[postgres]"   # postgres | mysql | sqlite
```

Database driver extras:
- `pip install orgkernel[postgres]` — PostgreSQL (recommended)
- `pip install orgkernel[mysql]` — MySQL / MariaDB
- `pip install orgkernel[sqlite]` — SQLite for local dev

### Service layer

Direct Python async — no HTTP, no API key.

```python
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession

from orgkernel.database import async_engine, init_db, get_session_factory
from orgkernel.services import AgentIdentityService, ExecutionTokenService, AuditChainService
from orgkernel.schemas import AgentIdentityCSR, ExecutionTokenCreate, ScopeCheckRequest, AuditLayer


async def demo(db: AsyncSession) -> None:
    # Configure database
    async_engine.url = "postgresql+asyncpg://user:pass@localhost:5432/orgkernel"
    await init_db()

    identity_svc = AgentIdentityService(db)
    token_svc    = ExecutionTokenService(db)
    audit_svc    = AuditChainService()

    # 1. Issue agent identity (CSR flow)
    csr = AgentIdentityCSR(
        agent_name="invoice-processor",
        org_id="acme-corp",
        requested_ou="finance_team",
        public_key="<agent-ed25519-public-key-base64url>",
        purpose="automated-invoice-processing",
    )
    issued = await identity_svc.issue_from_csr(csr)
    print(f"Agent ID: {issued.identity.agent_id}")       # → "aid_7f3k9..."
    print(f"Private key (returned once): {issued.agent_private_key_pem[:30]}..."

    # 2. Mint scoped execution token (Ed25519-signed by Org CA)
    token = await token_svc.mint(
        ExecutionTokenCreate(
            agent_id=issued.identity.agent_id,
            mission_id="msn_invoice01",
            execution_scope=["read_invoice", "write_payment_draft"],
            immutable_params={"currency": "USD"},
            bounded_params=[{"name": "amount", "upper_bound": 50000}],
            expires_at=datetime.now(timezone.utc) + timedelta(hours=4),
        )
    )
    print(f"Token: {token.token_id}")   # → "tok_abc123..."
    print(f"Signed: {token.token_signature[:20]}...")

    # 3. Enforce scope before every tool call
    allowed = await token_svc.check_scope(
        ScopeCheckRequest(
            token_id=token.token_id,
            tool_name="read_invoice",
            params={"invoice_id": "4521"},
        )
    )
    print(f"Scope check passed: {allowed.passed}")  # → True

    # 4. Initialize audit chain (writes genesis IDENTITY entry)
    chain_id = await audit_svc.initialize(
        db,
        mission_id="msn_invoice01",
        agent_id=issued.identity.agent_id,
    )

    # 5. Append audit entries
    await audit_svc.append(
        db,
        chain_id=chain_id,
        layer=AuditLayer.EXECUTION,
        event="EXECUTION_tool_call",
        agent_id=issued.identity.agent_id,
        mission_id="msn_invoice01",
        data={"tool": "read_invoice", "invoice_id": "4521", "result": "success", "duration_ms": 230},
        token_id=token.token_id,
    )

    # 6. Verify audit integrity
    assert await audit_svc.verify_integrity(db, chain_id) is True

    await db.commit()
```

### FastAPI integration

Mount the built-in HTTP router for 27 REST endpoints across identity, token, and audit.

```python
from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from orgkernel.database import async_engine, get_session_factory, init_db
from orgkernel.pyapi.router import router

app = FastAPI(title="Agent Platform powered by OrgKernel")


@app.on_event("startup")
async def startup() -> None:
    async_engine.url = "postgresql+asyncpg://user:pass@localhost:5432/orgkernel"
    await init_db()


async def get_db() -> AsyncSession:
    factory = get_session_factory(async_engine)
    async with factory() as session:
        yield session


app.include_router(router, prefix="/orgkernel", get_db=get_db)
# All 27 endpoints under /orgkernel/...
```

---

## REST API Reference

All endpoints are prefixed `/orgkernel`. No API key — the server is your own infrastructure.

### Endpoint overview

| Method | Path | Description |
|---|---|---|
| `POST` | `/orgkernel/identity/csr/submit` | Submit CSR (step 1 of PKI lifecycle) |
| `POST` | `/orgkernel/identity/issue` | Issue identity from CSR (step 2–3) |
| `GET` | `/orgkernel/identity/{agent_id}` | Get identity by ID |
| `GET` | `/orgkernel/identity/{agent_id}/certificate` | Get signed certificate |
| `POST` | `/orgkernel/identity/verify` | Static verification (status + expiry) |
| `POST` | `/orgkernel/identity/challenge/request` | Request cryptographic challenge |
| `POST` | `/orgkernel/identity/challenge/verify` | Verify signed challenge |
| `POST` | `/orgkernel/identity/{agent_id}/suspend` | Suspend identity |
| `POST` | `/orgkernel/identity/{agent_id}/reactivate` | Reactivate suspended identity |
| `POST` | `/orgkernel/identity/{agent_id}/revoke` | Permanently revoke identity |
| `GET` | `/orgkernel/identity/org/{org_id}` | List all identities for an org |
| `GET` | `/orgkernel/identity/org/{org_id}/page` | Paginated list by org |
| `POST` | `/orgkernel/token/mint` | Mint a scoped, time-bounded token |
| `GET` | `/orgkernel/token/{token_id}` | Get token by ID |
| `POST` | `/orgkernel/token/scope/check` | Validate a tool call against token scope |
| `POST` | `/orgkernel/token/{token_id}/use` | Mark token as consumed |
| `POST` | `/orgkernel/token/{token_id}/invalidate` | Early invalidation with reason |
| `GET` | `/orgkernel/token/mission/{mission_id}/active` | Get active token for a mission |
| `GET` | `/orgkernel/token/mission/{mission_id}/page` | Paginated tokens by mission |
| `GET` | `/orgkernel/token/agent/{agent_id}/page` | Paginated tokens by agent |
| `POST` | `/orgkernel/audit/initialize` | Initialize a new AuditChain |
| `POST` | `/orgkernel/audit/{chain_id}/append` | Append an audit entry |
| `POST` | `/orgkernel/audit/{chain_id}/close` | Close an AuditChain |
| `GET` | `/orgkernel/audit/mission/{mission_id}` | Get AuditChain by mission_id |
| `GET` | `/orgkernel/audit/{chain_id}` | Get AuditChain by chain_id |
| `GET` | `/orgkernel/audit/{chain_id}/verify` | Verify chain integrity |
| `GET` | `/orgkernel/audit/agent/{agent_id}/page` | Paginated chains by agent |

### curl examples

```bash
BASE="http://localhost:8000/orgkernel"

# 1. Submit CSR and issue identity
curl -X POST "$BASE/identity/csr/submit" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "compliance-agent",
    "org_id": "acme-corp",
    "requested_ou": "legal/compliance",
    "public_key": "<agent-ed25519-public-key-base64url>",
    "purpose": "policy-audit"
  }'

curl -X POST "$BASE/identity/issue" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "compliance-agent",
    "org_id": "acme-corp",
    "requested_ou": "legal/compliance",
    "public_key": "<agent-ed25519-public-key-base64url>",
    "purpose": "policy-audit"
  }'

# 2. Mint an ExecutionToken
curl -X POST "$BASE/token/mint" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "aid_7f3k9...",
    "mission_id": "msn_audit01",
    "execution_scope": ["doc_reader", "email_sender"],
    "expires_at": "2026-03-26T12:00:00Z"
  }'

# 3. Enforce scope on every tool call
curl -X POST "$BASE/token/scope/check" \
  -H "Content-Type: application/json" \
  -d '{
    "token_id": "tok_abc123...",
    "tool_name": "doc_reader",
    "params": {"doc_id": "POL-001"}
  }'
# → {"passed": true, "blocked": false, ...}

# 4. Initialize AuditChain
curl -X POST "$BASE/audit/initialize" \
  -H "Content-Type: application/json" \
  -d '{
    "mission_id": "msn_audit01",
    "agent_id": "aid_7f3k9..."
  }'
# → {"chain_id": "ac_xyz...", "message": "AuditChain initialized"}

# 5. Append audit entry
curl -X POST "$BASE/audit/ac_xyz.../append" \
  -H "Content-Type: application/json" \
  -d '{
    "layer": "EXECUTION",
    "event": "EXECUTION_tool_call",
    "agent_id": "aid_7f3k9...",
    "mission_id": "msn_audit01",
    "data": {"tool": "doc_reader", "doc_id": "POL-001", "result": "success"},
    "token_id": "tok_abc123..."
  }'

# 6. Verify AuditChain integrity
curl "$BASE/audit/ac_xyz.../verify"
# → {"chain_id": "ac_xyz...", "valid": true, "message": "Integrity check passed"}

# 7. Get all identities for an org
curl "$BASE/identity/org/acme-corp"

# 8. Paginated tokens by mission
curl "$BASE/token/mission/msn_audit01/page?page_no=1&page_size=20"

# 9. Get full AuditChain
curl "$BASE/audit/mission/msn_audit01"
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

### MissionBoundary 🔲 Phase 2–3 (planned)

| Field | Source |
|---|---|
| `authority_constraints` | `AuthorityGraphService.resolve_authority()` |
| `policy_constraints` | `PolicyEngineService.evaluate_for_mission()` |
| `data_constraints` | `DataClassifierService.classify_for_mission()` |
| `runtime_constraints` | MissionDefinition + PolicyEngine `max_tool_calls` |
| `authority_graph_version` | Snapshot version of authority graph at approval |
| `policy_engine_version` | Snapshot version of policy engine at approval |

### Audit Chain — Three-Layer Hash Chain (Phase 1)

| Layer | Triggered By | Content |
|---|---|---|
| **L1 Business** | `AuditChainService.initialize()` | Mission objective, org, agent_id |
| **L2 Execution** | `AuditChainService.append()` + state transitions + tool calls | Tool name, params, status, violations |
| **L3 Compliance** | Only `MissionService.escalate()` (Phase 2) | Escalation reason, escalated_to, from_state |

### Enums

```
AgentIdentityStatus:  ACTIVE | SUSPENDED | REVOKED | EXPIRED

MissionState:         CREATED | PLANNING | WAITING_APPROVAL | APPROVED |   ← Phase 2
                      PENDING_EXECUTION | IN_PROGRESS | EXECUTED | CLOSED

ApprovalLevel:         L0 (no approval) | L1 (self) | L2 (team) |         ← Phase 3
                       L3 (department) | L4 (executive) | L5 (board/C-level)

ClassificationTier:    PUBLIC | INTERNAL | CONFIDENTIAL | SECRET | TOP_SECRET  ← Phase 3

PolicyType:            TOOL_RESTRICTION | DATA_ACCESS | RATE_LIMIT |          ← Phase 3
                       SPEND_LIMIT | TIME_RESTRICTION | CUSTOM
```

---

## Contributing

We welcome contributions from the community. OrgKernel is the cryptographic trust foundation of an enterprise agent platform — quality and security are paramount.

### How to Contribute

1. **Fork** the repository and create your branch from `main`
2. **Write tests** for any new functionality
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
- Environment details (OS, Python version, database version)

### Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). We are committed to providing a welcoming and inclusive environment for everyone.

---

## License

OrgKernel is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full text.

> The trust foundation you depend on is fully open-source. Inspect every line, audit the cryptography, fork for your own infrastructure, and contribute improvements back to the community. No vendor lock-in, no black boxes.

---

<p align="center">
  Built by <a href="https://www.metaprise.ai">Metaprise</a> &nbsp;·&nbsp;
  <a href="https://github.com/MetapriseAI/OrgKernel/issues">Issues</a> &nbsp;·&nbsp;
  <a href="mailto:developer@metaprise.ai">Contact</a><br/>
  <sub>Python 3.10+ · FastAPI · SQLAlchemy Async · PostgreSQL / MySQL / SQLite</sub>
</p>
