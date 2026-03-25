"""
OrgKernel — Open-source enterprise trust layer for AI agents.

Three cryptographic primitives:
    AgentIdentity   — cryptographic organizational credential
    ExecutionToken  — scoped, time-bounded execution permission
    AuditChain      — append-only, hash-chained execution log

Quick start::

    from orgkernel.database import async_engine, init_db, get_session_factory
    from orgkernel.services import AgentIdentityService, ExecutionTokenService, AuditChainService
    from orgkernel.schemas import AgentIdentityCreate, ExecutionTokenCreate, AuditLayer

    # Initialize database
    async_engine.url = "postgresql+asyncpg://user:pass@localhost:5432/orgkernel"
    await init_db()

    # Use services
    factory = get_session_factory(async_engine)
    async with factory() as db:
        identity_svc = AgentIdentityService(db)
        ...

Canonical schemas are in schemas/.
Models are in models.py.
Database utilities are in database.py.
"""

from orgkernel.schemas import (
    AgentCertificate,
    AgentIdentity,
    AgentIdentityCreate,
    AgentIdentityCSR,
    AgentIdentityIssueResult,
    AgentIdentityOut,
    AgentIdentityRevoke,
    AgentIdentityStatus,
    AgentIdentityVerify,
    AgentIdentityVerifyResponse,
    ChallengeRequest,
    ChallengeResponse,
    ChallengeVerificationResult,
    BoundedParam,
    ExecutionToken,
    ExecutionTokenCreate,
    ExecutionTokenOut,
    ScopeCheckRequest,
    ScopeCheckResponse,
    ScopeCheckResult,
    AuditChain,
    AuditEntry,
    AuditLayer,
)

__version__ = "1.0.0"

__all__ = [
    # Version
    "__version__",
    # AgentIdentity
    "AgentIdentity",
    "AgentIdentityStatus",
    "AgentCertificate",
    "AgentIdentityCSR",
    "ChallengeRequest",
    "ChallengeResponse",
    "ChallengeVerificationResult",
    "AgentIdentityCreate",
    "AgentIdentityIssueResult",
    "AgentIdentityOut",
    "AgentIdentityRevoke",
    "AgentIdentityVerify",
    "AgentIdentityVerifyResponse",
    # ExecutionToken
    "ExecutionToken",
    "BoundedParam",
    "ScopeCheckResult",
    "ExecutionTokenCreate",
    "ExecutionTokenOut",
    "ScopeCheckRequest",
    "ScopeCheckResponse",
    # AuditChain
    "AuditChain",
    "AuditEntry",
    "AuditLayer",
]
