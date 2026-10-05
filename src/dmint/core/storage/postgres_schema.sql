-- Dmint PostgreSQL Approval Store Schema
-- Mirrors the SQLite approval_records, store_policy, and store_recovery schemas.

CREATE TABLE IF NOT EXISTS approval_records (
    schema_version TEXT NOT NULL,
    approval_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    request_fingerprint TEXT NOT NULL,
    binding_version TEXT NOT NULL,
    canonicalization_profile TEXT NOT NULL,
    integration_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_kind TEXT NOT NULL CHECK (resource_kind IN ('none', 'value')),
    resource_value TEXT,
    arguments_json TEXT NOT NULL,
    trusted_context_json TEXT NOT NULL,
    policy_version_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    policy_evaluated_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN (
            'PENDING', 'APPROVED', 'REJECTED', 'CANCELLED',
            'EXPIRED', 'POLICY_INVALIDATED', 'CONSUMED'
        )
    ),
    state_at TEXT NOT NULL,
    decision_authority_id TEXT,
    decision_authority_subject TEXT,
    decision_authority_kind TEXT,
    decision_at TEXT,
    state_reason TEXT,
    consumed_at TEXT,
    deployment_epoch TEXT NOT NULL,
    record_checksum TEXT NOT NULL,
    CHECK (
        (resource_kind = 'none' AND resource_value IS NULL)
        OR
        (resource_kind = 'value' AND resource_value IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_approval_records_pending
    ON approval_records (state, expires_at)
    WHERE state = 'PENDING';

CREATE INDEX IF NOT EXISTS idx_approval_records_dedup
    ON approval_records (request_fingerprint, principal_id, integration_id, state, expires_at);

CREATE TABLE IF NOT EXISTS store_policy (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    rules_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS store_recovery (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    recovery_token TEXT NOT NULL,
    counter INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
