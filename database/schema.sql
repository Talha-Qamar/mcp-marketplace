CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    bio TEXT,
    website TEXT,
    github_username TEXT,
    role TEXT DEFAULT 'publisher', -- publisher | admin
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    author_id TEXT NOT NULL,
    description TEXT,
    long_description TEXT,
    github_url TEXT,
    npm_package TEXT,
    language TEXT, -- python/typescript/go/rust/other
    hosting TEXT, -- local/remote/hybrid
    transport TEXT DEFAULT 'stdio', -- e.g. Streamable HTTP, stdio, SSE
    authentication TEXT DEFAULT 'None', -- e.g. OAuth, API Key, None
    license TEXT,
    version TEXT,
    stars INTEGER DEFAULT 0,
    forks INTEGER DEFAULT 0,
    install_count INTEGER DEFAULT 0,
    last_commit TEXT,
    category_id TEXT NOT NULL,
    security_status TEXT DEFAULT 'unverified', -- verified/unverified/flagged
    is_featured INTEGER DEFAULT 0,
    is_official INTEGER DEFAULT 0,
    -- Submission gate (spec §9.1). Only 'approved' (and pre-gate 'legacy') rows
    -- appear in the catalog: pending | in_review | approved | rejected | suspended | legacy
    listing_status TEXT DEFAULT 'legacy',
    source_json TEXT, -- where the code comes from: {kind: git|upload|local, ...}
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (author_id) REFERENCES users(id),
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

CREATE TABLE IF NOT EXISTS server_versions (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    version TEXT NOT NULL,
    changelog TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id)
);

CREATE TABLE IF NOT EXISTS tools (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    input_schema TEXT, -- JSON
    -- Implementation source of the tool function. This is what the AST taint
    -- analyzer parses; `description` is what Model A reads. One tool, two views.
    source_code TEXT,
    source_language TEXT, -- 'python' | 'typescript' | ...
    created_at TEXT NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id)
);

CREATE TABLE IF NOT EXISTS resources (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    uri_template TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id)
);

CREATE TABLE IF NOT EXISTS prompts (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    template TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id)
);

CREATE TABLE IF NOT EXISTS categories (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    icon TEXT,
    server_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tags (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_tags (
    server_id TEXT NOT NULL,
    tag_id TEXT NOT NULL,
    PRIMARY KEY(server_id, tag_id),
    FOREIGN KEY (server_id) REFERENCES servers(id),
    FOREIGN KEY (tag_id) REFERENCES tags(id)
);

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    website TEXT,
    logo_url TEXT,
    type TEXT,
    mcp_support TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS installs (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    user_id TEXT,
    client_type TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ============================================================
-- MCP Secure POC Layer — Tables (prefixed mcs_)
-- ============================================================

-- Stores scan records + embedded attestation JSON
CREATE TABLE IF NOT EXISTS mcs_scan_records (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    snapshot_json TEXT NOT NULL,
    analyzers_json TEXT NOT NULL,
    verdict TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    ruleset_hash TEXT NOT NULL,
    model_hashes_json TEXT,
    attestation_json TEXT,
    record_json TEXT, -- full ScanRecord: contract results, policy reasons, ingestion summary
    superseded INTEGER DEFAULT 0,
    is_external INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);

-- Transparency log leaves (append-only)
CREATE TABLE IF NOT EXISTS mcs_log_leaves (
    leaf_index INTEGER PRIMARY KEY,
    attestation_id TEXT NOT NULL,
    leaf_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Simulated on-chain anchor receipts
CREATE TABLE IF NOT EXISTS mcs_anchor_receipts (
    id TEXT PRIMARY KEY,
    root_hash TEXT NOT NULL,
    tx_hash TEXT NOT NULL,
    block_number INTEGER NOT NULL,
    block_timestamp TEXT NOT NULL,
    network TEXT NOT NULL DEFAULT 'SIMULATED_CHAIN',
    log_size_at_anchor INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);

-- Version watcher state per monitored server
CREATE TABLE IF NOT EXISTS mcs_watcher_rows (
    server_id TEXT PRIMARY KEY,
    watched_ref TEXT NOT NULL DEFAULT 'main',
    last_seen_sha TEXT,
    last_fingerprint TEXT,
    last_verdict TEXT,
    last_checked_at TEXT,
    status TEXT NOT NULL DEFAULT 'up_to_date',
    updated_at TEXT NOT NULL
);

-- External verification requests (Feature 4)
CREATE TABLE IF NOT EXISTS mcs_external_requests (
    id TEXT PRIMARY KEY,
    requester_name TEXT,
    candidate_ref TEXT NOT NULL,
    verdict TEXT,
    attestation_id TEXT,
    created_at TEXT NOT NULL
);

-- ============================================================
-- Submission gate (spec §9)
-- ============================================================

-- One row per submitted version. The row is also the scan job: the worker
-- picks up 'queued' rows, and rows left in 'ingesting'/'scanning' by a crash
-- are re-queued on start.
CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL,
    submitter_id TEXT NOT NULL,
    source_json TEXT NOT NULL,
    declared_tools_json TEXT,
    -- queued | ingesting | scanning | approved | in_review | rejected | failed | superseded
    state TEXT NOT NULL,
    verdict TEXT,
    scan_record_id TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(id)
);
CREATE INDEX IF NOT EXISTS idx_submissions_state ON submissions(state);
CREATE INDEX IF NOT EXISTS idx_submissions_server ON submissions(server_id);

-- Admin decisions on REVIEW verdicts. Stored, not yet signed or logged
-- (attestation of decisions is deferred with the blockchain work, spec §8).
CREATE TABLE IF NOT EXISTS review_decisions (
    id TEXT PRIMARY KEY,
    submission_id TEXT NOT NULL,
    scan_record_id TEXT,
    reviewer_id TEXT NOT NULL,
    decision TEXT NOT NULL, -- approve | reject
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);
