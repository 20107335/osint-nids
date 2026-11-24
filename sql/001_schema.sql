-- OSINT-NIDS schema v1

-- One row per unique indicator
CREATE TABLE IF NOT EXISTS iocs (
    id          BIGSERIAL PRIMARY KEY,
    value       TEXT NOT NULL,
    ioc_type    TEXT NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'url')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (value, ioc_type)
);

-- Where each IOC came from and what that source says about it
CREATE TABLE IF NOT EXISTS ioc_sources (
    id             BIGSERIAL PRIMARY KEY,
    ioc_id         BIGINT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    source         TEXT NOT NULL,
    label          TEXT NOT NULL CHECK (label IN ('malicious', 'benign')),
    category       TEXT,
    first_seen     TIMESTAMPTZ,
    snapshot_date  DATE,
    UNIQUE (ioc_id, source)
);

-- Cached OSINT API responses
CREATE TABLE IF NOT EXISTS enrichment_cache (
    id           BIGSERIAL PRIMARY KEY,
    ioc_id       BIGINT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL,
    queried_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    http_status  INTEGER,
    response     JSONB
);
CREATE INDEX IF NOT EXISTS idx_enrich_lookup
    ON enrichment_cache (ioc_id, provider, queried_at DESC);

-- Log of every feed download
CREATE TABLE IF NOT EXISTS snapshots (
    id           BIGSERIAL PRIMARY KEY,
    feed         TEXT NOT NULL,
    taken_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    file_path    TEXT,
    bytes        BIGINT,
    status       TEXT NOT NULL,
    rows_loaded  INTEGER,
    error        TEXT
);