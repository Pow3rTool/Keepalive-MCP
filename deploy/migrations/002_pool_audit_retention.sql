-- Keep machine-generated SSH pool telemetry cheap to prune even after the
-- human-attributed audit trail has accumulated for years. The application deletes
-- only `pool-*` rows older than KA_POOL_AUDIT_RETENTION_DAYS (30 by default);
-- every other audit verb is retained indefinitely.
CREATE INDEX IF NOT EXISTS idx_audit_pool_ts
    ON audit (ts)
    WHERE verb LIKE 'pool-%';

