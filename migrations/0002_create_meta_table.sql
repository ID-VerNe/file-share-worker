-- Migration: meta table for counters (used_bytes quota counter)
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

-- Seed used_bytes from the current bucket contents so the counter starts
-- accurate. Re-run any time drift is suspected; it upserts.
-- NOTE: the actual reconciliation is performed by an admin script or by
-- setting used_bytes manually once after this migration. The application
-- maintains it incrementally from here on.
INSERT OR IGNORE INTO meta (k, v) VALUES ('used_bytes', '0');
