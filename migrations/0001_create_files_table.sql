-- Migration: Create files metadata table
CREATE TABLE IF NOT EXISTS files (
    file_key TEXT PRIMARY KEY,
    original_name TEXT NOT NULL,
    expire_at INTEGER NOT NULL,
    max_downloads INTEGER NOT NULL,
    download_count INTEGER DEFAULT 0,
    version_salt TEXT NOT NULL,
    is_one_time INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    created_at INTEGER NOT NULL,
    delete_after INTEGER
);

-- Indices for performance on Cron and cleanups
CREATE INDEX IF NOT EXISTS idx_files_expire_at ON files(expire_at);
CREATE INDEX IF NOT EXISTS idx_files_status ON files(status);
CREATE INDEX IF NOT EXISTS idx_files_delete_after ON files(delete_after);
