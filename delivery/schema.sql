-- D1: no credential plaintext, no recipient PII, no archive public URL.
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS grants (
  grant_id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash)=64),
  label TEXT NOT NULL,
  is_owner INTEGER NOT NULL DEFAULT 0 CHECK(is_owner IN (0,1)),
  expires_at INTEGER NOT NULL CHECK(expires_at>0),
  revoked_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS entitlements (
  grant_id TEXT NOT NULL REFERENCES grants(grant_id),
  app_id TEXT NOT NULL,
  channel TEXT NOT NULL CHECK(channel IN ('stable','qualification')),
  PRIMARY KEY(grant_id,app_id,channel)
);
CREATE TRIGGER IF NOT EXISTS qualification_owner_only BEFORE INSERT ON entitlements
WHEN NEW.channel='qualification' AND (SELECT is_owner FROM grants WHERE grant_id=NEW.grant_id) != 1
BEGIN SELECT RAISE(ABORT,'qualification requires owner'); END;
CREATE TABLE IF NOT EXISTS releases (
  app_id TEXT NOT NULL,
  release_id TEXT NOT NULL,
  channel TEXT NOT NULL CHECK(channel IN ('stable','qualification')),
  manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
  archive_sha256 TEXT NOT NULL CHECK(length(archive_sha256)=64),
  archive_size INTEGER NOT NULL CHECK(archive_size>0 AND archive_size<=536870912),
  object_key TEXT NOT NULL,
  qualification_id TEXT NOT NULL,
  evidence_json TEXT NOT NULL CHECK(json_valid(evidence_json)),
  PRIMARY KEY(app_id,release_id,channel)
);
CREATE TABLE IF NOT EXISTS channels (
  app_id TEXT NOT NULL,
  channel TEXT NOT NULL CHECK(channel IN ('stable','qualification')),
  release_id TEXT NOT NULL,
  PRIMARY KEY(app_id,channel),
  FOREIGN KEY(app_id,release_id,channel) REFERENCES releases(app_id,release_id,channel)
);
-- Release rows are append-only; channel pointers may advance after qualification.
CREATE TRIGGER IF NOT EXISTS release_immutable_update BEFORE UPDATE ON releases
BEGIN SELECT RAISE(ABORT,'immutable release'); END;
CREATE TRIGGER IF NOT EXISTS release_immutable_delete BEFORE DELETE ON releases
BEGIN SELECT RAISE(ABORT,'immutable release'); END;

-- Ordered parts are bound to app/release/kind/full-artifact hash and append-only.
CREATE TABLE IF NOT EXISTS artifact_parts (
  app_id TEXT NOT NULL,
  release_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('archive','package')),
  artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64),
  parts_json TEXT NOT NULL CHECK(json_valid(parts_json)),
  PRIMARY KEY(app_id,release_id,kind,artifact_sha256)
);
CREATE TRIGGER IF NOT EXISTS parts_immutable_update BEFORE UPDATE ON artifact_parts
BEGIN SELECT RAISE(ABORT,'immutable parts'); END;
CREATE TRIGGER IF NOT EXISTS parts_immutable_delete BEFORE DELETE ON artifact_parts
BEGIN SELECT RAISE(ABORT,'immutable parts'); END;
