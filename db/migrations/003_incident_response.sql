-- ============================================================================
--  IFT542 — Migration 003: incident-response schema
--  [DELIVERED — Task 3 item 26: corrective controls]
--
--  The risk register (report/task1-threat-model.md §3) promised four CORRECTIVE
--  controls that the hardening tasks never actually built. This migration adds
--  the two tables they need; the commands themselves live in ir/.
--
--    T5  forced reset on suspected breach  ->  credential_resets
--    T4  append-only retention             ->  security_events
--
--  T1 (session revocation) and T9 (invalidate sessions on leak) need no new
--  schema — they operate on the existing `sessions` table.
-- ============================================================================


-- ---------------------------------------------------------------------------
--  credential_resets — "this account is locked pending a credential reset"
-- ---------------------------------------------------------------------------
--  WHY A TABLE AND NOT A COLUMN ON `credentials`:
--    1. tests/password-storage.test.ts asserts that `credentials` has exactly
--       the columns (profile_id, password_hash). That assertion is Task 2
--       evidence — "the plaintext column is gone" — so adding a third column
--       would weaken the proof to make room for this feature.
--    2. There is no sentinel value available either: password_hash is NOT NULL
--       with CHECK (password_hash LIKE '$argon2id$%').
--    3. A row records WHY and UNDER WHICH INCIDENT the lock was applied, and
--       clearing it is an auditable DELETE rather than a silent UPDATE.
--
--  DROP + CREATE, not CREATE IF NOT EXISTS: 001_init.sql runs
--  DROP TABLE profiles CASCADE on every migrate, which would silently strip
--  this table's foreign key and leave it orphaned but present.
DROP TABLE IF EXISTS credential_resets CASCADE;

CREATE TABLE credential_resets (
  profile_id  INTEGER PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
  required_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  incident_id TEXT        NOT NULL,
  reason      TEXT        NOT NULL DEFAULT 'suspected-credential-compromise',
  required_by TEXT        NOT NULL DEFAULT 'unknown-operator'
);

COMMENT ON TABLE credential_resets IS
  'Presence of a row locks the account: src/app/api/login/route.ts refuses the '
  'login even when the password is correct. Removed by ir/force-reset.mjs --complete.';


-- ---------------------------------------------------------------------------
--  security_events — append-only audit sink  (T4: unattributable actions)
-- ---------------------------------------------------------------------------
--  CREATE IF NOT EXISTS with NO DROP, deliberately: surviving a wipe is what
--  "retention" means. `npm run db:reset` re-seeds the application tables and
--  leaves this one intact.
--
--  NO FOREIGN KEY on actor_profile_id, also deliberately: an audit record must
--  outlive its subject. ON DELETE CASCADE would mean that deleting a profile
--  erases that profile's audit trail — which is exactly the repudiation threat
--  (T4) rebuilt inside the control meant to close it.
CREATE TABLE IF NOT EXISTS security_events (
  id               BIGSERIAL PRIMARY KEY,
  occurred_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  event            TEXT        NOT NULL,          -- e.g. auth.login.failed, ir.sessions.revoked
  level            TEXT        NOT NULL DEFAULT 'info',
  outcome          TEXT        NOT NULL DEFAULT '',
  actor_profile_id INTEGER,                       -- no FK, on purpose (see above)
  actor_email      TEXT,                          -- ALREADY MASKED by src/lib/logger.ts
  actor_ip         TEXT,
  incident_id      TEXT,
  detail           JSONB       NOT NULL DEFAULT '{}'::jsonb,
  ingested_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_security_events_occurred ON security_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_event    ON security_events(event);
CREATE INDEX IF NOT EXISTS idx_security_events_incident ON security_events(incident_id);

COMMENT ON TABLE security_events IS
  'Append-only. INSERT is permitted; UPDATE, DELETE and TRUNCATE raise 42501 '
  'via the statement-level triggers below. Verify with: npm run ir:audit-log -- --verify';

COMMENT ON COLUMN security_events.actor_email IS
  'Masked at source by src/lib/logger.ts (a***@campus.local). Never a full address.';


-- ---------------------------------------------------------------------------
--  Append-only enforcement
-- ---------------------------------------------------------------------------
--  A trigger rather than REVOKE, because the application connects as the table
--  OWNER (user `ift542`), and an owner's privileges cannot be revoked from
--  themselves in any way that survives — the owner can always GRANT them back.
--  A trigger fires regardless of who is asking, including the owner and
--  including a superuser.
--
--  FOR EACH STATEMENT, not FOR EACH ROW. A row-level BEFORE DELETE trigger
--  never fires when zero rows match, so `DELETE FROM security_events WHERE
--  id = -1` would succeed silently and a test asserting "DELETE is refused"
--  against an empty table would pass vacuously. The statement-level trigger
--  fires on the attempt. (TRUNCATE only supports statement-level anyway.)
CREATE OR REPLACE FUNCTION security_events_append_only() RETURNS TRIGGER AS $fn$
BEGIN
  RAISE EXCEPTION
    'security_events is append-only; % is not permitted (incident-response control T4)', TG_OP
    USING ERRCODE = 'insufficient_privilege',      -- SQLSTATE 42501
          HINT    = 'Records may be added but never altered or removed. See report/response-runbook.md.';
  RETURN NULL;
END;
$fn$ LANGUAGE plpgsql;

-- Two triggers because TRUNCATE cannot share a trigger definition with
-- UPDATE/DELETE: it is a statement-level-only event and Postgres rejects
-- mixing it with row-level-capable events in one CREATE TRIGGER.
DROP TRIGGER IF EXISTS security_events_no_change   ON security_events;
DROP TRIGGER IF EXISTS security_events_no_truncate ON security_events;

CREATE TRIGGER security_events_no_change
  BEFORE UPDATE OR DELETE ON security_events
  FOR EACH STATEMENT EXECUTE FUNCTION security_events_append_only();

CREATE TRIGGER security_events_no_truncate
  BEFORE TRUNCATE ON security_events
  FOR EACH STATEMENT EXECUTE FUNCTION security_events_append_only();
