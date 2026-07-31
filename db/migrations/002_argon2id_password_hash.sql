-- ============================================================================
--  IFT542 — Migration 002: Argon2id password hashes
--  [FIXED — Task 2: plaintext passwords]
--
--  Replaces the plaintext `credentials.password` column (001_init.sql:30-33)
--  with `password_hash`, holding an Argon2id PHC string.
--
--  SQL cannot compute an Argon2id digest, so this file only prepares the
--  schema. The actual re-hashing, the DROP of the legacy column, the NOT NULL
--  and the CHECK constraint are applied by db/hash-passwords.mjs, which
--  db/migrate.mjs runs AFTER db/seed.sql. (The migration runner applies every
--  migrations/*.sql before the seed, so post-seed DDL cannot live here.)
-- ============================================================================

-- Nullable for now: the legacy backfill needs somewhere to write, and the
-- fresh path needs to insert digest-only rows. Made NOT NULL by the JS step.
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS password_hash TEXT;

-- The legacy plaintext column becomes OPTIONAL so that digest-only inserts do
-- not trip its NOT NULL. It is dropped entirely by db/hash-passwords.mjs once
-- every row has been hashed.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'credentials' AND column_name = 'password'
  ) THEN
    ALTER TABLE credentials ALTER COLUMN password DROP NOT NULL;
  END IF;
END $$;
