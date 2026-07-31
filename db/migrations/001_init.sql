-- ============================================================================
--  IFT542 — Student Registration  |  Migration 001: initial schema
--  Deliberately-vulnerable teaching artefact. Fictitious data only.
--
--  NOTE ON PASSWORD STORAGE: the `credentials` table stores passwords in
--  PLAINTEXT on purpose. [VULN: Plaintext passwords — Task 2]  This is one of
--  the planted vulnerabilities and must remain until the hardening session.
-- ============================================================================

-- Idempotent reset so `npm run db:reset` can be re-run freely during the demo.
DROP TABLE IF EXISTS sessions   CASCADE;
DROP TABLE IF EXISTS uploads    CASCADE;
DROP TABLE IF EXISTS enrolments CASCADE;
DROP TABLE IF EXISTS credentials CASCADE;
DROP TABLE IF EXISTS courses    CASCADE;
DROP TABLE IF EXISTS profiles   CASCADE;

-- Students and admins.
CREATE TABLE profiles (
  id           SERIAL PRIMARY KEY,
  email        TEXT NOT NULL UNIQUE,
  role         TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin')),
  display_name TEXT NOT NULL DEFAULT '',
  bio          TEXT NOT NULL DEFAULT '',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- "Password storage" table — separate from profiles, keyed by profile_id.
-- [VULN: Plaintext passwords — Task 2] `password` column holds the raw password.
CREATE TABLE credentials (
  profile_id INTEGER PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
  password   TEXT NOT NULL              -- PLAINTEXT on purpose (Task 2 vuln)
);

-- Catalogue of courses.
CREATE TABLE courses (
  id          SERIAL PRIMARY KEY,
  code        TEXT NOT NULL UNIQUE,
  title       TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  capacity    INTEGER NOT NULL DEFAULT 30,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Student <-> course enrolments.
CREATE TABLE enrolments (
  id         SERIAL PRIMARY KEY,
  profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  course_id  INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (profile_id, course_id)
);

-- Uploaded documents. The file itself lives on local disk (./uploads);
-- this table records metadata + the on-disk path.
CREATE TABLE uploads (
  id            SERIAL PRIMARY KEY,
  profile_id    INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  stored_name   TEXT NOT NULL,
  original_name TEXT NOT NULL,
  mime          TEXT NOT NULL DEFAULT '',
  size          INTEGER NOT NULL DEFAULT 0,
  path          TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Server-side session store for the custom cookie-session auth.
-- The cookie carries `sid` = sessions.id (a UUID).
CREATE TABLE sessions (
  id         UUID PRIMARY KEY,
  profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_enrolments_profile ON enrolments(profile_id);
CREATE INDEX idx_enrolments_course  ON enrolments(course_id);
CREATE INDEX idx_uploads_profile    ON uploads(profile_id);
CREATE INDEX idx_sessions_profile   ON sessions(profile_id);
