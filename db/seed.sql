-- ============================================================================
--  IFT542 — Student Registration  |  Seed data
--  ALL DATA IS FICTITIOUS. Invented names, @campus.local addresses, no PII.
--
--  [FIXED — Task 2] Passwords are no longer seeded here at all; they are
--  hashed with Argon2id by db/hash-passwords.mjs. See the Credentials section
--  below.
--
--  [VULN: Default admin with well-known password — Task 3]
--    admin@campus.local / admin123
-- ============================================================================

-- Clear existing rows (safe to re-run).
TRUNCATE sessions, uploads, enrolments, credentials, courses, profiles RESTART IDENTITY CASCADE;

-- ---- Profiles (6 students + 1 admin) --------------------------------------
INSERT INTO profiles (email, role, display_name, bio) VALUES
  ('ada.learner@campus.local',   'student', 'Ada Learner',    'First-year, likes graph theory.'),
  ('grace.coder@campus.local',   'student', 'Grace Coder',    'Enjoys compilers and long walks.'),
  ('linus.pupil@campus.local',   'student', 'Linus Pupil',    'Runs everything on the terminal.'),
  ('mira.scholar@campus.local',  'student', 'Mira Scholar',   'Robotics club treasurer.'),
  ('otto.student@campus.local',  'student', 'Otto Student',   'Wants to build databases.'),
  ('nova.trainee@campus.local',  'student', 'Nova Trainee',   'Into security and CTFs.'),
  ('admin@campus.local',         'admin',   'Campus Admin',   'Registration office administrator.');

-- ---- Credentials ----------------------------------------------------------
-- [FIXED — Task 2] Passwords are NO LONGER seeded here.
--
-- SQL cannot compute an Argon2id digest, and inserting plaintext — even
-- transiently — would defeat the fix. The credentials are hashed and inserted
-- by db/hash-passwords.mjs, which db/migrate.mjs runs immediately after this
-- file. The demo passwords themselves are unchanged and are documented in
-- README.md and in db/hash-passwords.mjs (DEMO_PASSWORDS).

-- ---- Courses (5) ----------------------------------------------------------
INSERT INTO courses (code, title, description, capacity) VALUES
  ('IFT101', 'Introduction to Computing',        'Foundations of computing and problem solving.', 40),
  ('IFT203', 'Data Structures & Algorithms',     'Core data structures and algorithmic analysis.', 35),
  ('IFT305', 'Database Systems',                 'Relational modelling, SQL, and transactions.',   30),
  ('IFT404', 'Web Application Development',       'Building modern web applications.',              30),
  ('IFT505', 'Web Security',                     'Common web vulnerabilities and defences.',       25);

-- ---- Enrolments (a handful) -----------------------------------------------
INSERT INTO enrolments (profile_id, course_id)
SELECT p.id, c.id FROM profiles p, courses c
WHERE (p.email = 'ada.learner@campus.local'  AND c.code IN ('IFT101', 'IFT203'))
   OR (p.email = 'grace.coder@campus.local'  AND c.code IN ('IFT203', 'IFT305'))
   OR (p.email = 'linus.pupil@campus.local'  AND c.code IN ('IFT101'))
   OR (p.email = 'nova.trainee@campus.local' AND c.code IN ('IFT505', 'IFT404'))
   OR (p.email = 'mira.scholar@campus.local' AND c.code IN ('IFT404'));
