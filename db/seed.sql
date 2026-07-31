-- ============================================================================
--  IFT542 — Student Registration  |  Seed data
--  ALL DATA IS FICTITIOUS. Invented names, @campus.local addresses, no PII.
--
--  Passwords are seeded in PLAINTEXT because the schema stores them that way
--  on purpose. [VULN: Plaintext passwords — Task 2]
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

-- ---- Credentials (PLAINTEXT, fictitious) ----------------------------------
INSERT INTO credentials (profile_id, password)
SELECT id, CASE email
  WHEN 'ada.learner@campus.local'  THEN 'ada-pw-2025'
  WHEN 'grace.coder@campus.local'  THEN 'grace-pw-2025'
  WHEN 'linus.pupil@campus.local'  THEN 'linus-pw-2025'
  WHEN 'mira.scholar@campus.local' THEN 'mira-pw-2025'
  WHEN 'otto.student@campus.local' THEN 'otto-pw-2025'
  WHEN 'nova.trainee@campus.local' THEN 'nova-pw-2025'
  WHEN 'admin@campus.local'        THEN 'admin123'   -- well-known default (Task 3 vuln)
END
FROM profiles;

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
