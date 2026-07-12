/**
 * Canonical `memberships` shape, shipped as raw-SQL DDL constants — NOT an
 * ORM adapter, NOT auto-applied. The kit NEVER creates or migrates a
 * table; the app owns its migrations (same stance as feature-flags-kit's
 * `FEATURE_FLAGS_SCHEMA_SQL`: use this as, or adapt it into, the app's own
 * migration).
 *
 * Deliberately NO `users` table: every app's user model differs
 * irreconcilably (bewks has TOTP columns, savoro has Notion creds, rouge
 * keys on `googleId`, budget mirrors Clerk). The kit only needs to be told
 * a role for a (scope, user) pair — it never needs to own or shape the
 * user row itself.
 *
 * Shape:
 *   memberships(scope_type, scope_id, user_id, role, created_at)
 *   PRIMARY KEY (scope_type, scope_id, user_id)
 *   INDEX on (user_id)  -- "which scopes is this user a member of"
 */

/** SQLite-compatible DDL. `created_at` defaults to an ISO-8601 text timestamp via `datetime('now')`. */
export const MEMBERSHIP_SCHEMA_SQL = `CREATE TABLE IF NOT EXISTS memberships (
  scope_type TEXT NOT NULL,
  scope_id   TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  role       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (scope_type, scope_id, user_id)
);
CREATE INDEX IF NOT EXISTS memberships_user_id_idx ON memberships (user_id);`;

/** Postgres DDL. `created_at` is `TIMESTAMPTZ` defaulting to `now()`. */
export const MEMBERSHIP_SCHEMA_SQL_POSTGRES = `CREATE TABLE IF NOT EXISTS memberships (
  scope_type TEXT NOT NULL,
  scope_id   TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  role       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (scope_type, scope_id, user_id)
);
CREATE INDEX IF NOT EXISTS memberships_user_id_idx ON memberships (user_id);`;
