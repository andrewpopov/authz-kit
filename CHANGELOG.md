# Changelog

## 0.1.0 — 2026-07-12

Initial release. Pure authorization primitives, a behavioral superset of
mizen's `packages/authorization` `authorize()`, cairn's org->project
implicit role inheritance, and bewks's `roleLevel`/`normalizeRole` ladder.

- `defineRoles(ladder, options?)`: build an ORDERED role ladder (lowest ->
  highest). Returns `normalize`, `atLeast`, `rank`, `roles`, `lowest`,
  `highest`. `normalize` FAILS CLOSED — any unknown/null/undefined/empty/
  non-string raw value resolves to the LOWEST role, never throws. Aliases
  (`{ USER: 'member' }`) are matched case-insensitively after trim+lowercase,
  normalized at definition time so `USER`/`user`/`' User '` behave
  identically. Throws at definition time on an empty ladder, a duplicate
  role, or an alias targeting a role not in the ladder.
- `definePolicy(roles, actions, options?)` + `authorize(policy, action,
  context)`: a typed action policy (an unknown action key elsewhere is a
  compile error) and a pure `Decision` — `{allowed:true, role, via}` or
  `{allowed:false, reason: 'NOT_A_MEMBER' | 'INSUFFICIENT_ROLE'}`. Fails
  closed everywhere: a missing/null/undefined scoped role is
  `NOT_A_MEMBER`; an insufficient one is `INSUFFICIENT_ROLE`; an unknown
  action at runtime is denied, never throws. `ActionRule.scope` defaults to
  `'resource'`.
- Global escalation (`superRole` on `definePolicy`, OPT-IN): a `global`
  role at least `superRole` is allowed ANY action regardless of scoped
  role, reporting `via: 'global'`. With no `superRole` configured, there is
  NO escalation — models cairn/sano-os/fidash's `isAdmin` bypass, but only
  for apps that opt in.
- `mapScopeRole(parentRole, table, options?)`: pure two-tier scope-role
  inheritance lookup (e.g. org role -> implied project role). An
  unrecognized/absent parent role resolves to `options.fallback` if given,
  else `undefined` (NOT a member) — never invents a role. Reproduces
  mizen's `defaultSpaceRole()` and cairn's `getMemberRole` org->project
  inheritance exactly (see test fixtures).
- The kit is PURE and has NO store seam: apps fetch their own role rows and
  hand them to `authorize`/`normalize`/`mapScopeRole` as plain values — no
  I/O, no ORM imports, no framework imports, no `process.env` in the core.
- Stored-value regression fixture: a table of raw role values actually
  found in the fleet (`'GUEST'`, `'USER'`, `'user'`, `'admin'`, `'owner'`,
  `'moderator'`, `'LIBRARIAN'`, `null`, `''`) asserts the exact effective
  role for a given ladder+aliases — the preHash-lockout analog for role
  values, so a migration onto this kit can't silently change access.
- `createAllowlistRoleResolver(options)`: a pure, fail-closed env-allowlist
  admin bootstrap, unifying four independently hand-rolled fleet copies
  (sano-os's admin-email helper, smarthome's `auth.service.ts` role
  re-sync-on-login, rouge's `ROGUE_SIM_ADMIN_EMAILS` guest guard, savoro's
  `auth.service.ts`). `adminEmails` is injected (raw env string or
  array) — the kit never reads `process.env`. `resolve(email,
  currentRole?)` matches email case-insensitively after trim, honors an
  opt-in `neverElevate` list so a role like `guest` is never elevated by
  the allowlist (rouge's guard), and is demotion-safe: a non-allowlisted
  user's stored role is never lowered below itself, only ever raised to
  `defaultRole` if it was lower.
- `MEMBERSHIP_SCHEMA_SQL` / `MEMBERSHIP_SCHEMA_SQL_POSTGRES`: raw-SQL DDL
  constants for the canonical `memberships(scope_type, scope_id, user_id,
  role, created_at)` shape, PK `(scope_type, scope_id, user_id)`, indexed
  on `user_id`. Same stance as feature-flags-kit's
  `FEATURE_FLAGS_SCHEMA_SQL`: the kit never creates or migrates a table,
  apps own their migrations. Deliberately no `users` table — every
  consumer app's user model differs irreconcilably.
- `templates/membership.prisma`: a copy-once Prisma rendering of the same
  shape, shipped in the tarball's `templates/` dir (not imported by the
  package, not in `dist`). Paste it into your schema and own it from
  there — Prisma has no schema import mechanism, so template changes ship
  as CHANGELOG diffs you apply by hand.
