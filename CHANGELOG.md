# Changelog

## 0.2.0 — 2026-07-12

**BREAKING CHANGE.** `definePolicy` now takes a single options object with
PER-SCOPE `ladders`, instead of one shared role ladder for every scope. The
old positional signature `definePolicy(roles, actions, options)` is
REMOVED — there is no deprecated alias, no back-compat shim. `superRole` is
now `{ scope, min }` rather than a bare role string.

**Why.** Real consumers have DIFFERENT role vocabularies per scope — mizen's
`packages/authorization` has fully independent `WorkspaceRole`
(`OWNER`/`ADMIN`/`MEMBER`/`GUEST`) and `SpaceRole`
(`MANAGER`/`EDITOR`/`COMMENTER`/`VIEWER`) enums that never compare to each
other. Under 0.1.0, adopting this kit meant flattening both vocabularies
onto one shared ladder — awkward, and it let two unrelated role sets sit on
the same ordering by coincidence. In 0.2.0, `min` is type-constrained to the
ladder of the ACTION'S OWN scope (`{ scope: 'resource', min: 'OWNER' }` is a
compile error when the resource ladder has no `OWNER`), and cross-scope
isolation is now STRUCTURAL: a role normalized against one scope's ladder
can never satisfy a rule scoped to a different ladder.

Before (0.1.0):

```ts
const roles = defineRoles(['guest', 'member', 'admin', 'owner'] as const);
const policy = definePolicy(
  roles,
  { 'workspace.delete': { min: 'admin', scope: 'org' } },
  { superRole: 'admin' },
);
```

After (0.2.0), per-scope ladders:

```ts
const workspace = defineRoles(['GUEST', 'MEMBER', 'ADMIN', 'OWNER'] as const);
const space = defineRoles(['VIEWER', 'EDITOR', 'MANAGER'] as const);
const global = defineRoles(['user', 'admin'] as const);

const policy = definePolicy({
  ladders: { global, org: workspace, resource: space },
  actions: {
    'workspace.delete': { scope: 'org', min: 'OWNER' },
    'space.edit': { scope: 'resource', min: 'EDITOR' },
  },
  superRole: { scope: 'global', min: 'admin' }, // OPTIONAL — escalation stays OPT-IN
});
```

Simple, single-vocabulary apps (e.g. bewks) are NOT forced to write three
ladders — a single ladder is still accepted and normalizes internally to
`{global, org, resource}` all pointing at the same ladder:

```ts
const policy = definePolicy({ ladders: oneLadder, actions: { /* ... */ } });
```

Behavior preserved from 0.1.0, re-verified by test and by canary (break the
guard, confirm the specific test fails by name, restore, reconfirm green):
fail-closed everywhere (missing scoped role -> `NOT_A_MEMBER`, insufficient
role -> `INSUFFICIENT_ROLE`, unknown action at runtime -> denied, never
throws); `superRole` escalation stays strictly OPT-IN (omitted -> no
escalation at all); an unknown action key at `authorize()` call sites stays
a compile error. `defineRoles`, `mapScopeRole`, `createAllowlistRoleResolver`,
and `MEMBERSHIP_SCHEMA_SQL`/`MEMBERSHIP_SCHEMA_SQL_POSTGRES` are UNCHANGED.

- `ActionRule<L>` is now a scope-discriminated union keyed off the ladders
  actually configured in `L` — an action naming a scope with NO configured
  ladder is a compile error (not just a wrong-`min` error).
- `Decision`, `AuthzContext`, and `Scope` are unchanged in shape.
- New exports: `LadderMap`, `RoleOf<L>`, `SingleLadderPolicyOptions`.
- `src/__tests__/fixtures.mizen.test.ts` now ports mizen's `WorkspaceRole`
  and `SpaceRole` as TWO SEPARATE `defineRoles` ladders (previously merged
  onto one shared ladder) — this is the fixture that motivated the change,
  and it now asserts the cross-scope isolation directly: an org-only role
  can never satisfy a resource-scoped rule, and a value that's valid on the
  org ladder normalizes to the RESOURCE ladder's lowest when read as a
  resource role.

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
