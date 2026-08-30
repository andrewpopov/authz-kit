# @andrewpopov/authz-kit

Pure authorization primitives: an ordered role ladder with fail-closed
normalization, a typed action policy with an `authorize()` decision, and
two-tier scope-role inheritance. ORM- and framework-agnostic — **apps fetch
roles, the kit decides.**

## The core principle: no store seam

Several consumer apps deliberately re-read role rows from the database on
every request, for security. This package never fights that: it has **no**
store port, no caching, no I/O. `defineRoles`, `definePolicy`/`authorize`,
and `mapScopeRole` are pure functions over plain values you already have in
hand — a raw role string from a DB row, a JWT claim, wherever. You fetch;
the kit decides.

## `defineRoles`: an ordered ladder, fail-closed normalization

```ts
import { defineRoles } from '@andrewpopov/authz-kit';

const roles = defineRoles(['guest', 'member', 'admin', 'owner'] as const, {
  aliases: { USER: 'member', moderator: 'member' },
});

roles.normalize('OWNER'); // 'owner'
roles.normalize('wizard'); // 'guest' — unknown value, fails closed to LOWEST
roles.normalize(null); // 'guest'
roles.atLeast('admin', 'member'); // true
roles.rank('owner'); // 3
```

The ladder is declared **lowest -> highest**. `normalize` is the one choke
point every raw role value should pass through: any value it can't map to a
known role or alias — `null`, `undefined`, `''`, an unrecognized string, a
number, an object — resolves to the **lowest** role. It never throws.
Aliases are matched case-insensitively after trim+lowercase, and that
normalization happens at DEFINITION time on the alias keys, so `{ USER:
'member' }` and `{ user: 'member' }` behave identically.

`defineRoles` throws at DEFINITION time (not on a runtime value) for an
empty ladder, a case-insensitive duplicate role, an alias whose target
isn't in the ladder, or an alias key that collides with a declared role
name or a conflicting alias AND resolves to a DIFFERENT role than the one
already at that slot — roles and aliases share ONE normalized,
case-insensitive namespace, so none of these can silently shadow another
entry at `normalize()` time. A collision that resolves to the SAME role
(e.g. `{ GUEST: 'guest' }` alongside a declared `guest` role, or two
aliases that agree on one target) is redundant but harmless, so it does
NOT throw. Those are all programmer errors caught immediately, not
something a bad database row should ever trigger.

## `definePolicy` + `authorize`: a typed action policy, per-scope ladders

Real consumers have DIFFERENT role vocabularies per scope — mizen's
`packages/authorization` has fully independent `WorkspaceRole` and
`SpaceRole` enums that never compare to each other. `definePolicy` takes a
LADDER PER SCOPE, and each action's `min` is type-constrained to the ladder
of THAT action's scope:

```ts
import { defineRoles, definePolicy, authorize } from '@andrewpopov/authz-kit';

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

authorize(policy, 'space.edit', { roles: { resource: 'editor' } });
// { allowed: true, role: 'EDITOR', via: 'resource' }

authorize(policy, 'space.edit', { roles: {} });
// { allowed: false, reason: 'NOT_A_MEMBER' }

// { scope: 'resource', min: 'OWNER' } is a TYPE ERROR — the resource
// ladder has no 'OWNER'; 'min' is constrained to the ladder of that
// action's OWN scope.
//
// An action naming a scope with no configured ladder (e.g. { scope:
// 'resource', ... } when `ladders` only has `org`) is also a TYPE ERROR.
//
// authorize(policy, 'not.a.real.action', ...) is a TYPE ERROR — the action
// keys are typed, like defineFlags's registry keys.
```

`Scope` is `'global' | 'org' | 'resource'`; every `ActionRule` now names its
own scope explicitly (no default). Because `min` is plain `string` data at
runtime, `definePolicy` also validates it at DEFINITION time, not just at
the type level: an action naming a scope with no configured ladder, or a
`min` that isn't an actual member of that scope's ladder, throws
immediately. This matters because a config- or type-system-bypassed `min`
that isn't a real ladder entry would otherwise rank as `0` at
`authorize()` time — the LOWEST possible rank — which makes `atLeast()`
true for every real role on that ladder, a fail-open. `superRole` (if
given) is validated the same way. That definition-time validation only
sees `actions`' OWN properties (it walks them with `Object.entries`), so
`authorize()`'s action lookup is deliberately OWN-property-only too — an
action reachable only through an inherited/prototype-polluted `actions`
object is never authorizable, keeping validation and lookup in agreement
regardless of how `policy.actions` was built. `authorize` evaluates the
rule's scope, pulls that scope's role out of `context.roles`, normalizes
it against THAT
SCOPE'S OWN ladder, and returns a `Decision`:

- `{ allowed: true, role, via: scope }`
- `{ allowed: false, reason: 'NOT_A_MEMBER' | 'INSUFFICIENT_ROLE' }`

### Single-ladder shorthand: keep simple apps simple

Apps with ONE shared role vocabulary (e.g. bewks) don't have to write the
same ladder out three times — pass a single `RoleLadder` and it's applied to
`global`, `org`, and `resource` internally:

```ts
const roles = defineRoles(['guest', 'member', 'admin', 'owner'] as const);

const policy = definePolicy({
  ladders: roles, // shorthand for { global: roles, org: roles, resource: roles }
  actions: {
    'library.manage': { min: 'admin', scope: 'org' },
    'book.request': { min: 'member', scope: 'resource' },
  },
});
```

### Cross-scope isolation is structural

Because `min` is constrained to (and normalized against) the ladder
configured for that specific scope, a role that's valid on one ladder can
NEVER accidentally satisfy a rule scoped to a different ladder — even if the
two ladders happen to share a role name. An org-only role with no resource
role present always resolves `NOT_A_MEMBER` on a resource-scoped rule, and a
value that's a real role on one ladder normalizes to the OTHER ladder's
LOWEST role when read through it, exactly like any other unrecognized
string.

## FAIL-CLOSED semantics (read this before adopting)

- **Missing scoped role -> `NOT_A_MEMBER`.** If `context.roles[scope]` is
  absent, `null`, or `undefined`, the decision is `NOT_A_MEMBER` — never an
  allow, never a throw. This is mizen's "fails closed when not a member"
  behavior, ported directly (see the mizen fixture test).
- **Insufficient role -> `INSUFFICIENT_ROLE`.** A present-but-too-low role
  (after normalization) denies with `INSUFFICIENT_ROLE`.
- **Unknown role string -> treated as the lowest role.** `authorize`
  normalizes before comparing, so a garbage role value can only ever match
  rules whose `min` is the lowest role — it can never accidentally pass a
  higher bar.
- **Unknown action at runtime -> denied, never throws.** The action key is
  a compile-time type error to get wrong, but a dynamically-dispatched
  action name that slips past the type system still resolves to
  `{ allowed: false, reason: 'INSUFFICIENT_ROLE' }`, never an allow and
  never an exception.
- **`normalize`/`mapScopeRole` never throw on a runtime value.** Only
  `defineRoles`/`definePolicy` throw, and only at definition time on
  genuine programmer errors.

## Global escalation: `superRole: { scope, min }` (opt-in, off by default)

```ts
const policy = definePolicy({
  ladders: roles,
  actions: { 'item.delete': { min: 'admin', scope: 'resource' } },
  superRole: { scope: 'global', min: 'admin' },
});

authorize(policy, 'item.delete', { roles: { global: 'admin' } });
// { allowed: true, role: 'admin', via: 'global' } — no resource role needed

// Without `superRole` configured on the policy, the identical call is DENIED:
// { allowed: false, reason: 'NOT_A_MEMBER' }
```

`superRole` names WHICH scope's ladder grants escalation — a role in
`context.roles[superRole.scope]` that is `atLeast(superRole.min)` (per that
scope's OWN ladder) is allowed **any** action regardless of the scoped role
the rule actually asks for. This models cairn/sano-os/fidash's `isAdmin`
bypass. It is **strictly opt-in**: a policy that doesn't set `superRole` has
no escalation path at all, full stop. `superRole.scope` is typically
`'global'`, but it can name any configured scope.

## `mapScopeRole`: two-tier scope inheritance

```ts
import { mapScopeRole } from '@andrewpopov/authz-kit';

// mizen's defaultSpaceRole(): OWNER/ADMIN -> MANAGER, MEMBER -> EDITOR, else VIEWER.
function defaultSpaceRole(workspaceRole: unknown) {
  return mapScopeRole(workspaceRole, { OWNER: 'MANAGER', ADMIN: 'MANAGER', MEMBER: 'EDITOR' }, { fallback: 'VIEWER' });
}

// cairn's org -> project inheritance: OWNER/ADMIN -> ADMIN, MEMBER -> MEMBER, else no implicit role.
function impliedProjectRole(orgRole: unknown) {
  return mapScopeRole(orgRole, { OWNER: 'ADMIN', ADMIN: 'ADMIN', MEMBER: 'MEMBER' });
}
```

A pure explicit-table lookup — a parent-scope role (org/workspace) maps to
an implied child-scope role (project/space). An unrecognized or absent
parent role resolves to `options.fallback` if you gave one, else
`undefined` (i.e. **not a member** — it never invents a role for a parent
role it doesn't recognize).

## `createAllowlistRoleResolver`: env-allowlist admin bootstrap

An env-var admin-email allowlist ("if this email is in `ADMIN_EMAILS`,
treat them as admin") has been hand-rolled independently at least four
times across the fleet (sano-os's admin-email helper, smarthome's
`auth.service.ts` role re-sync on every login, rouge's
`ROGUE_SIM_ADMIN_EMAILS` simulator bootstrap, savoro's
`auth.service.ts`). `createAllowlistRoleResolver` is a behavioral superset
of all four, as a pure function:

```ts
import { createAllowlistRoleResolver } from '@andrewpopov/authz-kit';

const resolver = createAllowlistRoleResolver({
  ladder: roles, // a RoleLadder from defineRoles()
  adminEmails: process.env.ADMIN_EMAILS ?? '', // raw env string OR string[] — injected, never read internally
  adminRole: 'admin',
  defaultRole: 'member',
  neverElevate: ['guest'], // rouge's guard: these roles are NEVER elevated, allowlisted or not
});

resolver.isAllowlisted('ADMIN@example.com'); // true — matched trim+lowercase
resolver.resolve('admin@example.com', storedRole); // 'admin' if allowlisted
```

`resolve(email, currentRole?)` semantics, in order, FAIL CLOSED throughout:

1. **`neverElevate` guard (rouge's real behavior).** If the normalized
   `currentRole` is one of `neverElevate`, it is returned UNCHANGED —
   allowlisted or not. This is rouge's hard-won guest guard
   (`start-static.js`, `ROGUE_SIM_ADMIN_EMAILS`): a guest account must
   never be silently elevated just because its email happens to match the
   allowlist.
2. **Allowlisted -> `adminRole`.**
3. **Not allowlisted -> demotion-safe fallback.** The resolver returns the
   HIGHER of `defaultRole` and the normalized `currentRole` — never the
   bare `defaultRole`. This is the demotion-safety property: an app that
   stores a genuinely granted role (e.g. `owner`, set by an invite flow)
   is never silently demoted back to `defaultRole` just because that
   user's email isn't (or is no longer) on the allowlist.

`isAllowlisted(email)` fails closed on a `null`/`undefined`/empty/
non-string `email` — always `false`. `adminEmails` accepts either a raw
env string (split on comma/semicolon/whitespace, empty entries ignored)
or a pre-split array; the kit never reads `process.env` itself — you
inject the value.

## Account-admin mutation policy

User-management services across the fleet share a security-critical policy
layer even though their database schemas, role names, session tables, and
deletion semantics differ. `defineAccountAdminPolicy` and
`evaluateAccountAdminMutation` extract only that pure layer.

The package does **not** fetch users, start transactions, update rows, revoke
tokens, send invitations, write audit records, or delete domain content. An
app loads authoritative facts, asks the policy for a decision, then performs
the approved work in its own transaction. A policy result's
`effects.invalidateCredentials` tells the app when an effective role change,
active-to-inactive transition, or deletion must invalidate its access and
refresh credentials; the app supplies the actual invalidation implementation.

```ts
import {
  defineRoles,
  defineAccountAdminPolicy,
  evaluateAccountAdminMutation,
} from '@andrewpopov/authz-kit';

const roles = defineRoles(['user', 'admin', 'owner'] as const);
const accountAdmin = defineAccountAdminPolicy({
  roles,
  statuses: ['active', 'deactivated'] as const,
  activeStatuses: ['active'] as const,
  isProtectedRole: (role) => role === 'owner',
  canManageTarget: ({ actorRole, targetRole }) => actorRole === 'owner' || targetRole === 'user',
  canAssignRole: ({ actorRole, nextRole }) => actorRole === 'owner' || nextRole === 'user',
});

// Load these facts inside the app's transaction. The count excludes the
// target and must be authoritative when removing an active protected account.
const decision = evaluateAccountAdminMutation(accountAdmin, {
  actorId: actor.id,
  actorRole: actor.role,
  target: { id: target.id, role: target.role, status: target.status },
  mutation: { kind: 'set-status', status: 'deactivated' },
  activeProtectedPeerCount: otherActiveOwners,
});

if (!decision.allowed) throw new Error(decision.reason);
if (decision.outcome === 'no-op') return;

await transaction(async (tx) => {
  // Re-read/re-evaluate in tx if any supplied fact can race.
  await disableUser(tx, target.id);
  if (decision.effects.invalidateCredentials) await revokeCredentials(tx, target.id);
  await writeAudit(tx, actor.id, target.id);
});
```

The policy fails closed for an unknown actor role, target role, target status,
proposed role/status, or mutation kind. `mutation` is validated by SHAPE
before its VALUE is ever trusted, then EXHAUSTIVELY on that value: a `null`,
`undefined`, or non-object `mutation`, a `kind` that isn't an OWN string
property (so a `kind` inherited from a crafted/polluted prototype is never
trusted), or a recognized-shape-but-unknown `kind` value (a host bug, a stale
client, a mutation shape from a future schema version) — all of these deny
with `UNKNOWN_MUTATION_KIND`, and `evaluateAccountAdminMutation` never throws
on any of them. Unlike ordinary authorization normalization, an unknown
stored role cannot be treated as the lowest role and accidentally made safe
to modify: `RoleLadder.isKnown(raw)` distinguishes a real declared role or
alias from a value that merely normalizes to the lowest role.

Built-in protections are configurable but default to enabled:

- self role reduction, self deactivation, and self deletion deny;
- application-provided target and role-assignment authority must allow;
- removing an active protected account requires an explicit count of other
  active protected accounts and denies at zero;
- an unchanged role/status is an allowed `no-op` with no credential effect.

The source fixtures cover Savoro's active-owner invariant, Smarthome's
role-change invalidation/no-op behavior, Sano OS and Cairn self-protection,
and Bewks's privileged-target guard. Keep Savoro's pantry purge plan,
Bewks's invite/email behavior, Sano OS's Google grant revocation, and each
application's transaction and audit implementation local — those are domain
policies, not a common account protocol.

## The canonical `memberships` shape, and "apps own their migrations"

`src/schema.ts` exports raw-SQL DDL constants — `MEMBERSHIP_SCHEMA_SQL`
(SQLite) and `MEMBERSHIP_SCHEMA_SQL_POSTGRES` (Postgres) — for a canonical
membership table apps can run in their OWN migration:

```
memberships(
  scope_type TEXT NOT NULL,      -- e.g. 'org' | 'workspace' | 'project' | 'space' | 'list'
  scope_id   TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  role       TEXT NOT NULL,
  created_at ...,
  PRIMARY KEY (scope_type, scope_id, user_id)
)  + INDEX on (user_id)
```

Both constants use `CREATE TABLE IF NOT EXISTS` and are safe to run
idempotently. They differ only in `created_at`: the SQLite variant
defaults to a text ISO-8601 timestamp via `datetime('now')`; the Postgres
variant (mizen and budget are Postgres) uses `TIMESTAMPTZ NOT NULL DEFAULT
now()`.

**This is exactly feature-flags-kit's stance, ported here**:
`FEATURE_FLAGS_SCHEMA_SQL` never auto-creates its table, and neither does
this kit — **the kit never creates or migrates a table; the app owns its
migrations, explicitly, in its own migration tool.** These constants exist
to be copied into (or run as) that migration, not to be executed by the
kit on the app's behalf.

### Why there's deliberately no `users` table

`schema.ts` intentionally does **not** export a `users` (or `accounts`)
table. Every consuming app's user model differs irreconcilably — bewks
has TOTP columns, savoro stores Notion OAuth credentials, rouge keys
identity on `googleId`, budget mirrors a Clerk-managed user. Any one
canonical shape would fit none of them exactly and would invite exactly
the kind of parallel-special-case sprawl this kit exists to avoid. The
kit only needs to be told **a role** for a `(scope, user)` pair — it never
needs to own, shape, or migrate the user row itself. Apps keep their own
`users` table and just point `user_id` at it.

## `templates/membership.prisma`: a copy-once template, not a dependency

For Prisma-based apps, `templates/membership.prisma` renders the same
`memberships` shape as a Prisma model (`model Membership`, `@@id([scopeType,
scopeId, userId])`, `@@index([userId])`). It ships in the package tarball
(`files: ["dist", "templates"]`) but is **never imported by the package
and never part of `dist`** — it is a **copy-once template**: paste it into
your own `schema.prisma`, extend it freely, and own your migrations
forever from that point on. Prisma has no schema-import mechanism, so
there is **no automatic upgrade path** — future changes to this template
ship as CHANGELOG-documented diffs in this package that you apply to your
own copy by hand, if and when you want them.

## Adoption note: replacing a hand-rolled ladder

If you're migrating an app off a hand-rolled role check (a `switch`, a
`Set.has()`, an inline ladder) onto `defineRoles`/`authorize`, **first run
every raw role value that's actually stored today through the new
`normalize`/`authorize` and assert access is unchanged**, before flipping
any code over. A normalizer that treats an existing stored value even
slightly differently than the old code — a case difference, a legacy alias
the new ladder doesn't know about, a fallback direction — silently demotes
or elevates real users' access, and your test suite can stay green the
whole time because a fresh test fixture doesn't know what's actually
sitting in your database. See `src/__tests__/stored-value-regression.test.ts`
for the pattern (and the analogous `auth-kit` `preHash` lockout incident in
this author's memory notes — same failure shape, different subsystem).

## API

| Export | Purpose |
|---|---|
| `defineRoles(ladder, options?)` | Ordered role ladder; `normalize`/`atLeast`/`rank`, fail-closed to the lowest role. |
| `definePolicy({ ladders, actions, superRole? })` | Typed action policy over PER-SCOPE ladders (or one ladder via the single-ladder shorthand); an unknown action key, an unconfigured-scope action, or an out-of-ladder `min` are all compile errors, and also throw at DEFINITION time as a runtime backstop (a scope with no ladder, or a `min`/`superRole` not actually a member of its ladder). |
| `authorize(policy, action, context)` | Pure decision: `{allowed:true, role, via}` or `{allowed:false, reason}`. |
| `mapScopeRole(parentRole, table, options?)` | Pure parent-role -> child-role lookup for scope inheritance. |
| `createAllowlistRoleResolver(options)` | Pure, fail-closed env-allowlist admin bootstrap; `resolve`/`isAllowlisted`. |
| `MEMBERSHIP_SCHEMA_SQL` / `MEMBERSHIP_SCHEMA_SQL_POSTGRES` | Raw-SQL DDL for the canonical `memberships` shape — apps own their migrations. |

`RoleLadder`: `{ roles, lowest, highest, normalize, atLeast, rank }`.
`LadderMap`: `Partial<{ global: RoleLadder<...>; org: RoleLadder<...>; resource: RoleLadder<...> }>` — which scopes a policy configures, and the ladder each one uses.
`ActionRule<L>`: `{ scope, min }`, scope-discriminated so `min` is constrained to the ladder configured for that `scope`.
`Decision`: `{allowed:true; role: string; via: Scope} \| {allowed:false; reason: 'NOT_A_MEMBER' | 'INSUFFICIENT_ROLE'}`.
`Scope`: `'global' | 'org' | 'resource'`.
`AllowlistRoleResolver`: `{ resolve(email, currentRole?), isAllowlisted(email) }`.

## Install

```
npm install github:andrewpopov/authz-kit#v0.3.2
```

## Standards

Read the [security model](./SECURITY.md) before using a role ladder in a
security-sensitive route or migration.

## Verify locally

```bash
npm ci
npm run verify
```

See [`STANDARDS.md`](./STANDARDS.md) (synced from `agent_brain/knowledge/shared-package-standards.md`).

## Project policies

See [Contributing](./CONTRIBUTING.md), [Support](./SUPPORT.md), and the
[Security Policy](./SECURITY.md). This package is licensed under [MIT](./LICENSE).
