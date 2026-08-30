---
kind: security
summary: Unknown/malformed account-admin mutations are denied, definePolicy/defineRoles reject fail-open definitions at definition time, and authorize()'s action lookup can no longer be reached through the prototype chain.
---

Six fail-open paths in a package whose purpose is fail-closed decisions over
host-supplied runtime data.

`evaluateAccountAdminMutation` branched on the three known mutation kinds with
no exhaustive default, so an unrecognized runtime value — a host bug, or a
stale client sending a kind that predates a schema change — fell through every
branch to `{ allowed: true }`. Unknown kinds are now denied with a new
`UNKNOWN_MUTATION_KIND` reason. That validation has since been hardened
further: a `null`/`undefined`/non-object `mutation` used to throw a
`TypeError` on `.kind` access instead of returning a decision, and a `kind`
INHERITED from a crafted prototype (e.g. `Object.create({ kind: 'delete' })`,
which has no own `kind` at all) used to read as a legitimate discriminator via
the prototype chain. Both now deny with `UNKNOWN_MUTATION_KIND` — the shape of
`mutation` (a non-null object with `kind` as an OWN string property) is
checked before its value is ever trusted.

`definePolicy` performed none of the definition-time validation its
documentation promised. Because `rank()` maps an unknown role to 0 and
`atLeast` compares `rank(actual) >= rank(min)`, an action whose `min` was not
a member of its ladder authorized *every* role on that ladder. Actions and
`superRole` are now validated against their configured ladders and throw at
definition time. That validation is itself only sound if `authorize()`'s
lookup agrees with it: `definePolicy` validates via `Object.entries`, which
sees only OWN properties, so `authorize()`'s action lookup is now own-
property-only too — an action reachable only through an inherited/polluted
prototype (`Object.create({ dangerous: { scope, min: 'wizard' } })`) is no
longer authorizable, closing the same fail-open one layer down.

`defineRoles` detected duplicates case-sensitively while `normalize()` matched
case-insensitively, and never checked alias keys against declared role names —
so aliasing `guest` to `admin` silently made the declared lowest role normalize
to `admin`. Roles and aliases are now built as one normalized namespace that
rejects collisions, with one exception applied consistently to both role- and
alias-collisions: an alias key that resolves to the SAME role already at that
slot (e.g. `{ GUEST: 'guest' }`, or two aliases agreeing on one target) is
redundant, not a conflict, and remains allowed — only a genuinely different
target (the shadowing/escalation shape) is rejected.
