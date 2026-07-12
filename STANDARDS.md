# Shared Package Standards

> **Canonical source:** `agent_brain/knowledge/shared-package-standards.md`.
> This file is a synced copy; change the canonical doc first.

This is a **TypeScript package**: source in `src/`, compiled with `tsc` to a
**committed** `dist/`. `main`/`types` point at `dist/`; the type gate is
`typecheck` + `build` + a dist-freshness check in CI. Zero runtime dependencies.

Distribution, versioning, branch protection, CI, and the release checklist follow
the canonical standard. Engineering standards that apply here:

1. **Superset of every consumer's copy.** This package must be at least as
   capable as mizen's `authorize()` (fail-closed, action-based, workspace
   + space role sets), cairn's org->project implicit role inheritance, and
   bewks's ordered `roleLevel`/`normalizeRole` ladder before any of them is
   migrated onto it — fail-closed normalization, a typed action policy, and
   explicit-table scope inheritance are table stakes, not extras.
2. **The kit decides, apps fetch. No store seam.** `defineRoles`,
   `definePolicy`/`authorize`, and `mapScopeRole` are pure functions over
   plain values — no ORM imports, no framework imports, no I/O, no
   `process.env` in the core. Several consumers deliberately re-read role
   rows from the database per request for security; this package never
   caches or fetches on their behalf, it only decides given what they hand
   it.
3. **Fail closed everywhere, never throw on the decision path.**
   `normalize` never throws — an unknown/null/undefined/non-string raw
   value is the LOWEST role. `authorize` never throws — a missing scoped
   role is `NOT_A_MEMBER`, an insufficient one is `INSUFFICIENT_ROLE`, an
   unknown action at runtime is denied. `mapScopeRole` never invents a
   role for an unrecognized parent — it returns the caller's fallback or
   `undefined`. Only `defineRoles`/`definePolicy` throw, and only at
   DEFINITION time, on genuine programmer errors (empty ladder, duplicate
   role, alias to an unknown target) — never on a runtime input value.
4. **Escalation is opt-in, off by default.** The `superRole` global-bypass
   on `definePolicy` (modeling cairn/sano-os/fidash's `isAdmin` bypass) only
   applies when a policy explicitly configures it — with no `superRole`,
   a global role never substitutes for a missing or insufficient scoped
   role. A policy that doesn't opt in fails closed by default.
5. **Types are a contract, tested.** `verify:pack` installs the tarball and
   resolves every export through both CJS and ESM. `definePolicy`'s action
   keys make an unknown action a compile error, asserted with a
   `@ts-expect-error` test in a file typechecked by
   `tsconfig.typecheck.json`.
6. **Uniform gates:** `test`, `verify:pack`, `typecheck` + `build` + dist freshness.
