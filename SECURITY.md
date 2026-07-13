# Security model

`@andrewpopov/authz-kit` is a pure policy evaluator. It does not authenticate
users, load memberships, protect routes, or persist role changes.

## Package guarantees

- Unknown, missing, or non-string role values normalize to the ladder's lowest
  role; they never throw or gain authority.
- An absent scoped membership is denied. Cross-scope access is denied unless a
  policy explicitly maps the parent role into that scope.
- A configured `superRole` is an intentional global escalation path; it is off
  by default.
- Allowlist entries are normalized before comparison and a non-allowlisted
  identity receives the configured fallback role.

## Consumer responsibilities

- Authenticate and verify identities before passing them to this package. An
  attacker-controlled identity string is not an authorization boundary.
- Fetch current memberships from an authoritative store on each security-
  sensitive decision or enforce a bounded, revocable cache.
- Treat role-ladder and scope-map changes as data migrations: review existing
  stored roles, membership templates, and super-role assignments before deploy.
- Enforce the returned decision at every route/operation boundary; do not use
  UI visibility as authorization.
- Log denials without logging credentials or full identity claims.

Report a suspected security issue privately to the repository maintainer; do
not open a public issue until a fix and disclosure plan exist.
