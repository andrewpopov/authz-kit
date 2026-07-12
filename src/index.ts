/**
 * @andrewpopov/authz-kit — pure authorization primitives.
 *
 * Three pieces, composable but independently usable:
 * `defineRoles` builds an ORDERED role ladder (lowest -> highest) with a
 * fail-closed `normalize` — any unknown/null/undefined/non-string value
 * normalizes to the LOWEST role, never throws — plus `atLeast`/`rank` for
 * comparisons. `definePolicy` + `authorize` give you a typed action policy
 * (an unknown action key is a compile error, like `defineFlags`) and a
 * pure `authorize(action, context) -> Decision` that fails closed on a
 * missing scoped role (`NOT_A_MEMBER`) or an insufficient one
 * (`INSUFFICIENT_ROLE`), with an OPT-IN `superRole` global-escalation
 * bypass that is OFF unless a policy configures it. `mapScopeRole` is a
 * pure lookup-table mapper for two-tier scope inheritance (e.g. an org
 * role implying a project role) — no cleverness, an unrecognized parent
 * role never invents a child role. `createAllowlistRoleResolver` is a
 * pure, fail-closed env-allowlist admin bootstrap (unifies four
 * hand-rolled fleet copies), and `MEMBERSHIP_SCHEMA_SQL` /
 * `MEMBERSHIP_SCHEMA_SQL_POSTGRES` are raw-SQL DDL constants for the
 * canonical membership shape — the kit never creates or migrates a table,
 * the app owns its migrations.
 *
 * The kit is PURE and has NO store seam: apps fetch their own role rows
 * (several re-read per request deliberately, for security) and hand them
 * to `authorize`/`normalize`/`mapScopeRole` as plain values. The kit only
 * decides — it never queries a database, a session, or `process.env`.
 */

export { defineRoles, type RoleLadder, type DefineRolesOptions } from './roles';

export {
  definePolicy,
  authorize,
  type Scope,
  type ActionRule,
  type Policy,
  type AuthzContext,
  type Decision,
  type DefinePolicyOptions,
} from './policy';

export { mapScopeRole } from './scope';

export {
  createAllowlistRoleResolver,
  type CreateAllowlistRoleResolverOptions,
  type AllowlistRoleResolver,
} from './allowlist';

export { MEMBERSHIP_SCHEMA_SQL, MEMBERSHIP_SCHEMA_SQL_POSTGRES } from './schema';
