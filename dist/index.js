"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.MEMBERSHIP_SCHEMA_SQL_POSTGRES = exports.MEMBERSHIP_SCHEMA_SQL = exports.createAllowlistRoleResolver = exports.mapScopeRole = exports.authorize = exports.definePolicy = exports.evaluateAccountAdminMutation = exports.defineAccountAdminPolicy = exports.defineRoles = void 0;
var roles_1 = require("./roles");
Object.defineProperty(exports, "defineRoles", { enumerable: true, get: function () { return roles_1.defineRoles; } });
var accountAdmin_1 = require("./accountAdmin");
Object.defineProperty(exports, "defineAccountAdminPolicy", { enumerable: true, get: function () { return accountAdmin_1.defineAccountAdminPolicy; } });
Object.defineProperty(exports, "evaluateAccountAdminMutation", { enumerable: true, get: function () { return accountAdmin_1.evaluateAccountAdminMutation; } });
var policy_1 = require("./policy");
Object.defineProperty(exports, "definePolicy", { enumerable: true, get: function () { return policy_1.definePolicy; } });
Object.defineProperty(exports, "authorize", { enumerable: true, get: function () { return policy_1.authorize; } });
var scope_1 = require("./scope");
Object.defineProperty(exports, "mapScopeRole", { enumerable: true, get: function () { return scope_1.mapScopeRole; } });
var allowlist_1 = require("./allowlist");
Object.defineProperty(exports, "createAllowlistRoleResolver", { enumerable: true, get: function () { return allowlist_1.createAllowlistRoleResolver; } });
var schema_1 = require("./schema");
Object.defineProperty(exports, "MEMBERSHIP_SCHEMA_SQL", { enumerable: true, get: function () { return schema_1.MEMBERSHIP_SCHEMA_SQL; } });
Object.defineProperty(exports, "MEMBERSHIP_SCHEMA_SQL_POSTGRES", { enumerable: true, get: function () { return schema_1.MEMBERSHIP_SCHEMA_SQL_POSTGRES; } });
