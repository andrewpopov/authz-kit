"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mapScopeRole = mapScopeRole;
/**
 * Two-tier scope-role inheritance: map a parent-scope role (e.g. an
 * org/workspace role) to an implied child-scope role (e.g. a
 * project/space role) via an explicit table. A pure lookup — no
 * cleverness, no default-highest/lowest guessing.
 *
 * `parentRole` is normalized by the CALLER before this is invoked (this
 * function does no ladder normalization itself — it is deliberately
 * ladder-agnostic so it can map between two DIFFERENT ladders, e.g. a
 * WorkspaceRole ladder to a SpaceRole ladder). An unknown/absent parent
 * role, or a parent role with no entry in `table`, resolves to
 * `options.fallback` if given, else `undefined` — i.e. NOT a member.
 * This never invents a role for an unrecognized parent role.
 */
function mapScopeRole(parentRole, table, options = {}) {
    if (typeof parentRole !== 'string')
        return options.fallback;
    const mapped = table[parentRole];
    return mapped ?? options.fallback;
}
