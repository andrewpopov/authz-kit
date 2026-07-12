"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.definePolicy = definePolicy;
exports.authorize = authorize;
/**
 * Declare a typed action policy over a role ladder. `A`'s keys become the
 * only legal `action` values `authorize()` accepts at the type level — an
 * unknown key elsewhere is a compile error, mirroring `defineFlags`.
 */
function definePolicy(roles, actions, options = {}) {
    return { roles, actions, superRole: options.superRole };
}
/**
 * Pure decision function — no I/O, never throws. FAILS CLOSED at every
 * branch: an unknown action, a missing scoped role, or an unrecognized role
 * string all resolve to a `{allowed:false}` decision, never an allow.
 */
function authorize(policy, action, context) {
    const rule = policy.actions[action];
    // Global escalation check happens before the (possibly unknown-action)
    // rule lookup fails, but only if superRole is configured — an unknown
    // action must still deny even for a global admin's own scope, since there
    // is no rule to escalate INTO, only a bypass of the scoped role check.
    if (policy.superRole !== undefined && context.roles.global !== undefined && context.roles.global !== null) {
        if (policy.roles.atLeast(context.roles.global, policy.superRole)) {
            if (rule === undefined) {
                return { allowed: false, reason: 'INSUFFICIENT_ROLE' };
            }
            return { allowed: true, role: policy.roles.normalize(context.roles.global), via: 'global' };
        }
    }
    // Unknown action at runtime: typed keys make this a compile error to
    // reach, but a runtime caller (e.g. dynamic dispatch) must still fail closed.
    if (rule === undefined) {
        return { allowed: false, reason: 'INSUFFICIENT_ROLE' };
    }
    const scope = rule.scope ?? 'resource';
    const scopedRole = context.roles[scope];
    if (scopedRole === undefined || scopedRole === null) {
        return { allowed: false, reason: 'NOT_A_MEMBER' };
    }
    const normalized = policy.roles.normalize(scopedRole);
    if (policy.roles.atLeast(normalized, rule.min)) {
        return { allowed: true, role: normalized, via: scope };
    }
    return { allowed: false, reason: 'INSUFFICIENT_ROLE' };
}
