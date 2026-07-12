"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.definePolicy = definePolicy;
exports.authorize = authorize;
function isRoleLadder(value) {
    return typeof value === 'object' && value !== null && typeof value.normalize === 'function';
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- overload implementation signature; the two public overloads above are what callers see.
function definePolicy(options) {
    const ladders = isRoleLadder(options.ladders)
        ? { global: options.ladders, org: options.ladders, resource: options.ladders }
        : options.ladders;
    return { ladders, actions: options.actions, superRole: options.superRole };
}
/**
 * Pure decision function — no I/O, never throws. FAILS CLOSED at every
 * branch: an unknown action, a missing scoped role, or an unrecognized role
 * string all resolve to a `{allowed:false}` decision, never an allow.
 * Cross-scope isolation is STRUCTURAL — a scope's role is only ever
 * normalized and compared against THAT scope's ladder, so a role that is
 * valid in one ladder can never satisfy a rule scoped to a different one.
 */
function authorize(policy, action, context) {
    const actions = policy.actions;
    const rule = actions[action];
    // Global escalation check happens before the (possibly unknown-action)
    // rule lookup fails, but only if superRole is configured — an unknown
    // action must still deny even for a super-role holder, since there is no
    // rule to escalate INTO, only a bypass of the scoped role check.
    if (policy.superRole !== undefined) {
        const superRule = policy.superRole;
        const superLadder = policy.ladders[superRule.scope];
        const rawSuperRole = context.roles[superRule.scope];
        if (superLadder !== undefined && rawSuperRole !== undefined && rawSuperRole !== null) {
            if (superLadder.atLeast(rawSuperRole, superRule.min)) {
                if (rule === undefined) {
                    return { allowed: false, reason: 'INSUFFICIENT_ROLE' };
                }
                return { allowed: true, role: superLadder.normalize(rawSuperRole), via: superRule.scope };
            }
        }
    }
    // Unknown action at runtime: typed keys make this a compile error to
    // reach, but a runtime caller (e.g. dynamic dispatch) must still fail closed.
    if (rule === undefined) {
        return { allowed: false, reason: 'INSUFFICIENT_ROLE' };
    }
    const { scope, min } = rule;
    const ladder = policy.ladders[scope];
    const scopedRole = context.roles[scope];
    if (ladder === undefined || scopedRole === undefined || scopedRole === null) {
        return { allowed: false, reason: 'NOT_A_MEMBER' };
    }
    const normalized = ladder.normalize(scopedRole);
    if (ladder.atLeast(normalized, min)) {
        return { allowed: true, role: normalized, via: scope };
    }
    return { allowed: false, reason: 'INSUFFICIENT_ROLE' };
}
