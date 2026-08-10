"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.definePolicy = definePolicy;
exports.authorize = authorize;
function isRoleLadder(value) {
    return typeof value === 'object' && value !== null && typeof value.normalize === 'function';
}
/**
 * Validates ONE action rule against the ladder namespace: the rule's scope
 * must have a configured ladder, and `min` must be an ACTUAL member of that
 * ladder's declared roles (not merely an alias, and not a typo). This is
 * the runtime backstop for what the type system already enforces at compile
 * time — `min` must be checked against `ladder.roles` directly (not
 * `ladder.isKnown`, which also accepts aliases) because `rank()` only knows
 * about declared role names: a `min` that isn't one silently ranks 0 (the
 * lowest possible rank), which makes `atLeast()` true for every actual
 * role — a fail-open, not a fail-closed miss.
 */
function validateActionRule(ladders, rule, label) {
    const ladder = ladders[rule.scope];
    if (ladder === undefined) {
        throw new Error(`definePolicy: ${label} names scope "${rule.scope}", which has no configured ladder`);
    }
    if (!ladder.roles.includes(rule.min)) {
        throw new Error(`definePolicy: ${label} has min role "${rule.min}", which is not a member of the "${rule.scope}" ladder (${ladder.roles.join(', ')})`);
    }
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- overload implementation signature; the two public overloads above are what callers see.
function definePolicy(options) {
    const ladders = isRoleLadder(options.ladders)
        ? { global: options.ladders, org: options.ladders, resource: options.ladders }
        : options.ladders;
    for (const [name, rule] of Object.entries(options.actions ?? {})) {
        validateActionRule(ladders, rule, `action "${name}"`);
    }
    if (options.superRole !== undefined) {
        validateActionRule(ladders, options.superRole, 'superRole');
    }
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
    // OWN-property-only lookup, deliberately: `definePolicy` validates
    // `options.actions` via `Object.entries`, which only sees own enumerable
    // properties. If this read instead fell through to an INHERITED property
    // (e.g. `Object.create({ dangerous: { scope: 'org', min: 'wizard' } })`
    // passed as `actions`), it would find a rule `definePolicy` never
    // validated — reopening exactly the fail-open finding-2 fix exists to
    // close, just reached through the prototype chain instead of a typo.
    // Keeping validation and lookup on the same (own-property-only) model is
    // what makes that agreement hold regardless of how `policy.actions` was
    // built, not just when it went through `definePolicy`.
    const actions = policy.actions;
    const actionKey = action;
    const rule = Object.prototype.hasOwnProperty.call(actions, actionKey) ? actions[actionKey] : undefined;
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
