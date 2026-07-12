import type { RoleLadder } from './roles';
/**
 * `'global'` — a single actor-wide role (e.g. platform admin).
 * `'org'` — a role scoped to an org/workspace.
 * `'resource'` — a role scoped to the specific resource being acted on
 * (e.g. a project/space). Defaults to `'resource'` when unspecified on an
 * `ActionRule`, since most actions act on a specific resource.
 */
export type Scope = 'global' | 'org' | 'resource';
export interface ActionRule<R extends string> {
    min: R;
    /** Defaults to `'resource'`. */
    scope?: Scope;
}
export interface DefinePolicyOptions<R extends string> {
    /**
     * OPT-IN global escalation: a `global` role that is `atLeast(superRole)`
     * is allowed ANY action regardless of the scoped role in context. If
     * unset, there is NO escalation — a global role never substitutes for a
     * missing/insufficient scoped role. This models cairn/sano-os/fidash's
     * `isAdmin` bypass, but only for apps that opt in.
     */
    superRole?: R;
}
export interface Policy<R extends string, A extends Record<string, ActionRule<R>>> {
    roles: RoleLadder<readonly R[]>;
    actions: A;
    superRole?: R;
}
export interface AuthzContext<R extends string = string> {
    roles: {
        global?: unknown;
        org?: unknown;
        resource?: unknown;
    };
}
export type Decision = {
    allowed: true;
    role: string;
    via: Scope;
} | {
    allowed: false;
    reason: 'NOT_A_MEMBER' | 'INSUFFICIENT_ROLE';
};
/**
 * Declare a typed action policy over a role ladder. `A`'s keys become the
 * only legal `action` values `authorize()` accepts at the type level — an
 * unknown key elsewhere is a compile error, mirroring `defineFlags`.
 */
export declare function definePolicy<R extends string, const A extends Record<string, ActionRule<R>>>(roles: RoleLadder<readonly R[]>, actions: A, options?: DefinePolicyOptions<R>): Policy<R, A>;
/**
 * Pure decision function — no I/O, never throws. FAILS CLOSED at every
 * branch: an unknown action, a missing scoped role, or an unrecognized role
 * string all resolve to a `{allowed:false}` decision, never an allow.
 */
export declare function authorize<R extends string, A extends Record<string, ActionRule<R>>>(policy: Policy<R, A>, action: keyof A, context: AuthzContext<R>): Decision;
