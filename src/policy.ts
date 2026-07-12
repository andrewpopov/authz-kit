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

// eslint-disable-next-line @typescript-eslint/no-unused-vars -- R is part of the public shape (parity with the design contract); roles are intentionally `unknown` since normalization happens inside authorize().
export interface AuthzContext<R extends string = string> {
  roles: {
    global?: unknown;
    org?: unknown;
    resource?: unknown;
  };
}

export type Decision =
  | { allowed: true; role: string; via: Scope }
  | { allowed: false; reason: 'NOT_A_MEMBER' | 'INSUFFICIENT_ROLE' };

/**
 * Declare a typed action policy over a role ladder. `A`'s keys become the
 * only legal `action` values `authorize()` accepts at the type level — an
 * unknown key elsewhere is a compile error, mirroring `defineFlags`.
 */
export function definePolicy<R extends string, const A extends Record<string, ActionRule<R>>>(
  roles: RoleLadder<readonly R[]>,
  actions: A,
  options: DefinePolicyOptions<R> = {},
): Policy<R, A> {
  return { roles, actions, superRole: options.superRole };
}

/**
 * Pure decision function — no I/O, never throws. FAILS CLOSED at every
 * branch: an unknown action, a missing scoped role, or an unrecognized role
 * string all resolve to a `{allowed:false}` decision, never an allow.
 */
export function authorize<R extends string, A extends Record<string, ActionRule<R>>>(
  policy: Policy<R, A>,
  action: keyof A,
  context: AuthzContext<R>,
): Decision {
  const rule = policy.actions[action as string];

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
