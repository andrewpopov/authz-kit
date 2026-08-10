import type { RoleLadder } from './roles';

/**
 * `'global'` — a single actor-wide role (e.g. platform admin).
 * `'org'` — a role scoped to an org/workspace.
 * `'resource'` — a role scoped to the specific resource being acted on
 * (e.g. a project/space).
 */
export type Scope = 'global' | 'org' | 'resource';

/** A per-scope ladder map: which scopes a policy configures, and the ladder each one uses. */
export type LadderMap = Partial<Record<Scope, RoleLadder<readonly string[]>>>;

/** The role-string union of a `RoleLadder`, or `never` if `L` isn't one. */
export type RoleOf<L> = L extends RoleLadder<infer T> ? T[number] : never;

/**
 * A scope-discriminated action rule: `min` is type-constrained to the ROLES
 * OF THE LADDER CONFIGURED FOR THAT SCOPE. `{ scope: 'resource', min:
 * 'OWNER' }` is a type error when the resource ladder has no `OWNER`, and
 * naming a scope with no configured ladder (not a key of `L`) is a type
 * error too, since it isn't a member of this union at all.
 */
export type ActionRule<L> = {
  [S in keyof L & Scope]: { scope: S; min: RoleOf<L[S]> };
}[keyof L & Scope];

export interface DefinePolicyOptions<L extends LadderMap, A extends Record<string, ActionRule<L>>> {
  ladders: L;
  actions: A;
  /**
   * OPT-IN global escalation: names WHICH ladder/scope grants escalation
   * (typically `{ scope: 'global', min: 'admin' }`). A role in
   * `context.roles[superRole.scope]` that is `atLeast(superRole.min)` (per
   * that scope's OWN ladder) is allowed ANY action regardless of the scoped
   * role the rule actually asks for. If unset, there is NO escalation — a
   * role in that scope never substitutes for a missing/insufficient scoped
   * role. This models cairn/sano-os/fidash's `isAdmin` bypass, but only for
   * apps that opt in.
   */
  superRole?: ActionRule<L>;
}

export interface Policy<L extends LadderMap, A extends Record<string, ActionRule<L>>> {
  ladders: L;
  actions: A;
  superRole?: ActionRule<L>;
}

export interface AuthzContext {
  roles: {
    global?: unknown;
    org?: unknown;
    resource?: unknown;
  };
}

export type Decision =
  | { allowed: true; role: string; via: Scope }
  | { allowed: false; reason: 'NOT_A_MEMBER' | 'INSUFFICIENT_ROLE' };

/** A ladder-shaped `{global, org, resource}` map, all pointing at the same ladder `T`. */
type UniformLadders<T extends readonly string[]> = {
  global: RoleLadder<T>;
  org: RoleLadder<T>;
  resource: RoleLadder<T>;
};

/** Options for the single-ladder shorthand: one ladder applies to every scope. */
export interface SingleLadderPolicyOptions<
  T extends readonly string[],
  A extends Record<string, ActionRule<UniformLadders<T>>>,
> {
  ladders: RoleLadder<T>;
  actions: A;
  superRole?: ActionRule<UniformLadders<T>>;
}

function isRoleLadder(value: unknown): value is RoleLadder<readonly string[]> {
  return typeof value === 'object' && value !== null && typeof (value as RoleLadder<readonly string[]>).normalize === 'function';
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
function validateActionRule(ladders: LadderMap, rule: { scope: Scope; min: string }, label: string): void {
  const ladder = ladders[rule.scope];
  if (ladder === undefined) {
    throw new Error(`definePolicy: ${label} names scope "${rule.scope}", which has no configured ladder`);
  }
  if (!ladder.roles.includes(rule.min)) {
    throw new Error(
      `definePolicy: ${label} has min role "${rule.min}", which is not a member of the "${rule.scope}" ladder (${ladder.roles.join(', ')})`,
    );
  }
}

/**
 * Declare a typed action policy. `A`'s keys become the only legal `action`
 * values `authorize()` accepts at the type level — an unknown key elsewhere
 * is a compile error, mirroring `defineFlags`.
 *
 * Two forms:
 *  - Per-scope ladders: `{ ladders: { global, org, resource }, actions }` —
 *    each action's `min` is constrained to the ladder of ITS OWN scope, and
 *    an action naming an unconfigured scope is a type error.
 *  - Single-ladder shorthand: `{ ladders: oneLadder, actions }` — the same
 *    ladder applies to `global`, `org`, and `resource`, so simple
 *    single-vocabulary apps don't have to write the map out three times.
 */
export function definePolicy<T extends readonly string[], A extends Record<string, ActionRule<UniformLadders<T>>>>(
  options: SingleLadderPolicyOptions<T, A>,
): Policy<UniformLadders<T>, A>;
export function definePolicy<L extends LadderMap, A extends Record<string, ActionRule<L>>>(
  options: DefinePolicyOptions<L, A>,
): Policy<L, A>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- overload implementation signature; the two public overloads above are what callers see.
export function definePolicy(options: any): any {
  const ladders: LadderMap = isRoleLadder(options.ladders)
    ? { global: options.ladders, org: options.ladders, resource: options.ladders }
    : options.ladders;

  for (const [name, rule] of Object.entries(options.actions ?? {}) as [string, { scope: Scope; min: string }][]) {
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
export function authorize<L extends LadderMap, A extends Record<string, ActionRule<L>>>(
  policy: Policy<L, A>,
  action: keyof A,
  context: AuthzContext,
): Decision {
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
  const actions = policy.actions as unknown as Record<string, ActionRule<L> | undefined>;
  const actionKey = action as string;
  const rule = Object.prototype.hasOwnProperty.call(actions, actionKey) ? actions[actionKey] : undefined;

  // Global escalation check happens before the (possibly unknown-action)
  // rule lookup fails, but only if superRole is configured — an unknown
  // action must still deny even for a super-role holder, since there is no
  // rule to escalate INTO, only a bypass of the scoped role check.
  if (policy.superRole !== undefined) {
    const superRule = policy.superRole;
    const superLadder = (policy.ladders as LadderMap)[superRule.scope];
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
  const ladder = (policy.ladders as LadderMap)[scope];
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
