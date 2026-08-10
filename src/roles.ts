/**
 * An ordered role ladder, LOWEST -> HIGHEST. `normalize` is the single choke
 * point every raw role value (from a DB row, a JWT claim, wherever) must
 * pass through before it is compared or trusted — it FAILS CLOSED: any
 * value it cannot map to a known role becomes the LOWEST role, never a
 * throw and never `undefined`.
 */
export interface RoleLadder<T extends readonly string[]> {
  /** The ladder as declared, lowest -> highest. */
  roles: T;
  lowest: T[number];
  highest: T[number];
  /**
   * Trim + lowercase + alias-map `raw`, then match against the ladder
   * (case-insensitively). Any unknown/null/undefined/empty/non-string value
   * — or a string that matches neither a role nor an alias — resolves to
   * `lowest`. Never throws.
   */
  normalize(raw: unknown): T[number];
  /** `normalize(role)` then compare ladder position: is it >= `min`? */
  atLeast(role: unknown, min: T[number]): boolean;
  /** True only when a raw value maps to a declared role or declared alias. */
  isKnown(raw: unknown): boolean;
  /** Ladder position of an ALREADY-NORMALIZED role (0 = lowest). */
  rank(role: T[number]): number;
}

export interface DefineRolesOptions<T extends readonly string[]> {
  /**
   * Extra raw strings that map onto a ladder role, e.g. `{ USER: 'member' }`.
   * Alias keys are matched case-insensitively and after trimming — `'USER'`,
   * `'user'`, and `' User '` all behave identically, because keys are
   * normalized (trim + lowercase) at definition time, not at lookup time.
   */
  aliases?: Record<string, T[number]>;
}

/**
 * Declare an ordered role ladder, LOWEST -> HIGHEST (e.g.
 * `['guest','member','admin','owner']`). Throws at definition time on an
 * empty ladder, a duplicate role, or an alias whose target isn't in the
 * ladder — those are programmer errors, not runtime data problems.
 */
export function defineRoles<const T extends readonly string[]>(
  ladder: T,
  options: DefineRolesOptions<T> = {},
): RoleLadder<T> {
  if (ladder.length === 0) {
    throw new Error('defineRoles: ladder must not be empty');
  }

  // ONE normalized namespace for roles AND aliases: `normalize`/`isKnown`
  // both match case-insensitively, so a case-sensitive duplicate check on
  // roles alone (or a target-only check on aliases) can miss a collision
  // that's very real at lookup time — a second role differing only in case,
  // or an alias key that shadows a declared role's own name. Build the
  // namespace in one pass and reject any case-insensitive collision, so the
  // set of keys `normalize` can ever match is provably one-to-one.
  const rankByRole = new Map<string, number>();
  const namespace = new Map<string, { kind: 'role'; role: T[number] } | { kind: 'alias'; target: T[number] }>();

  ladder.forEach((role, i) => {
    const key = role.trim().toLowerCase();
    if (namespace.has(key)) {
      throw new Error(`defineRoles: duplicate role "${role}" (case-insensitive collision with an existing role)`);
    }
    rankByRole.set(role, i);
    namespace.set(key, { kind: 'role', role });
  });

  // Normalize alias keys (trim + lowercase) at definition time so lookup is
  // a single case-normalized map access, and validate every alias target is
  // an actual ladder role (a typo here is a programmer error, fail loud now).
  const aliasMap = new Map<string, T[number]>();
  for (const [rawKey, target] of Object.entries(options.aliases ?? {})) {
    if (!rankByRole.has(target)) {
      throw new Error(`defineRoles: alias "${rawKey}" targets unknown role "${target}"`);
    }
    const key = rawKey.trim().toLowerCase();
    const existing = namespace.get(key);
    if (existing !== undefined) {
      // Same-target-is-fine, applied consistently to BOTH collision shapes:
      // an alias key that resolves to the exact role/alias already sitting
      // in that slot is redundant, not a conflict — only a DIFFERENT target
      // is the actual hazard (the shadowing/escalation case).
      const existingTarget = existing.kind === 'role' ? existing.role : existing.target;
      if (existingTarget !== target) {
        if (existing.kind === 'role') {
          throw new Error(`defineRoles: alias "${rawKey}" collides with declared role "${existing.role}"`);
        }
        throw new Error(
          `defineRoles: alias "${rawKey}" collides with a conflicting alias (already maps to "${existing.target}", cannot also map to "${target}")`,
        );
      }
      continue; // redundant — same normalized key, resolves to the same role either way; not a conflict.
    }
    namespace.set(key, { kind: 'alias', target });
    aliasMap.set(key, target);
  }

  const lowest = ladder[0];
  const highest = ladder[ladder.length - 1];

  function normalize(raw: unknown): T[number] {
    if (typeof raw !== 'string') return lowest;
    const key = raw.trim().toLowerCase();
    if (key === '') return lowest;
    if (aliasMap.has(key)) return aliasMap.get(key) as T[number];
    for (const role of ladder) {
      if (role.toLowerCase() === key) return role;
    }
    return lowest;
  }

  function isKnown(raw: unknown): boolean {
    if (typeof raw !== 'string') return false;
    const key = raw.trim().toLowerCase();
    if (key === '') return false;
    return aliasMap.has(key) || ladder.some((role) => role.toLowerCase() === key);
  }

  function rank(role: T[number]): number {
    return rankByRole.get(role) ?? 0;
  }

  function atLeast(role: unknown, min: T[number]): boolean {
    return rank(normalize(role)) >= rank(min);
  }

  return { roles: ladder, lowest, highest, normalize, isKnown, atLeast, rank };
}
