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

  const seen = new Set<string>();
  for (const role of ladder) {
    if (seen.has(role)) {
      throw new Error(`defineRoles: duplicate role "${role}"`);
    }
    seen.add(role);
  }

  const rankByRole = new Map<string, number>(ladder.map((role, i) => [role, i] as const));

  // Normalize alias keys (trim + lowercase) at definition time so lookup is
  // a single case-normalized map access, and validate every alias target is
  // an actual ladder role (a typo here is a programmer error, fail loud now).
  const aliasMap = new Map<string, T[number]>();
  for (const [rawKey, target] of Object.entries(options.aliases ?? {})) {
    if (!rankByRole.has(target)) {
      throw new Error(`defineRoles: alias "${rawKey}" targets unknown role "${target}"`);
    }
    aliasMap.set(rawKey.trim().toLowerCase(), target);
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

  function rank(role: T[number]): number {
    return rankByRole.get(role) ?? 0;
  }

  function atLeast(role: unknown, min: T[number]): boolean {
    return rank(normalize(role)) >= rank(min);
  }

  return { roles: ladder, lowest, highest, normalize, atLeast, rank };
}
