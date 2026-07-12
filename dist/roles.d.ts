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
export declare function defineRoles<const T extends readonly string[]>(ladder: T, options?: DefineRolesOptions<T>): RoleLadder<T>;
