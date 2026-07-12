import type { RoleLadder } from './roles';
export interface CreateAllowlistRoleResolverOptions<T extends readonly string[]> {
    /** The role ladder this resolver's roles are drawn from. */
    ladder: RoleLadder<T>;
    /**
     * Allowlisted admin emails. Accepts either a raw env string
     * (comma/semicolon/whitespace-separated, e.g.
     * `"a@x.com, b@y.com;c@z.com"`) or an already-split array. Injected —
     * this module never reads `process.env` itself.
     */
    adminEmails: readonly string[] | string;
    /** Role granted to an allowlisted email. */
    adminRole: T[number];
    /** Role for everyone else (subject to the demotion-safety rule below). */
    defaultRole: T[number];
    /**
     * Roles that must NEVER be elevated even if the email is allowlisted —
     * rouge's guest guard (`ROGUE_SIM_ADMIN_EMAILS`, `start-static.js` ~line
     * 183): a guest stays a guest no matter what the allowlist says.
     */
    neverElevate?: readonly T[number][];
}
export interface AllowlistRoleResolver<T extends readonly string[]> {
    /**
     * Resolve the effective role for `email` given the role currently on
     * record (`currentRole`, e.g. a stored DB value). FAILS CLOSED: a
     * null/undefined/empty/non-string email is never allowlisted.
     *
     * Precedence, in order:
     *  1. `neverElevate` guard — if the normalized `currentRole` is in
     *     `neverElevate`, it is returned UNCHANGED, allowlisted or not
     *     (rouge's guest guard: a guest is never elevated by the allowlist).
     *  2. Allowlisted -> `adminRole`.
     *  3. Not allowlisted -> the HIGHER of `defaultRole` and the normalized
     *     `currentRole` (demotion safety: an app that stores a granted role
     *     like `owner` in the DB is never silently demoted to `defaultRole`
     *     just because the allowlist resolver re-ran without that email on
     *     it).
     */
    resolve(email: unknown, currentRole?: unknown): T[number];
    /** Is `email` present on the allowlist? Fails closed on a bad input. */
    isAllowlisted(email: unknown): boolean;
}
/**
 * Env-allowlist admin bootstrap, hand-rolled independently four times
 * across the fleet (sano-os's admin-email helper, smarthome's
 * `auth.service.ts` re-sync-on-login, rouge's `ROGUE_SIM_ADMIN_EMAILS`
 * guest guard, savoro's `auth.service.ts`) and unified here as one pure,
 * fail-closed resolver. Never reads `process.env` — `adminEmails` is
 * injected by the caller.
 */
export declare function createAllowlistRoleResolver<T extends readonly string[]>(options: CreateAllowlistRoleResolverOptions<T>): AllowlistRoleResolver<T>;
