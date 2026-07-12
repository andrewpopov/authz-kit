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

const SPLIT_PATTERN = /[,;\s]+/;

function parseEmailList(raw: readonly string[] | string): string[] {
  const entries = typeof raw === 'string' ? raw.split(SPLIT_PATTERN) : raw;
  const out: string[] = [];
  for (const entry of entries) {
    if (typeof entry !== 'string') continue;
    const trimmed = entry.trim().toLowerCase();
    if (trimmed === '') continue;
    out.push(trimmed);
  }
  return out;
}

function normalizeEmail(email: unknown): string | undefined {
  if (typeof email !== 'string') return undefined;
  const trimmed = email.trim().toLowerCase();
  return trimmed === '' ? undefined : trimmed;
}

/**
 * Env-allowlist admin bootstrap, hand-rolled independently four times
 * across the fleet (sano-os's admin-email helper, smarthome's
 * `auth.service.ts` re-sync-on-login, rouge's `ROGUE_SIM_ADMIN_EMAILS`
 * guest guard, savoro's `auth.service.ts`) and unified here as one pure,
 * fail-closed resolver. Never reads `process.env` — `adminEmails` is
 * injected by the caller.
 */
export function createAllowlistRoleResolver<T extends readonly string[]>(
  options: CreateAllowlistRoleResolverOptions<T>,
): AllowlistRoleResolver<T> {
  const { ladder, adminRole, defaultRole } = options;
  const neverElevate = new Set<string>(options.neverElevate ?? []);
  const allowlist = new Set(parseEmailList(options.adminEmails));

  function isAllowlisted(email: unknown): boolean {
    const normalized = normalizeEmail(email);
    if (normalized === undefined) return false;
    return allowlist.has(normalized);
  }

  function resolve(email: unknown, currentRole?: unknown): T[number] {
    const normalizedCurrent = ladder.normalize(currentRole);

    // rouge's guard: a role in `neverElevate` (e.g. 'guest') is NEVER
    // elevated by the allowlist, allowlisted or not.
    if (neverElevate.has(normalizedCurrent)) {
      return normalizedCurrent;
    }

    if (isAllowlisted(email)) {
      return adminRole;
    }

    // Demotion safety: don't let a re-run of the resolver demote a
    // stored/granted role that's higher than defaultRole.
    return ladder.rank(normalizedCurrent) > ladder.rank(defaultRole) ? normalizedCurrent : defaultRole;
  }

  return { resolve, isAllowlisted };
}
