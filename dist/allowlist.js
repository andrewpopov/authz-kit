"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAllowlistRoleResolver = createAllowlistRoleResolver;
const SPLIT_PATTERN = /[,;\s]+/;
function parseEmailList(raw) {
    const entries = typeof raw === 'string' ? raw.split(SPLIT_PATTERN) : raw;
    const out = [];
    for (const entry of entries) {
        if (typeof entry !== 'string')
            continue;
        const trimmed = entry.trim().toLowerCase();
        if (trimmed === '')
            continue;
        out.push(trimmed);
    }
    return out;
}
function normalizeEmail(email) {
    if (typeof email !== 'string')
        return undefined;
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
function createAllowlistRoleResolver(options) {
    const { ladder, adminRole, defaultRole } = options;
    const neverElevate = new Set(options.neverElevate ?? []);
    const allowlist = new Set(parseEmailList(options.adminEmails));
    function isAllowlisted(email) {
        const normalized = normalizeEmail(email);
        if (normalized === undefined)
            return false;
        return allowlist.has(normalized);
    }
    function resolve(email, currentRole) {
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
