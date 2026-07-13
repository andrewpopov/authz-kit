"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.defineRoles = defineRoles;
/**
 * Declare an ordered role ladder, LOWEST -> HIGHEST (e.g.
 * `['guest','member','admin','owner']`). Throws at definition time on an
 * empty ladder, a duplicate role, or an alias whose target isn't in the
 * ladder — those are programmer errors, not runtime data problems.
 */
function defineRoles(ladder, options = {}) {
    if (ladder.length === 0) {
        throw new Error('defineRoles: ladder must not be empty');
    }
    const seen = new Set();
    for (const role of ladder) {
        if (seen.has(role)) {
            throw new Error(`defineRoles: duplicate role "${role}"`);
        }
        seen.add(role);
    }
    const rankByRole = new Map(ladder.map((role, i) => [role, i]));
    // Normalize alias keys (trim + lowercase) at definition time so lookup is
    // a single case-normalized map access, and validate every alias target is
    // an actual ladder role (a typo here is a programmer error, fail loud now).
    const aliasMap = new Map();
    for (const [rawKey, target] of Object.entries(options.aliases ?? {})) {
        if (!rankByRole.has(target)) {
            throw new Error(`defineRoles: alias "${rawKey}" targets unknown role "${target}"`);
        }
        aliasMap.set(rawKey.trim().toLowerCase(), target);
    }
    const lowest = ladder[0];
    const highest = ladder[ladder.length - 1];
    function normalize(raw) {
        if (typeof raw !== 'string')
            return lowest;
        const key = raw.trim().toLowerCase();
        if (key === '')
            return lowest;
        if (aliasMap.has(key))
            return aliasMap.get(key);
        for (const role of ladder) {
            if (role.toLowerCase() === key)
                return role;
        }
        return lowest;
    }
    function isKnown(raw) {
        if (typeof raw !== 'string')
            return false;
        const key = raw.trim().toLowerCase();
        if (key === '')
            return false;
        return aliasMap.has(key) || ladder.some((role) => role.toLowerCase() === key);
    }
    function rank(role) {
        return rankByRole.get(role) ?? 0;
    }
    function atLeast(role, min) {
        return rank(normalize(role)) >= rank(min);
    }
    return { roles: ladder, lowest, highest, normalize, isKnown, atLeast, rank };
}
