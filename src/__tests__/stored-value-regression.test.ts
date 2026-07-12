import { describe, it, expect } from 'vitest';
import { defineRoles } from '../roles';

/**
 * Stored-value regression fixture — the preHash-lockout analog for this
 * package (see agent memory: "The preHash lockout trap"). If an app swaps
 * its hand-rolled role check for `defineRoles`, a normalizer that treats
 * an ALREADY-STORED raw value differently than the app's old code silently
 * demotes (or elevates) real users' access — with tests still green,
 * because a fresh fixture wouldn't catch a mismatch against what's
 * actually sitting in a database TODAY.
 *
 * This table is deliberately built from raw values observed across the
 * fleet (bewks UserRole rows, savoro accountType rows, and cairn/mizen
 * role columns), not synthetic examples, so it pins the exact effective
 * role for what apps will actually feed through `normalize` on migration.
 */
const fleetRoles = defineRoles(['guest', 'member', 'admin', 'owner'] as const, {
  aliases: { USER: 'member', user: 'member', LIBRARIAN: 'member', moderator: 'member' },
});

describe('stored-value regression: raw values as found in the fleet today', () => {
  it.each([
    ['GUEST', 'guest'],
    ['USER', 'member'],
    ['user', 'member'],
    ['admin', 'admin'],
    ['owner', 'owner'],
    ['moderator', 'member'],
    ['LIBRARIAN', 'member'],
    [null, 'guest'],
    ['', 'guest'],
  ])('stored value %j -> effective role %s', (raw, expected) => {
    expect(fleetRoles.normalize(raw)).toBe(expected);
  });
});
