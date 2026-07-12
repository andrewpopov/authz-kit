import { describe, it, expect } from 'vitest';
import { defineRoles } from '../roles';
import { definePolicy, authorize } from '../policy';

/**
 * Behavioral-superset fixture: reproduces bewks's `src/lib/auth/roles.ts`
 * ladder (`UserRole` OWNER=4 > ADMIN=3 > MEMBER=2 (legacy USER/LIBRARIAN
 * also collapse to MEMBER) > GUEST=1, defaulting unrecognized/null/
 * undefined input to GUEST) on top of `defineRoles`.
 */
const bewksRoles = defineRoles(['guest', 'member', 'admin', 'owner'] as const, {
  aliases: { USER: 'member', LIBRARIAN: 'member' },
});

describe('bewks roleLevel/normalizeRole fixture', () => {
  it('normalize matches bewks normalizeRole for every real UserRole value', () => {
    expect(bewksRoles.normalize('OWNER')).toBe('owner');
    expect(bewksRoles.normalize('ADMIN')).toBe('admin');
    expect(bewksRoles.normalize('MEMBER')).toBe('member');
    expect(bewksRoles.normalize('USER')).toBe('member'); // legacy alias
    expect(bewksRoles.normalize('LIBRARIAN')).toBe('member'); // legacy alias
    expect(bewksRoles.normalize('GUEST')).toBe('guest');
  });

  it('null/undefined/unrecognized fall back to GUEST, matching normalizeRole(role) => UserRole.GUEST', () => {
    expect(bewksRoles.normalize(null)).toBe('guest');
    expect(bewksRoles.normalize(undefined)).toBe('guest');
    expect(bewksRoles.normalize('wizard')).toBe('guest');
    expect(bewksRoles.normalize('')).toBe('guest');
  });

  it('rank reproduces roleLevel: OWNER=4 > ADMIN=3 > MEMBER=2 > GUEST=1 (as a 0-based ladder position, same ORDER)', () => {
    // bewks's roleLevel is 1-based (GUEST=1..OWNER=4); ours is 0-based
    // (guest=0..owner=3). The +1 offset reproduces bewks's exact numbers;
    // what matters for `atLeast`/access decisions is the ORDER, which is identical.
    const roleLevel = (raw: unknown) => bewksRoles.rank(bewksRoles.normalize(raw)) + 1;
    expect(roleLevel('OWNER')).toBe(4);
    expect(roleLevel('ADMIN')).toBe(3);
    expect(roleLevel('MEMBER')).toBe(2);
    expect(roleLevel('USER')).toBe(2); // legacy alias -> same level as MEMBER
    expect(roleLevel('LIBRARIAN')).toBe(2); // legacy alias -> same level as MEMBER
    expect(roleLevel('GUEST')).toBe(1);
    expect(roleLevel(null)).toBe(1); // hasAdminAccess(null) === false, same as bewks
    expect(roleLevel('nonsense')).toBe(1);
  });

  it('hasAdminAccess(role) === atLeast(role, "admin")', () => {
    expect(bewksRoles.atLeast('OWNER', 'admin')).toBe(true);
    expect(bewksRoles.atLeast('ADMIN', 'admin')).toBe(true);
    expect(bewksRoles.atLeast('MEMBER', 'admin')).toBe(false);
    expect(bewksRoles.atLeast('USER', 'admin')).toBe(false);
    expect(bewksRoles.atLeast(null, 'admin')).toBe(false);
  });
});

/**
 * bewks has ONE role vocabulary shared everywhere — the exact case the
 * single-ladder shorthand exists for. `definePolicy({ ladders: oneLadder,
 * actions })` must behave identically to spelling out the same ladder for
 * global/org/resource by hand; simple apps shouldn't have to write three.
 */
describe('definePolicy single-ladder shorthand: bewks stays a one-ladder app', () => {
  const policy = definePolicy({
    ladders: bewksRoles,
    actions: {
      'library.manage': { min: 'admin', scope: 'org' },
      'book.request': { min: 'member', scope: 'resource' },
    },
  });

  it('the shorthand applies the same ladder to every scope', () => {
    expect(authorize(policy, 'library.manage', { roles: { org: 'ADMIN' } })).toEqual({
      allowed: true,
      role: 'admin',
      via: 'org',
    });
    expect(authorize(policy, 'book.request', { roles: { resource: 'USER' } })).toEqual({
      allowed: true,
      role: 'member',
      via: 'resource',
    });
  });

  it('still fails closed: a legacy MEMBER-level alias can never satisfy an admin-only rule', () => {
    expect(authorize(policy, 'library.manage', { roles: { org: 'LIBRARIAN' } })).toEqual({
      allowed: false,
      reason: 'INSUFFICIENT_ROLE',
    });
  });
});
