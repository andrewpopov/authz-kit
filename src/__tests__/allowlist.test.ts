import { describe, it, expect } from 'vitest';
import { defineRoles } from '../roles';
import { createAllowlistRoleResolver } from '../allowlist';

const ladder = defineRoles(['guest', 'member', 'admin', 'owner'] as const);

describe('createAllowlistRoleResolver: email matching', () => {
  const resolver = createAllowlistRoleResolver({
    ladder,
    adminEmails: ['Admin@Example.com', ' second@example.com '],
    adminRole: 'admin',
    defaultRole: 'member',
  });

  it('matches case-insensitively and trims whitespace', () => {
    expect(resolver.isAllowlisted('admin@example.com')).toBe(true);
    expect(resolver.isAllowlisted('ADMIN@EXAMPLE.COM')).toBe(true);
    expect(resolver.isAllowlisted('  Admin@Example.com  ')).toBe(true);
    expect(resolver.isAllowlisted('second@example.com')).toBe(true);
  });

  it('a non-allowlisted email is not allowlisted', () => {
    expect(resolver.isAllowlisted('nobody@example.com')).toBe(false);
  });

  it.each([
    [null, 'null'],
    [undefined, 'undefined'],
    ['', 'empty string'],
    [123, 'a number'],
    [{}, 'an object'],
  ])('%s (%s) is never allowlisted', (email: unknown, _label: unknown) => {
    expect(resolver.isAllowlisted(email)).toBe(false);
  });

  it('resolve grants adminRole for an allowlisted email', () => {
    expect(resolver.resolve('admin@example.com')).toBe('admin');
  });

  it('resolve grants defaultRole for a non-allowlisted email', () => {
    expect(resolver.resolve('nobody@example.com')).toBe('member');
  });

  it('resolve on a null/undefined/non-string email never allowlists, falls back to defaultRole', () => {
    expect(resolver.resolve(null)).toBe('member');
    expect(resolver.resolve(undefined)).toBe('member');
    expect(resolver.resolve('')).toBe('member');
  });
});

describe('createAllowlistRoleResolver: raw env string parsing', () => {
  it('splits on comma, semicolon, and whitespace, ignoring empty entries', () => {
    const resolver = createAllowlistRoleResolver({
      ladder,
      adminEmails: 'a@x.com, b@y.com;c@z.com   d@w.com,,;  ',
      adminRole: 'admin',
      defaultRole: 'member',
    });
    expect(resolver.isAllowlisted('a@x.com')).toBe(true);
    expect(resolver.isAllowlisted('b@y.com')).toBe(true);
    expect(resolver.isAllowlisted('c@z.com')).toBe(true);
    expect(resolver.isAllowlisted('d@w.com')).toBe(true);
  });

  it('an empty/whitespace-only env string allowlists nobody', () => {
    const resolver = createAllowlistRoleResolver({
      ladder,
      adminEmails: '   ',
      adminRole: 'admin',
      defaultRole: 'member',
    });
    expect(resolver.isAllowlisted('a@x.com')).toBe(false);
    expect(resolver.resolve('a@x.com')).toBe('member');
  });
});

describe('createAllowlistRoleResolver: neverElevate guard (rouge guest guard)', () => {
  const resolver = createAllowlistRoleResolver({
    ladder,
    adminEmails: ['guest@example.com'],
    adminRole: 'admin',
    defaultRole: 'member',
    neverElevate: ['guest'],
  });

  it('an allowlisted email whose currentRole is guest (neverElevate) stays guest — rouge real behavior', () => {
    // This is rouge's ROGUE_SIM_ADMIN_EMAILS guard (start-static.js ~line
    // 183): a guest account must never be elevated by the allowlist, even
    // if its email happens to be on the list.
    expect(resolver.resolve('guest@example.com', 'guest')).toBe('guest');
  });

  it('an omitted currentRole normalizes to the lowest role (guest here), so the guard still applies', () => {
    // No currentRole => ladder.normalize(undefined) => 'guest' (lowest),
    // which is itself in neverElevate — so this is NOT elevated either.
    expect(resolver.resolve('guest@example.com')).toBe('guest');
  });

  it('a non-guest currentRole on the same allowlisted email IS elevated normally', () => {
    expect(resolver.resolve('guest@example.com', 'member')).toBe('admin');
  });
});

describe('createAllowlistRoleResolver: demotion safety', () => {
  const resolver = createAllowlistRoleResolver({
    ladder,
    adminEmails: [],
    adminRole: 'admin',
    defaultRole: 'member',
  });

  it('a non-allowlisted user with a stored higher role keeps that role, is not demoted to defaultRole', () => {
    expect(resolver.resolve('owner@example.com', 'owner')).toBe('owner');
  });

  it('a non-allowlisted user with a stored LOWER role than defaultRole is bumped to defaultRole', () => {
    expect(resolver.resolve('guest@example.com', 'guest')).toBe('member');
  });

  it('a non-allowlisted user with no stored role at all resolves to defaultRole', () => {
    expect(resolver.resolve('nobody@example.com')).toBe('member');
  });
});
