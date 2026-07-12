import { describe, it, expect } from 'vitest';
import { defineRoles } from '../roles';

describe('defineRoles: normalize', () => {
  const roles = defineRoles(['guest', 'member', 'admin', 'owner'] as const);

  it.each([
    ['OWNER', 'owner'],
    [' owner ', 'owner'],
    ['Owner', 'owner'],
    ['admin', 'admin'],
    ['MEMBER', 'member'],
    ['guest', 'guest'],
  ])('%s -> %s', (raw, expected) => {
    expect(roles.normalize(raw)).toBe(expected);
  });

  it.each([
    ['wizard', 'wizard is not a ladder role'],
    ['', 'empty string'],
    [null, 'null'],
    [undefined, 'undefined'],
    [123, 'a number'],
    [{}, 'an object'],
  ])('unknown value %s (%s) fails closed to the lowest role', (raw: unknown, _label: unknown) => {
    expect(roles.normalize(raw)).toBe('guest');
  });
});

describe('defineRoles: aliases', () => {
  const roles = defineRoles(['guest', 'member', 'admin', 'owner'] as const, {
    aliases: { USER: 'member', moderator: 'member' },
  });

  it.each([
    ['USER', 'member'],
    ['user', 'member'],
    [' User ', 'member'],
    ['moderator', 'member'],
    ['MODERATOR', 'member'],
  ])('alias %s -> %s (case-insensitive)', (raw, expected) => {
    expect(roles.normalize(raw)).toBe(expected);
  });
});

describe('defineRoles: atLeast', () => {
  const roles = defineRoles(['guest', 'member', 'admin', 'owner'] as const);

  it('compares ladder position after normalizing', () => {
    expect(roles.atLeast('owner', 'admin')).toBe(true);
    expect(roles.atLeast('admin', 'admin')).toBe(true);
    expect(roles.atLeast('member', 'admin')).toBe(false);
    expect(roles.atLeast('guest', 'member')).toBe(false);
  });

  it('an unknown role normalizes to lowest before comparison', () => {
    expect(roles.atLeast('wizard', 'guest')).toBe(true);
    expect(roles.atLeast('wizard', 'member')).toBe(false);
  });
});

describe('defineRoles: definition-time throws', () => {
  it('throws on an empty ladder', () => {
    expect(() => defineRoles([] as const)).toThrow(/empty/i);
  });

  it('throws on a duplicate role', () => {
    expect(() => defineRoles(['guest', 'member', 'guest'] as const)).toThrow(/duplicate/i);
  });

  it('throws on an alias targeting a role not in the ladder', () => {
    expect(() =>
      defineRoles(['guest', 'member', 'admin', 'owner'] as const, {
        aliases: { superuser: 'root' as never },
      }),
    ).toThrow(/unknown role/i);
  });
});

describe('defineRoles: rank / roles / lowest / highest', () => {
  const roles = defineRoles(['guest', 'member', 'admin', 'owner'] as const);

  it('exposes the declared ladder and its endpoints', () => {
    expect(roles.roles).toEqual(['guest', 'member', 'admin', 'owner']);
    expect(roles.lowest).toBe('guest');
    expect(roles.highest).toBe('owner');
  });

  it('rank increases lowest -> highest', () => {
    expect(roles.rank('guest')).toBe(0);
    expect(roles.rank('member')).toBe(1);
    expect(roles.rank('admin')).toBe(2);
    expect(roles.rank('owner')).toBe(3);
  });
});
