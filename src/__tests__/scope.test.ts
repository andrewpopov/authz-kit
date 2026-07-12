import { describe, it, expect } from 'vitest';
import { mapScopeRole } from '../scope';

describe('mapScopeRole: pure lookup semantics', () => {
  const table = { admin: 'manager', member: 'editor' } as const;

  it('maps a parent role present in the table', () => {
    expect(mapScopeRole('admin', table)).toBe('manager');
    expect(mapScopeRole('member', table)).toBe('editor');
  });

  it('an unrecognized parent role resolves to undefined by default — never invents a role', () => {
    expect(mapScopeRole('guest', table)).toBeUndefined();
  });

  it('a non-string parent role resolves to undefined by default', () => {
    expect(mapScopeRole(null, table)).toBeUndefined();
    expect(mapScopeRole(undefined, table)).toBeUndefined();
    expect(mapScopeRole(123, table)).toBeUndefined();
  });

  it('an explicit fallback is used instead of undefined when provided', () => {
    expect(mapScopeRole('guest', table, { fallback: 'viewer' })).toBe('viewer');
    expect(mapScopeRole(null, table, { fallback: 'viewer' })).toBe('viewer');
  });
});

// -- Fixture: mizen's defaultSpaceRole() (packages/authorization consumer,
// apps/api/src/authorization/authorization.service.ts) --
//
//   if (workspaceRole === 'OWNER' || workspaceRole === 'ADMIN') return 'MANAGER';
//   if (workspaceRole === 'MEMBER') return 'EDITOR';
//   return 'VIEWER';    // i.e. GUEST -> VIEWER
//
// mizen's version always returns a value (VIEWER is a real fallback, not
// "not a member") — replicated here with an explicit `fallback: 'VIEWER'`.
describe('mapScopeRole fixture: mizen defaultSpaceRole()', () => {
  const mizenSpaceRoleTable = {
    OWNER: 'MANAGER',
    ADMIN: 'MANAGER',
    MEMBER: 'EDITOR',
  } as const;

  function defaultSpaceRole(workspaceRole: unknown): string {
    return mapScopeRole(workspaceRole, mizenSpaceRoleTable, { fallback: 'VIEWER' }) as string;
  }

  it.each([
    ['OWNER', 'MANAGER'],
    ['ADMIN', 'MANAGER'],
    ['MEMBER', 'EDITOR'],
    ['GUEST', 'VIEWER'],
  ])('%s -> %s', (workspaceRole, expected) => {
    expect(defaultSpaceRole(workspaceRole)).toBe(expected);
  });
});

// -- Fixture: cairn's getMemberRole() org -> project implicit inheritance
// (packages/api/src/services/project.service.ts, ~line 402-419) --
//
//   Org OWNER/ADMIN -> implicit project ADMIN.
//   Any other org member -> implicit project MEMBER.
//   No org membership (or a PRIVATE-visibility project, handled by the
//   caller, not this table) -> no implicit role (undefined, NOT a member).
//
// Note cairn's ProjectRole ladder also has a VIEWER tier below MEMBER that
// this inheritance table never produces — org members who aren't
// OWNER/ADMIN always inherit MEMBER, never VIEWER, matching the source.
describe('mapScopeRole fixture: cairn org -> project inheritance', () => {
  const cairnProjectRoleTable = {
    OWNER: 'ADMIN',
    ADMIN: 'ADMIN',
    MEMBER: 'MEMBER',
  } as const;

  function impliedProjectRole(orgRole: unknown): string | undefined {
    return mapScopeRole(orgRole, cairnProjectRoleTable);
  }

  it.each([
    ['OWNER', 'ADMIN'],
    ['ADMIN', 'ADMIN'],
    ['MEMBER', 'MEMBER'],
  ])('org %s -> implicit project %s', (orgRole, expected) => {
    expect(impliedProjectRole(orgRole)).toBe(expected);
  });

  it('no org membership => no implicit role (undefined, not a member)', () => {
    expect(impliedProjectRole(undefined)).toBeUndefined();
    expect(impliedProjectRole(null)).toBeUndefined();
  });

  it('an unrecognized org role string also => undefined, never a guessed role', () => {
    expect(impliedProjectRole('SOMETHING_ELSE')).toBeUndefined();
  });
});
