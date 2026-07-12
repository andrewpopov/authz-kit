import { describe, it, expect } from 'vitest';
import { defineRoles } from '../roles';
import { definePolicy, authorize } from '../policy';

const roles = defineRoles(['guest', 'member', 'admin', 'owner'] as const);

// Single-ladder shorthand: one ladder applies to global/org/resource.
const policy = definePolicy({
  ladders: roles,
  actions: {
    'org.manage': { min: 'admin', scope: 'org' },
    'resource.view': { min: 'guest', scope: 'resource' },
    'resource.edit': { min: 'member', scope: 'resource' },
  },
});

describe('authorize: fail-closed basics', () => {
  it('missing scope role => NOT_A_MEMBER', () => {
    expect(authorize(policy, 'resource.view', { roles: {} })).toEqual({
      allowed: false,
      reason: 'NOT_A_MEMBER',
    });
  });

  it('null/undefined scope role both count as missing => NOT_A_MEMBER', () => {
    expect(authorize(policy, 'resource.view', { roles: { resource: null } })).toEqual({
      allowed: false,
      reason: 'NOT_A_MEMBER',
    });
    expect(authorize(policy, 'resource.view', { roles: { resource: undefined } })).toEqual({
      allowed: false,
      reason: 'NOT_A_MEMBER',
    });
  });

  it('too-low role => INSUFFICIENT_ROLE', () => {
    expect(authorize(policy, 'org.manage', { roles: { org: 'member' } })).toEqual({
      allowed: false,
      reason: 'INSUFFICIENT_ROLE',
    });
  });

  it('sufficient role => allowed, reports the normalized role and scope', () => {
    expect(authorize(policy, 'org.manage', { roles: { org: 'ADMIN' } })).toEqual({
      allowed: true,
      role: 'admin',
      via: 'org',
    });
  });

  it('unknown role string is treated as the lowest role, never allowed above guest-level rules', () => {
    const decision = authorize(policy, 'resource.edit', { roles: { resource: 'wizard' } });
    expect(decision).toEqual({ allowed: false, reason: 'INSUFFICIENT_ROLE' });
  });

  it('an unknown role string still passes a rule whose min is the lowest role', () => {
    const decision = authorize(policy, 'resource.view', { roles: { resource: 'wizard' } });
    expect(decision).toEqual({ allowed: true, role: 'guest', via: 'resource' });
  });

  it('unknown action at runtime is denied, never throws, never allows', () => {
    const decision = authorize(policy, 'not.a.real.action' as never, { roles: { org: 'owner', resource: 'owner' } });
    expect(decision).toEqual({ allowed: false, reason: 'INSUFFICIENT_ROLE' });
  });

  it('the whole decision path never throws', () => {
    expect(() => authorize(policy, 'resource.view', { roles: {} })).not.toThrow();
    expect(() => authorize(policy, 'org.manage', { roles: { org: {} } })).not.toThrow();
  });
});

describe('authorize: global escalation (opt-in superRole)', () => {
  const escalatingPolicy = definePolicy({
    ladders: roles,
    actions: {
      'resource.edit': { min: 'admin', scope: 'resource' },
    },
    superRole: { scope: 'global', min: 'admin' },
  });

  it('a global admin is allowed an action they have NO resource role for, via: global', () => {
    const decision = authorize(escalatingPolicy, 'resource.edit', { roles: { global: 'admin' } });
    expect(decision).toEqual({ allowed: true, role: 'admin', via: 'global' });
  });

  it('a global role below superRole does NOT escalate', () => {
    const decision = authorize(escalatingPolicy, 'resource.edit', { roles: { global: 'member' } });
    expect(decision).toEqual({ allowed: false, reason: 'NOT_A_MEMBER' });
  });

  it('WITHOUT superRole configured, the same global admin is DENIED — escalation is opt-in only', () => {
    const noEscalationPolicy = definePolicy({
      ladders: roles,
      actions: {
        'resource.edit': { min: 'admin', scope: 'resource' },
      },
    });
    const decision = authorize(noEscalationPolicy, 'resource.edit', { roles: { global: 'admin' } });
    expect(decision).toEqual({ allowed: false, reason: 'NOT_A_MEMBER' });
  });

  it('escalation still denies an unknown action, even for a super-role global admin', () => {
    const decision = authorize(escalatingPolicy, 'no.such.action' as never, { roles: { global: 'admin' } });
    expect(decision).toEqual({ allowed: false, reason: 'INSUFFICIENT_ROLE' });
  });
});

describe('authorize: per-scope ladders and cross-scope isolation', () => {
  const orgLadder = defineRoles(['GUEST', 'MEMBER', 'ADMIN', 'OWNER'] as const);
  const resourceLadder = defineRoles(['VIEWER', 'EDITOR', 'MANAGER'] as const);
  const globalLadder = defineRoles(['user', 'admin'] as const);

  const scopedPolicy = definePolicy({
    ladders: { global: globalLadder, org: orgLadder, resource: resourceLadder },
    actions: {
      'workspace.delete': { scope: 'org', min: 'OWNER' },
      'space.edit': { scope: 'resource', min: 'EDITOR' },
    },
    superRole: { scope: 'global', min: 'admin' },
  });

  it('an org role satisfies an org-scoped rule', () => {
    expect(authorize(scopedPolicy, 'workspace.delete', { roles: { org: 'OWNER' } })).toEqual({
      allowed: true,
      role: 'OWNER',
      via: 'org',
    });
  });

  it('an org role must NEVER satisfy a resource-scoped rule — cross-scope isolation is structural', () => {
    // Only an org role is present, no resource role at all.
    const decision = authorize(scopedPolicy, 'space.edit', { roles: { org: 'OWNER' } });
    expect(decision).toEqual({ allowed: false, reason: 'NOT_A_MEMBER' });
  });

  it('normalization happens against the ladder OF THAT SCOPE: an org-valid value is junk to the resource ladder', () => {
    // 'OWNER' is a real org-ladder role, but it is not a resource-ladder
    // role at all — read as a resource role it must normalize to the
    // RESOURCE ladder's lowest ('VIEWER'), not be treated as valid.
    const decision = authorize(scopedPolicy, 'space.edit', { roles: { resource: 'OWNER' } });
    expect(decision).toEqual({ allowed: false, reason: 'INSUFFICIENT_ROLE' });
    expect(resourceLadder.normalize('OWNER')).toBe('VIEWER');
  });

  it('escalation names which scope grants it: a global admin with no resource role is allowed, via: global', () => {
    const decision = authorize(scopedPolicy, 'space.edit', { roles: { global: 'admin' } });
    expect(decision).toEqual({ allowed: true, role: 'admin', via: 'global' });
  });
});
