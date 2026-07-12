import { describe, it, expect } from 'vitest';
import { defineRoles } from '../roles';
import { definePolicy, authorize } from '../policy';

const roles = defineRoles(['guest', 'member', 'admin', 'owner'] as const);

const policy = definePolicy(roles, {
  'org.manage': { min: 'admin', scope: 'org' },
  'resource.view': { min: 'guest', scope: 'resource' },
  'resource.edit': { min: 'member' }, // scope omitted -> defaults to 'resource'
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

  it('a scope omitted on an ActionRule defaults to resource', () => {
    expect(authorize(policy, 'resource.edit', { roles: { resource: 'member' } })).toEqual({
      allowed: true,
      role: 'member',
      via: 'resource',
    });
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
  const escalatingPolicy = definePolicy(
    roles,
    {
      'resource.edit': { min: 'admin', scope: 'resource' },
    },
    { superRole: 'admin' },
  );

  it('a global admin is allowed an action they have NO resource role for, via: global', () => {
    const decision = authorize(escalatingPolicy, 'resource.edit', { roles: { global: 'admin' } });
    expect(decision).toEqual({ allowed: true, role: 'admin', via: 'global' });
  });

  it('a global role below superRole does NOT escalate', () => {
    const decision = authorize(escalatingPolicy, 'resource.edit', { roles: { global: 'member' } });
    expect(decision).toEqual({ allowed: false, reason: 'NOT_A_MEMBER' });
  });

  it('WITHOUT superRole configured, the same global admin is DENIED — escalation is opt-in only', () => {
    const noEscalationPolicy = definePolicy(roles, {
      'resource.edit': { min: 'admin', scope: 'resource' },
    });
    const decision = authorize(noEscalationPolicy, 'resource.edit', { roles: { global: 'admin' } });
    expect(decision).toEqual({ allowed: false, reason: 'NOT_A_MEMBER' });
  });

  it('escalation still denies an unknown action, even for a super-role global admin', () => {
    const decision = authorize(escalatingPolicy, 'no.such.action' as never, { roles: { global: 'admin' } });
    expect(decision).toEqual({ allowed: false, reason: 'INSUFFICIENT_ROLE' });
  });
});
