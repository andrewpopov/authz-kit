import { describe, expect, it } from 'vitest';
import { defineAccountAdminPolicy, evaluateAccountAdminMutation } from '../accountAdmin';
import { defineRoles } from '../roles';

const roles = defineRoles(['user', 'admin', 'owner'] as const);
const policy = defineAccountAdminPolicy({
  roles,
  statuses: ['active', 'deactivated', 'suspended'] as const,
  activeStatuses: ['active'] as const,
  isProtectedRole: (role) => role === 'owner',
  // Matches the common fleet shape: owners can manage everyone; admins can
  // manage ordinary users but not another privileged account.
  canManageTarget: ({ actorRole, targetRole }) => actorRole === 'owner' || targetRole === 'user',
  canAssignRole: ({ actorRole, nextRole }) => actorRole === 'owner' || nextRole === 'user',
});

function evaluate(input: Parameters<typeof evaluateAccountAdminMutation<typeof roles.roles, readonly ['active', 'deactivated', 'suspended']>>[1]) {
  return evaluateAccountAdminMutation(policy, input);
}

describe('account-admin mutation policy: source-derived guards', () => {
  it('Savoro fixture: blocks removal of the last active owner', () => {
    expect(evaluate({
      actorId: 'owner-2', actorRole: 'owner',
      target: { id: 'owner-1', role: 'owner', status: 'active' },
      mutation: { kind: 'set-status', status: 'deactivated' },
      activeProtectedPeerCount: 0,
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'LAST_ACTIVE_PROTECTED_ACCOUNT' });
  });

  it('Savoro fixture: fails closed when the transactional active-owner count is missing', () => {
    expect(evaluate({
      actorId: 'owner-2', actorRole: 'owner',
      target: { id: 'owner-1', role: 'owner', status: 'active' },
      mutation: { kind: 'delete' },
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'MISSING_ACTIVE_PROTECTED_PEER_COUNT' });
  });

  it('Smarthome fixture: unchanged role is a no-op and does not invalidate credentials', () => {
    expect(evaluate({
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'user-1', role: 'user', status: 'active' },
      mutation: { kind: 'set-role', role: 'user' },
    })).toMatchObject({ allowed: true, outcome: 'no-op', effects: { invalidateCredentials: false } });
  });

  it('Smarthome fixture: an effective role change invalidates credentials', () => {
    expect(evaluate({
      actorId: 'owner-1', actorRole: 'owner',
      target: { id: 'user-1', role: 'user', status: 'active' },
      mutation: { kind: 'set-role', role: 'admin' },
    })).toMatchObject({ allowed: true, outcome: 'allowed', effects: { invalidateCredentials: true } });
  });

  it('Sano OS fixture: self-deactivation is forbidden', () => {
    expect(evaluate({
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'admin-1', role: 'admin', status: 'active' },
      mutation: { kind: 'set-status', status: 'deactivated' },
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'SELF_DEACTIVATION' });
  });

  it('Cairn fixture: self-demotion is forbidden', () => {
    expect(evaluate({
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'admin-1', role: 'admin', status: 'active' },
      mutation: { kind: 'set-role', role: 'user' },
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'SELF_ROLE_REDUCTION' });
  });

  it('Bewks fixture: a non-owner cannot manage a privileged target', () => {
    expect(evaluate({
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'owner-1', role: 'owner', status: 'active' },
      mutation: { kind: 'set-status', status: 'deactivated' },
      activeProtectedPeerCount: 1,
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'TARGET_MANAGEMENT_FORBIDDEN' });
  });

  it('rejects unknown stored role and status values instead of treating them as ordinary accounts', () => {
    expect(evaluate({
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'target', role: 'superadmin', status: 'active' },
      mutation: { kind: 'delete' },
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'UNKNOWN_TARGET_ROLE' });

    expect(evaluate({
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'target', role: 'user', status: 'unknown-status' },
      mutation: { kind: 'delete' },
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'UNKNOWN_TARGET_STATUS' });
  });
});
