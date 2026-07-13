import { describe, expect, it } from 'vitest';
import { defineAccountAdminPolicy, evaluateAccountAdminMutation } from '../accountAdmin';
import { defineRoles } from '../roles';

// These are independent app-shaped policy configurations. They deliberately
// differ in role vocabulary, account-state representation, protected-account
// invariant, and authority rule. The shared engine knows none of those names.

const savoroRoles = defineRoles(['member', 'admin', 'owner'] as const);
const savoroPolicy = defineAccountAdminPolicy({
  roles: savoroRoles,
  statuses: ['active', 'inactive', 'suspended', 'deactivated'] as const,
  activeStatuses: ['active'] as const,
  isProtectedRole: (role) => role === 'owner',
  canManageTarget: ({ actorRole, targetRole }) => actorRole === 'owner' || targetRole === 'member',
  canAssignRole: ({ actorRole, nextRole }) => actorRole === 'owner' || nextRole === 'member',
});

const smarthomeRoles = defineRoles(['user', 'admin'] as const);
const smarthomePolicy = defineAccountAdminPolicy({
  roles: smarthomeRoles,
  // Smart Home has no persisted status column; its adapter supplies this
  // derived vocabulary from the account's active/deactivated state.
  statuses: ['active', 'deactivated'] as const,
  activeStatuses: ['active'] as const,
  isProtectedRole: (role) => role === 'admin',
  canManageTarget: ({ actorRole }) => actorRole === 'admin',
  canAssignRole: ({ actorRole }) => actorRole === 'admin',
});

const sanoRoles = defineRoles(['user', 'admin'] as const);
const sanoPolicy = defineAccountAdminPolicy({
  roles: sanoRoles,
  // Sano OS maps `disabledAt === null` / non-null into these states.
  statuses: ['active', 'disabled'] as const,
  activeStatuses: ['active'] as const,
  isProtectedRole: () => false,
  canManageTarget: ({ actorRole }) => actorRole === 'admin',
  canAssignRole: ({ actorRole }) => actorRole === 'admin',
});

const cairnRoles = defineRoles(['user', 'admin'] as const);
const cairnPolicy = defineAccountAdminPolicy({
  roles: cairnRoles,
  // Cairn maps `isDeactivated` into this vocabulary at its service boundary.
  statuses: ['active', 'deactivated'] as const,
  activeStatuses: ['active'] as const,
  isProtectedRole: () => false,
  canManageTarget: ({ actorRole }) => actorRole === 'admin',
  canAssignRole: ({ actorRole }) => actorRole === 'admin',
});

const bewksRoles = defineRoles(['guest', 'member', 'admin', 'owner'] as const);
const bewksPolicy = defineAccountAdminPolicy({
  roles: bewksRoles,
  // Bewks maps `disabledAt` into this derived state vocabulary.
  statuses: ['active', 'disabled'] as const,
  activeStatuses: ['active'] as const,
  isProtectedRole: (role) => role === 'owner',
  canManageTarget: ({ actorRole, targetRole }) =>
    actorRole === 'owner' || (actorRole === 'admin' && (targetRole === 'guest' || targetRole === 'member')),
  canAssignRole: ({ actorRole, nextRole }) =>
    actorRole === 'owner' || (actorRole === 'admin' && (nextRole === 'guest' || nextRole === 'member')),
});

describe('account-admin mutation policy: app-shaped compatibility fixtures', () => {
  it('Savoro fixture: protects the last active owner', () => {
    expect(evaluateAccountAdminMutation(savoroPolicy, {
      actorId: 'owner-2', actorRole: 'owner',
      target: { id: 'owner-1', role: 'owner', status: 'active' },
      mutation: { kind: 'set-status', status: 'deactivated' },
      activeProtectedPeerCount: 0,
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'LAST_ACTIVE_PROTECTED_ACCOUNT' });
  });

  it('Savoro fixture: fails closed when the in-transaction protected-peer count is missing', () => {
    expect(evaluateAccountAdminMutation(savoroPolicy, {
      actorId: 'owner-2', actorRole: 'owner',
      target: { id: 'owner-1', role: 'owner', status: 'active' },
      mutation: { kind: 'delete' },
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'MISSING_ACTIVE_PROTECTED_PEER_COUNT' });
  });

  it('Smarthome fixture: an unchanged role is a no-op and does not invalidate credentials', () => {
    expect(evaluateAccountAdminMutation(smarthomePolicy, {
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'user-1', role: 'user', status: 'active' },
      mutation: { kind: 'set-role', role: 'user' },
    })).toMatchObject({ allowed: true, outcome: 'no-op', effects: { invalidateCredentials: false } });
  });

  it('Smarthome fixture: a role change invalidates credentials and preserves the last admin', () => {
    expect(evaluateAccountAdminMutation(smarthomePolicy, {
      actorId: 'admin-2', actorRole: 'admin',
      target: { id: 'admin-1', role: 'admin', status: 'active' },
      mutation: { kind: 'set-role', role: 'user' },
      activeProtectedPeerCount: 0,
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'LAST_ACTIVE_PROTECTED_ACCOUNT' });

    expect(evaluateAccountAdminMutation(smarthomePolicy, {
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'user-1', role: 'user', status: 'active' },
      mutation: { kind: 'set-role', role: 'admin' },
    })).toMatchObject({ allowed: true, outcome: 'allowed', effects: { invalidateCredentials: true } });
  });

  it('Sano OS fixture: its disabledAt-derived state cannot self-disable an admin', () => {
    expect(evaluateAccountAdminMutation(sanoPolicy, {
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'admin-1', role: 'admin', status: 'active' },
      mutation: { kind: 'set-status', status: 'disabled' },
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'SELF_DEACTIVATION' });
  });

  it('Cairn fixture: its isDeactivated-derived state cannot self-demote', () => {
    expect(evaluateAccountAdminMutation(cairnPolicy, {
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'admin-1', role: 'admin', status: 'active' },
      mutation: { kind: 'set-role', role: 'user' },
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'SELF_ROLE_REDUCTION' });
  });

  it('Bewks fixture: admins may manage members but not privileged targets', () => {
    expect(evaluateAccountAdminMutation(bewksPolicy, {
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'member-1', role: 'member', status: 'active' },
      mutation: { kind: 'set-status', status: 'disabled' },
    })).toMatchObject({ allowed: true, effects: { invalidateCredentials: true } });

    expect(evaluateAccountAdminMutation(bewksPolicy, {
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'owner-1', role: 'owner', status: 'active' },
      mutation: { kind: 'set-status', status: 'disabled' },
      activeProtectedPeerCount: 1,
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'TARGET_MANAGEMENT_FORBIDDEN' });
  });

  it('fails closed for unknown stored or proposed role/status values in every adapter', () => {
    expect(evaluateAccountAdminMutation(savoroPolicy, {
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'target', role: 'superadmin', status: 'active' },
      mutation: { kind: 'delete' },
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'UNKNOWN_TARGET_ROLE' });

    expect(evaluateAccountAdminMutation(sanoPolicy, {
      actorId: 'admin-1', actorRole: 'admin',
      target: { id: 'target', role: 'user', status: 'active' },
      mutation: { kind: 'set-status', status: 'archived' },
    })).toEqual({ allowed: false, outcome: 'denied', reason: 'UNKNOWN_PROPOSED_STATUS' });
  });
});
