import type { RoleLadder } from './roles';

export type AccountAdminMutation =
  | { kind: 'set-role'; role: unknown }
  | { kind: 'set-status'; status: unknown }
  | { kind: 'delete' };

export interface AccountAdminTarget {
  id: string;
  role: unknown;
  status: unknown;
}

export interface AccountAdminMutationContext<Role extends string> {
  actorRole: Role;
  targetRole: Role;
  mutation: AccountAdminMutation;
}

export interface DefineAccountAdminPolicyOptions<
  Roles extends readonly string[],
  Statuses extends readonly string[],
> {
  roles: RoleLadder<Roles>;
  statuses: Statuses;
  activeStatuses: readonly Statuses[number][];
  /** A role that cannot be removed from the active-account population without a peer check. */
  isProtectedRole: (role: Roles[number]) => boolean;
  /** App policy for whether this actor may touch the target's current role. */
  canManageTarget: (context: AccountAdminMutationContext<Roles[number]>) => boolean;
  /** App policy for whether this actor may assign a specific role. */
  canAssignRole: (context: { actorRole: Roles[number]; targetRole: Roles[number]; nextRole: Roles[number] }) => boolean;
  selfProtection?: {
    preventRoleReduction?: boolean;
    preventDeactivation?: boolean;
    preventDeletion?: boolean;
  };
}

export interface AccountAdminPolicy<Roles extends readonly string[], Statuses extends readonly string[]> {
  roles: RoleLadder<Roles>;
  statuses: Statuses;
  isKnownStatus: (status: unknown) => status is Statuses[number];
  isActiveStatus: (status: Statuses[number]) => boolean;
  isProtectedRole: (role: Roles[number]) => boolean;
  canManageTarget: (context: AccountAdminMutationContext<Roles[number]>) => boolean;
  canAssignRole: (context: { actorRole: Roles[number]; targetRole: Roles[number]; nextRole: Roles[number] }) => boolean;
  selfProtection: Required<NonNullable<DefineAccountAdminPolicyOptions<Roles, Statuses>['selfProtection']>>;
}

export type AccountAdminDenyReason =
  | 'UNKNOWN_ACTOR_ROLE'
  | 'UNKNOWN_TARGET_ROLE'
  | 'UNKNOWN_TARGET_STATUS'
  | 'UNKNOWN_PROPOSED_ROLE'
  | 'UNKNOWN_PROPOSED_STATUS'
  | 'SELF_ROLE_REDUCTION'
  | 'SELF_DEACTIVATION'
  | 'SELF_DELETION'
  | 'TARGET_MANAGEMENT_FORBIDDEN'
  | 'ROLE_ASSIGNMENT_FORBIDDEN'
  | 'MISSING_ACTIVE_PROTECTED_PEER_COUNT'
  | 'LAST_ACTIVE_PROTECTED_ACCOUNT';

export type AccountAdminDecision<Role extends string, Status extends string> =
  | {
      allowed: true;
      outcome: 'allowed' | 'no-op';
      actorRole: Role;
      targetRole: Role;
      targetStatus: Status;
      effects: { invalidateCredentials: boolean };
    }
  | { allowed: false; outcome: 'denied'; reason: AccountAdminDenyReason };

/**
 * Defines the PURE policy layer common to account-administration services.
 * Apps load authoritative facts, execute their own transaction, revoke their
 * own credentials, and write their own audit record. This policy only decides
 * whether a proposed mutation is safe and whether it must invalidate access.
 */
export function defineAccountAdminPolicy<
  const Roles extends readonly string[],
  const Statuses extends readonly string[],
>(options: DefineAccountAdminPolicyOptions<Roles, Statuses>): AccountAdminPolicy<Roles, Statuses> {
  if (options.statuses.length === 0) {
    throw new Error('defineAccountAdminPolicy: statuses must not be empty');
  }

  const knownStatuses = new Set<string>(options.statuses);
  for (const status of options.activeStatuses) {
    if (!knownStatuses.has(status)) {
      throw new Error(`defineAccountAdminPolicy: active status "${status}" is not declared`);
    }
  }

  const activeStatuses = new Set<string>(options.activeStatuses);
  return Object.freeze({
    roles: options.roles,
    statuses: options.statuses,
    isKnownStatus: (status: unknown): status is Statuses[number] =>
      typeof status === 'string' && knownStatuses.has(status),
    isActiveStatus: (status: Statuses[number]) => activeStatuses.has(status),
    isProtectedRole: options.isProtectedRole,
    canManageTarget: options.canManageTarget,
    canAssignRole: options.canAssignRole,
    selfProtection: {
      preventRoleReduction: options.selfProtection?.preventRoleReduction ?? true,
      preventDeactivation: options.selfProtection?.preventDeactivation ?? true,
      preventDeletion: options.selfProtection?.preventDeletion ?? true,
    },
  });
}

function denied(reason: AccountAdminDenyReason): AccountAdminDecision<never, never> {
  return { allowed: false, outcome: 'denied', reason };
}

/**
 * Evaluates a role, status, or deletion mutation from already-authoritative
 * facts. `activeProtectedPeerCount` must count OTHER active protected users;
 * it is required only when this mutation would remove an active protected
 * target. Omitting it then fails closed rather than weakening the invariant.
 */
export function evaluateAccountAdminMutation<
  Roles extends readonly string[],
  Statuses extends readonly string[],
>(
  policy: AccountAdminPolicy<Roles, Statuses>,
  input: {
    actorId: string;
    actorRole: unknown;
    target: AccountAdminTarget;
    mutation: AccountAdminMutation;
    activeProtectedPeerCount?: number;
  },
): AccountAdminDecision<Roles[number], Statuses[number]> {
  if (!policy.roles.isKnown(input.actorRole)) return denied('UNKNOWN_ACTOR_ROLE');
  if (!policy.roles.isKnown(input.target.role)) return denied('UNKNOWN_TARGET_ROLE');
  if (!policy.isKnownStatus(input.target.status)) return denied('UNKNOWN_TARGET_STATUS');

  const actorRole = policy.roles.normalize(input.actorRole);
  const targetRole = policy.roles.normalize(input.target.role);
  const targetStatus = input.target.status;
  const context: AccountAdminMutationContext<Roles[number]> = {
    actorRole,
    targetRole,
    mutation: input.mutation,
  };

  let nextRole: Roles[number] | undefined;
  let nextStatus: Statuses[number] | undefined;
  if (input.mutation.kind === 'set-role') {
    if (!policy.roles.isKnown(input.mutation.role)) return denied('UNKNOWN_PROPOSED_ROLE');
    nextRole = policy.roles.normalize(input.mutation.role);
  }
  if (input.mutation.kind === 'set-status') {
    if (!policy.isKnownStatus(input.mutation.status)) return denied('UNKNOWN_PROPOSED_STATUS');
    nextStatus = input.mutation.status;
  }

  if (input.actorId === input.target.id) {
    if (input.mutation.kind === 'delete' && policy.selfProtection.preventDeletion) {
      return denied('SELF_DELETION');
    }
    if (
      input.mutation.kind === 'set-status' &&
      policy.selfProtection.preventDeactivation &&
      policy.isActiveStatus(targetStatus) &&
      !policy.isActiveStatus(nextStatus as Statuses[number])
    ) {
      return denied('SELF_DEACTIVATION');
    }
    if (
      input.mutation.kind === 'set-role' &&
      policy.selfProtection.preventRoleReduction &&
      policy.roles.rank(nextRole as Roles[number]) < policy.roles.rank(targetRole)
    ) {
      return denied('SELF_ROLE_REDUCTION');
    }
  }

  if (!policy.canManageTarget(context)) return denied('TARGET_MANAGEMENT_FORBIDDEN');
  if (
    input.mutation.kind === 'set-role' &&
    !policy.canAssignRole({ actorRole, targetRole, nextRole: nextRole as Roles[number] })
  ) {
    return denied('ROLE_ASSIGNMENT_FORBIDDEN');
  }

  const isNoOp =
    (input.mutation.kind === 'set-role' && nextRole === targetRole) ||
    (input.mutation.kind === 'set-status' && nextStatus === targetStatus);
  if (isNoOp) {
    return {
      allowed: true,
      outcome: 'no-op',
      actorRole,
      targetRole,
      targetStatus,
      effects: { invalidateCredentials: false },
    };
  }

  const removesActiveProtectedTarget =
    policy.isActiveStatus(targetStatus) &&
    policy.isProtectedRole(targetRole) &&
    (input.mutation.kind === 'delete' ||
      (input.mutation.kind === 'set-role' && !policy.isProtectedRole(nextRole as Roles[number])) ||
      (input.mutation.kind === 'set-status' && !policy.isActiveStatus(nextStatus as Statuses[number])));

  if (removesActiveProtectedTarget) {
    if (input.activeProtectedPeerCount === undefined) {
      return denied('MISSING_ACTIVE_PROTECTED_PEER_COUNT');
    }
    if (input.activeProtectedPeerCount <= 0) {
      return denied('LAST_ACTIVE_PROTECTED_ACCOUNT');
    }
  }

  const invalidatesCredentials =
    input.mutation.kind === 'delete' ||
    input.mutation.kind === 'set-role' ||
    (input.mutation.kind === 'set-status' &&
      policy.isActiveStatus(targetStatus) &&
      !policy.isActiveStatus(nextStatus as Statuses[number]));

  return {
    allowed: true,
    outcome: 'allowed',
    actorRole,
    targetRole,
    targetStatus,
    effects: { invalidateCredentials: invalidatesCredentials },
  };
}
