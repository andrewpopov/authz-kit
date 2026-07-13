import type { RoleLadder } from './roles';
export type AccountAdminMutation = {
    kind: 'set-role';
    role: unknown;
} | {
    kind: 'set-status';
    status: unknown;
} | {
    kind: 'delete';
};
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
export interface DefineAccountAdminPolicyOptions<Roles extends readonly string[], Statuses extends readonly string[]> {
    roles: RoleLadder<Roles>;
    statuses: Statuses;
    activeStatuses: readonly Statuses[number][];
    /** A role that cannot be removed from the active-account population without a peer check. */
    isProtectedRole: (role: Roles[number]) => boolean;
    /** App policy for whether this actor may touch the target's current role. */
    canManageTarget: (context: AccountAdminMutationContext<Roles[number]>) => boolean;
    /** App policy for whether this actor may assign a specific role. */
    canAssignRole: (context: {
        actorRole: Roles[number];
        targetRole: Roles[number];
        nextRole: Roles[number];
    }) => boolean;
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
    canAssignRole: (context: {
        actorRole: Roles[number];
        targetRole: Roles[number];
        nextRole: Roles[number];
    }) => boolean;
    selfProtection: Required<NonNullable<DefineAccountAdminPolicyOptions<Roles, Statuses>['selfProtection']>>;
}
export type AccountAdminDenyReason = 'UNKNOWN_ACTOR_ROLE' | 'UNKNOWN_TARGET_ROLE' | 'UNKNOWN_TARGET_STATUS' | 'UNKNOWN_PROPOSED_ROLE' | 'UNKNOWN_PROPOSED_STATUS' | 'SELF_ROLE_REDUCTION' | 'SELF_DEACTIVATION' | 'SELF_DELETION' | 'TARGET_MANAGEMENT_FORBIDDEN' | 'ROLE_ASSIGNMENT_FORBIDDEN' | 'MISSING_ACTIVE_PROTECTED_PEER_COUNT' | 'LAST_ACTIVE_PROTECTED_ACCOUNT';
export type AccountAdminDecision<Role extends string, Status extends string> = {
    allowed: true;
    outcome: 'allowed' | 'no-op';
    actorRole: Role;
    targetRole: Role;
    targetStatus: Status;
    effects: {
        invalidateCredentials: boolean;
    };
} | {
    allowed: false;
    outcome: 'denied';
    reason: AccountAdminDenyReason;
};
/**
 * Defines the PURE policy layer common to account-administration services.
 * Apps load authoritative facts, execute their own transaction, revoke their
 * own credentials, and write their own audit record. This policy only decides
 * whether a proposed mutation is safe and whether it must invalidate access.
 */
export declare function defineAccountAdminPolicy<const Roles extends readonly string[], const Statuses extends readonly string[]>(options: DefineAccountAdminPolicyOptions<Roles, Statuses>): AccountAdminPolicy<Roles, Statuses>;
/**
 * Evaluates a role, status, or deletion mutation from already-authoritative
 * facts. `activeProtectedPeerCount` must count OTHER active protected users;
 * it is required only when this mutation would remove an active protected
 * target. Omitting it then fails closed rather than weakening the invariant.
 */
export declare function evaluateAccountAdminMutation<Roles extends readonly string[], Statuses extends readonly string[]>(policy: AccountAdminPolicy<Roles, Statuses>, input: {
    actorId: string;
    actorRole: unknown;
    target: AccountAdminTarget;
    mutation: AccountAdminMutation;
    activeProtectedPeerCount?: number;
}): AccountAdminDecision<Roles[number], Statuses[number]>;
