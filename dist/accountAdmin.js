"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.defineAccountAdminPolicy = defineAccountAdminPolicy;
exports.evaluateAccountAdminMutation = evaluateAccountAdminMutation;
/**
 * Defines the PURE policy layer common to account-administration services.
 * Apps load authoritative facts, execute their own transaction, revoke their
 * own credentials, and write their own audit record. This policy only decides
 * whether a proposed mutation is safe and whether it must invalidate access.
 */
function defineAccountAdminPolicy(options) {
    if (options.statuses.length === 0) {
        throw new Error('defineAccountAdminPolicy: statuses must not be empty');
    }
    const knownStatuses = new Set(options.statuses);
    for (const status of options.activeStatuses) {
        if (!knownStatuses.has(status)) {
            throw new Error(`defineAccountAdminPolicy: active status "${status}" is not declared`);
        }
    }
    const activeStatuses = new Set(options.activeStatuses);
    return Object.freeze({
        roles: options.roles,
        statuses: options.statuses,
        isKnownStatus: (status) => typeof status === 'string' && knownStatuses.has(status),
        isActiveStatus: (status) => activeStatuses.has(status),
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
function denied(reason) {
    return { allowed: false, outcome: 'denied', reason };
}
/**
 * Evaluates a role, status, or deletion mutation from already-authoritative
 * facts. `activeProtectedPeerCount` must count OTHER active protected users;
 * it is required only when this mutation would remove an active protected
 * target. Omitting it then fails closed rather than weakening the invariant.
 */
function evaluateAccountAdminMutation(policy, input) {
    if (!policy.roles.isKnown(input.actorRole))
        return denied('UNKNOWN_ACTOR_ROLE');
    if (!policy.roles.isKnown(input.target.role))
        return denied('UNKNOWN_TARGET_ROLE');
    if (!policy.isKnownStatus(input.target.status))
        return denied('UNKNOWN_TARGET_STATUS');
    const actorRole = policy.roles.normalize(input.actorRole);
    const targetRole = policy.roles.normalize(input.target.role);
    const targetStatus = input.target.status;
    const context = {
        actorRole,
        targetRole,
        mutation: input.mutation,
    };
    let nextRole;
    let nextStatus;
    if (input.mutation.kind === 'set-role') {
        if (!policy.roles.isKnown(input.mutation.role))
            return denied('UNKNOWN_PROPOSED_ROLE');
        nextRole = policy.roles.normalize(input.mutation.role);
    }
    if (input.mutation.kind === 'set-status') {
        if (!policy.isKnownStatus(input.mutation.status))
            return denied('UNKNOWN_PROPOSED_STATUS');
        nextStatus = input.mutation.status;
    }
    if (input.actorId === input.target.id) {
        if (input.mutation.kind === 'delete' && policy.selfProtection.preventDeletion) {
            return denied('SELF_DELETION');
        }
        if (input.mutation.kind === 'set-status' &&
            policy.selfProtection.preventDeactivation &&
            policy.isActiveStatus(targetStatus) &&
            !policy.isActiveStatus(nextStatus)) {
            return denied('SELF_DEACTIVATION');
        }
        if (input.mutation.kind === 'set-role' &&
            policy.selfProtection.preventRoleReduction &&
            policy.roles.rank(nextRole) < policy.roles.rank(targetRole)) {
            return denied('SELF_ROLE_REDUCTION');
        }
    }
    if (!policy.canManageTarget(context))
        return denied('TARGET_MANAGEMENT_FORBIDDEN');
    if (input.mutation.kind === 'set-role' &&
        !policy.canAssignRole({ actorRole, targetRole, nextRole: nextRole })) {
        return denied('ROLE_ASSIGNMENT_FORBIDDEN');
    }
    const isNoOp = (input.mutation.kind === 'set-role' && nextRole === targetRole) ||
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
    const removesActiveProtectedTarget = policy.isActiveStatus(targetStatus) &&
        policy.isProtectedRole(targetRole) &&
        (input.mutation.kind === 'delete' ||
            (input.mutation.kind === 'set-role' && !policy.isProtectedRole(nextRole)) ||
            (input.mutation.kind === 'set-status' && !policy.isActiveStatus(nextStatus)));
    if (removesActiveProtectedTarget) {
        if (input.activeProtectedPeerCount === undefined) {
            return denied('MISSING_ACTIVE_PROTECTED_PEER_COUNT');
        }
        if (input.activeProtectedPeerCount <= 0) {
            return denied('LAST_ACTIVE_PROTECTED_ACCOUNT');
        }
    }
    const invalidatesCredentials = input.mutation.kind === 'delete' ||
        input.mutation.kind === 'set-role' ||
        (input.mutation.kind === 'set-status' &&
            policy.isActiveStatus(targetStatus) &&
            !policy.isActiveStatus(nextStatus));
    return {
        allowed: true,
        outcome: 'allowed',
        actorRole,
        targetRole,
        targetStatus,
        effects: { invalidateCredentials: invalidatesCredentials },
    };
}
