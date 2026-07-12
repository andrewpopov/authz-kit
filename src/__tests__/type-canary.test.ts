import { describe, it, expect } from 'vitest';
import { defineRoles } from '../roles';
import { definePolicy, authorize } from '../policy';

/**
 * Type-level canaries: these must be COMPILE errors, not silent runtime
 * fallbacks — mirrors feature-flags-kit's `defineFlags` `@ts-expect-error`
 * canary. This file is typechecked by `tsconfig.typecheck.json` (which
 * includes test files), so each `@ts-expect-error` line only stays green
 * as long as the type checker really does reject it.
 */
describe('type-level: unknown action key is a compile error', () => {
  it('smoke test to keep the file executable', () => {
    const roles = defineRoles(['guest', 'member', 'admin', 'owner'] as const);
    const policy = definePolicy({
      ladders: roles,
      actions: {
        'resource.view': { min: 'guest', scope: 'resource' },
      },
    });

    const decision = authorize(policy, 'resource.view', { roles: { resource: 'guest' } });
    expect(decision.allowed).toBe(true);

    // Never actually invoked — this only needs to fail typecheck, not throw at runtime.
    const callWithUnknownAction = () =>
      // @ts-expect-error -- 'not.a.real.action' is not part of the policy's action key union.
      authorize(policy, 'not.a.real.action', { roles: {} });
    expect(typeof callWithUnknownAction).toBe('function');
  });
});

describe('type-level: min is constrained to the ladder of that action\'s OWN scope', () => {
  it('smoke test to keep the file executable', () => {
    const org = defineRoles(['GUEST', 'MEMBER', 'ADMIN', 'OWNER'] as const);
    const resource = defineRoles(['VIEWER', 'EDITOR', 'MANAGER'] as const);

    const orgOnlyMin = { scope: 'resource' as const, min: 'OWNER' as const };

    const defineWithCrossScopeMin = () =>
      // @ts-expect-error -- 'OWNER' is an org-only role; the resource ladder has no 'OWNER'.
      definePolicy({
        ladders: { org, resource },
        actions: {
          'space.edit': orgOnlyMin,
        },
      });
    expect(typeof defineWithCrossScopeMin).toBe('function');
  });
});

describe('type-level: an action naming a scope with no configured ladder is a compile error', () => {
  it('smoke test to keep the file executable', () => {
    const org = defineRoles(['GUEST', 'MEMBER', 'ADMIN', 'OWNER'] as const);

    const unconfiguredScopeAction = { scope: 'resource' as const, min: 'EDITOR' as const };

    const defineWithUnconfiguredScope = () =>
      // @ts-expect-error -- 'resource' has no configured ladder in `ladders`.
      definePolicy({
        // No 'resource' ladder configured — only 'org'.
        ladders: { org },
        actions: {
          'space.edit': unconfiguredScopeAction,
        },
      });
    expect(typeof defineWithUnconfiguredScope).toBe('function');
  });
});
