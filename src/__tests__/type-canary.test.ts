import { describe, it, expect } from 'vitest';
import { defineRoles } from '../roles';
import { definePolicy, authorize } from '../policy';

/**
 * Type-level canary: an unknown action key must be a COMPILE error, not a
 * silent runtime fallback — mirrors feature-flags-kit's `defineFlags`
 * `@ts-expect-error` canary. This file is typechecked by
 * `tsconfig.typecheck.json` (which includes test files), so the
 * `@ts-expect-error` line below only stays green as long as the key really
 * is rejected by the type checker.
 */
describe('type-level: unknown action key is a compile error', () => {
  it('smoke test to keep the file executable', () => {
    const roles = defineRoles(['guest', 'member', 'admin', 'owner'] as const);
    const policy = definePolicy(roles, {
      'resource.view': { min: 'guest', scope: 'resource' },
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
