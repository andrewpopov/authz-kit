import { describe, it, expect } from 'vitest';
import { defineRoles } from '../roles';
import { definePolicy, authorize } from '../policy';

/**
 * Behavioral-superset fixture: reproduces mizen's `packages/authorization`
 * (`authorize(action, {workspaceRole, spaceRole})`) on top of
 * `definePolicy`/`authorize`. mizen's `WorkspaceRole` (`@mizen/types`:
 * `'OWNER'|'ADMIN'|'MEMBER'|'GUEST'`, high to low) and `SpaceRole`
 * (`'MANAGER'|'EDITOR'|'COMMENTER'|'VIEWER'`, high to low) are genuinely
 * INDEPENDENT vocabularies in mizen — two separate enums, never compared to
 * each other. This fixture ports them as TWO SEPARATE `defineRoles`
 * ladders (`org` for workspace, `resource` for space), not one merged
 * ladder: cross-scope isolation is now structural, so a workspace role can
 * never accidentally satisfy a space-scoped rule (and vice versa) even by
 * ladder-position coincidence.
 *
 * Test cases are ported directly from mizen's `src/index.test.ts`.
 */

const workspace = defineRoles(['GUEST', 'MEMBER', 'ADMIN', 'OWNER'] as const);
const space = defineRoles(['VIEWER', 'COMMENTER', 'EDITOR', 'MANAGER'] as const);

const mizenPolicy = definePolicy({
  ladders: { org: workspace, resource: space },
  actions: {
    'workspace.delete': { min: 'OWNER', scope: 'org' },
    'workspace.manage': { min: 'ADMIN', scope: 'org' },
    'workspace.invite': { min: 'ADMIN', scope: 'org' },
    'integration.install': { min: 'ADMIN', scope: 'org' },
    'integration.manage': { min: 'ADMIN', scope: 'org' },
    'audit.view': { min: 'ADMIN', scope: 'org' },
    'export.create': { min: 'ADMIN', scope: 'org' },
    'workspace.view': { min: 'GUEST', scope: 'org' },
    'integration.use': { min: 'GUEST', scope: 'org' },
    'space.view': { min: 'VIEWER', scope: 'resource' },
    'item.view': { min: 'VIEWER', scope: 'resource' },
    'file.download': { min: 'VIEWER', scope: 'resource' },
    'item.comment': { min: 'COMMENTER', scope: 'resource' },
    'space.manage': { min: 'MANAGER', scope: 'resource' },
    'item.share': { min: 'MANAGER', scope: 'resource' },
    'space.create_item': { min: 'EDITOR', scope: 'resource' },
    'item.edit': { min: 'EDITOR', scope: 'resource' },
    'item.move': { min: 'EDITOR', scope: 'resource' },
    'item.archive': { min: 'EDITOR', scope: 'resource' },
    'file.upload': { min: 'EDITOR', scope: 'resource' },
    'file.replace': { min: 'EDITOR', scope: 'resource' },
  },
});

describe('mizen authorization fixture (two independent ladders: workspace + space)', () => {
  it('fails closed when the actor is not a workspace member', () => {
    expect(authorize(mizenPolicy, 'item.view', { roles: {} })).toEqual({
      allowed: false,
      reason: 'NOT_A_MEMBER',
    });
  });

  it('reserves workspace deletion for owners', () => {
    expect(authorize(mizenPolicy, 'workspace.delete', { roles: { org: 'ADMIN' } }).allowed).toBe(false);
    expect(authorize(mizenPolicy, 'workspace.delete', { roles: { org: 'OWNER' } }).allowed).toBe(true);
  });

  it('lets viewers read but never mutate content', () => {
    const context = { roles: { org: 'MEMBER', resource: 'VIEWER' } };
    expect(authorize(mizenPolicy, 'item.view', context).allowed).toBe(true);
    expect(authorize(mizenPolicy, 'item.edit', context).allowed).toBe(false);
  });

  it('reserves workspace export for workspace managers', () => {
    expect(authorize(mizenPolicy, 'export.create', { roles: { org: 'MEMBER' } }).allowed).toBe(false);
    expect(authorize(mizenPolicy, 'export.create', { roles: { org: 'ADMIN' } }).allowed).toBe(true);
  });

  it('any workspace member can view the workspace and use integrations', () => {
    expect(authorize(mizenPolicy, 'workspace.view', { roles: { org: 'GUEST' } }).allowed).toBe(true);
    expect(authorize(mizenPolicy, 'integration.use', { roles: { org: 'GUEST' } }).allowed).toBe(true);
  });

  it('a commenter can comment but not edit; an editor can edit but not manage the space', () => {
    const commenter = { roles: { org: 'MEMBER', resource: 'COMMENTER' } };
    const editor = { roles: { org: 'MEMBER', resource: 'EDITOR' } };
    expect(authorize(mizenPolicy, 'item.comment', commenter).allowed).toBe(true);
    expect(authorize(mizenPolicy, 'item.edit', commenter).allowed).toBe(false);
    expect(authorize(mizenPolicy, 'item.edit', editor).allowed).toBe(true);
    expect(authorize(mizenPolicy, 'space.manage', editor).allowed).toBe(false);
  });

  it('only a manager can manage the space or share an item', () => {
    const editor = { roles: { org: 'MEMBER', resource: 'EDITOR' } };
    const manager = { roles: { org: 'MEMBER', resource: 'MANAGER' } };
    expect(authorize(mizenPolicy, 'space.manage', editor).allowed).toBe(false);
    expect(authorize(mizenPolicy, 'item.share', editor).allowed).toBe(false);
    expect(authorize(mizenPolicy, 'space.manage', manager).allowed).toBe(true);
    expect(authorize(mizenPolicy, 'item.share', manager).allowed).toBe(true);
  });

  // The whole point of the per-scope change: cross-scope isolation is now
  // structural. A workspace (org) role, however high, must never satisfy a
  // space (resource) scoped rule when no resource role is present at all.
  it('cross-scope isolation: a workspace OWNER role never satisfies a resource-scoped rule with no resource role', () => {
    expect(authorize(mizenPolicy, 'item.edit', { roles: { org: 'OWNER' } })).toEqual({
      allowed: false,
      reason: 'NOT_A_MEMBER',
    });
  });

  // Normalization happens against the ladder OF THAT SCOPE: 'OWNER' is a
  // real workspace-ladder role but junk to the space ladder, so read as a
  // resource role it normalizes to the RESOURCE ladder's lowest ('VIEWER').
  it('normalization is scope-local: a workspace-valid value is junk to the space ladder', () => {
    expect(space.normalize('OWNER')).toBe('VIEWER');
    expect(authorize(mizenPolicy, 'space.manage', { roles: { org: 'MEMBER', resource: 'OWNER' } })).toEqual({
      allowed: false,
      reason: 'INSUFFICIENT_ROLE',
    });
  });
});
