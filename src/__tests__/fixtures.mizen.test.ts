import { describe, it, expect } from 'vitest';
import { defineRoles } from '../roles';
import { definePolicy, authorize } from '../policy';

/**
 * Behavioral-superset fixture: reproduces mizen's `packages/authorization`
 * (`authorize(action, {workspaceRole, spaceRole})`) on top of
 * `definePolicy`/`authorize`. mizen's `WorkspaceRole` ('OWNER'|'ADMIN'|
 * 'MEMBER'|'GUEST', high to low) maps onto our `org` scope; its
 * `SpaceRole` ('MANAGER'|'EDITOR'|'COMMENTER'|'VIEWER', high to low) maps
 * onto our `resource` scope. Both role vocabularies live on ONE combined
 * ladder here (lowest -> highest) — that's safe because org-scope rules
 * only ever compare an org role against another org role, and
 * resource-scope rules only ever compare a resource role against another
 * resource role; the two groups never cross-compare, so their relative
 * ordering against each other is irrelevant.
 *
 * Test cases are ported directly from mizen's `src/index.test.ts`.
 */

const roles = defineRoles([
  'guest',
  'member',
  'admin',
  'owner', // org group, low -> high
  'viewer',
  'commenter',
  'editor',
  'manager', // resource group, low -> high
] as const);

const mizenPolicy = definePolicy(roles, {
  'workspace.delete': { min: 'owner', scope: 'org' },
  'workspace.manage': { min: 'admin', scope: 'org' },
  'workspace.invite': { min: 'admin', scope: 'org' },
  'integration.install': { min: 'admin', scope: 'org' },
  'integration.manage': { min: 'admin', scope: 'org' },
  'audit.view': { min: 'admin', scope: 'org' },
  'export.create': { min: 'admin', scope: 'org' },
  'workspace.view': { min: 'guest', scope: 'org' },
  'integration.use': { min: 'guest', scope: 'org' },
  'space.view': { min: 'viewer', scope: 'resource' },
  'item.view': { min: 'viewer', scope: 'resource' },
  'file.download': { min: 'viewer', scope: 'resource' },
  'item.comment': { min: 'commenter', scope: 'resource' },
  'space.manage': { min: 'manager', scope: 'resource' },
  'item.share': { min: 'manager', scope: 'resource' },
  'space.create_item': { min: 'editor', scope: 'resource' },
  'item.edit': { min: 'editor', scope: 'resource' },
  'item.move': { min: 'editor', scope: 'resource' },
  'item.archive': { min: 'editor', scope: 'resource' },
  'file.upload': { min: 'editor', scope: 'resource' },
  'file.replace': { min: 'editor', scope: 'resource' },
});

describe('mizen authorization fixture', () => {
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
});
