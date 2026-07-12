import { describe, it, expect } from 'vitest';
import * as schema from '../schema';
import { MEMBERSHIP_SCHEMA_SQL, MEMBERSHIP_SCHEMA_SQL_POSTGRES } from '../schema';

describe('MEMBERSHIP_SCHEMA_SQL (sqlite)', () => {
  it('creates the table only if it does not already exist', () => {
    expect(MEMBERSHIP_SCHEMA_SQL).toContain('CREATE TABLE IF NOT EXISTS memberships');
  });

  it('has the (scope_type, scope_id, user_id) composite primary key', () => {
    expect(MEMBERSHIP_SCHEMA_SQL).toContain('PRIMARY KEY (scope_type, scope_id, user_id)');
  });

  it('indexes user_id', () => {
    expect(MEMBERSHIP_SCHEMA_SQL).toMatch(/CREATE INDEX IF NOT EXISTS .* ON memberships \(user_id\)/);
  });
});

describe('MEMBERSHIP_SCHEMA_SQL_POSTGRES', () => {
  it('creates the table only if it does not already exist', () => {
    expect(MEMBERSHIP_SCHEMA_SQL_POSTGRES).toContain('CREATE TABLE IF NOT EXISTS memberships');
  });

  it('has the (scope_type, scope_id, user_id) composite primary key', () => {
    expect(MEMBERSHIP_SCHEMA_SQL_POSTGRES).toContain('PRIMARY KEY (scope_type, scope_id, user_id)');
  });

  it('indexes user_id', () => {
    expect(MEMBERSHIP_SCHEMA_SQL_POSTGRES).toMatch(/CREATE INDEX IF NOT EXISTS .* ON memberships \(user_id\)/);
  });

  it('uses TIMESTAMPTZ, not the sqlite text-timestamp form', () => {
    expect(MEMBERSHIP_SCHEMA_SQL_POSTGRES).toContain('TIMESTAMPTZ NOT NULL DEFAULT now()');
  });
});

describe('purity guard: the schema module executes no SQL itself', () => {
  it('exports no run/exec/query function — only string constants', () => {
    const forbidden = /^(run|exec|execute|query)$/i;
    const offendingExports = Object.keys(schema).filter((key) => forbidden.test(key));
    expect(offendingExports).toEqual([]);

    for (const value of Object.values(schema)) {
      expect(typeof value).not.toBe('function');
    }
  });
});
