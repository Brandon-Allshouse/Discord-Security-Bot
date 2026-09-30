import { canModerate } from '@equinox/core';

/**
 * Who may run what, inside one tenant (Discord server).
 * - admin: Manage Server. Changes how the sensor behaves or who can moderate.
 * - mod:   admin, or a member holding the tenant's configured mod role.
 */
export type AccessLevel = 'admin' | 'mod';

export const COMMAND_ACCESS: Readonly<Record<string, AccessLevel>> = {
  setup: 'admin',
  mode: 'admin',
  'allow.add': 'admin',
  'allow.remove': 'admin',
  status: 'mod',
  test: 'mod',
  check: 'mod',
  'allow.list': 'mod',
};

/** Anything not in the table needs admin. If we forget to add a new command, it fails closed. */
export function requiredAccess(route: string): AccessLevel {
  return COMMAND_ACCESS[route] ?? 'admin';
}

export interface MemberAccess {
  hasManageGuild: boolean;
  roleIds: readonly string[];
}

export function isAuthorized(level: AccessLevel, member: MemberAccess, modRoleIds: readonly string[]): boolean {
  return level === 'admin' ? member.hasManageGuild : canModerate(member, modRoleIds);
}
