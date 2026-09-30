import { verifyAction, type DashboardAction, type DashboardResult } from '@equinox/core';
import type { BotContext } from '../context.js';
import { resolveAlertMessages, reviewWithFollowUps, saveSetup, sendTestSignal, setupProblem } from '../moderation.js';

/**
 * Carries out a request from the dashboard. The dashboard has already checked that the user
 * manages the server; here the bot checks the request is genuine (signed, recent), that it
 * serves that server, and re-validates everything as if the user had used the Discord command.
 * Every outcome is a fixed result code, never free text, so nothing from here is echoed as HTML.
 */
export async function handleDashboardAction(
  raw: unknown,
  ctx: Pick<BotContext, 'client' | 'deps' | 'stores' | 'guildCache' | 'logger'>,
  signingKey: string,
  now = Date.now(),
): Promise<DashboardResult> {
  const action = verifyAction(signingKey, raw, now);
  if (!action) {
    ctx.logger.warn('rejected a dashboard request: bad signature, too old, or malformed');
    return { code: 'rejected' };
  }
  const guild = ctx.client.guilds.cache.get(action.guildId);
  if (!guild || !(await ctx.deps.guilds.get(action.guildId))) return { code: 'guild_unavailable' };

  switch (action.type) {
    case 'review':
      return review(action, ctx);
    case 'setup': {
      const channel = guild.channels.cache.get(action.alertChannelId) ?? null;
      const modRole = action.modRoleId ? (guild.roles.cache.get(action.modRoleId) ?? null) : null;
      const quarantineRole = action.quarantineRoleId ? (guild.roles.cache.get(action.quarantineRoleId) ?? null) : null;
      // A role ID the server doesn't have is as bad as an unusable role.
      if (action.modRoleId && !modRole) return { code: 'setup_bad_mod_role' };
      if (action.quarantineRoleId && !quarantineRole) return { code: 'setup_bad_quarantine_role' };
      const problem = setupProblem(guild.id, channel, modRole, quarantineRole);
      if (problem) return { code: problem };
      await saveSetup(ctx, {
        guildId: guild.id,
        actorId: action.actorId,
        alertChannelId: action.alertChannelId,
        modRoleId: action.modRoleId,
        quarantineRoleId: action.quarantineRoleId,
        via: 'dashboard',
      });
      return { code: 'setup_saved' };
    }
    case 'test': {
      const result = await sendTestSignal(ctx, { guildId: guild.id, actorId: action.actorId, via: 'dashboard' });
      return { code: result.status === 'detected' ? 'test_sent' : 'test_not_detected' };
    }
  }
}

async function review(
  action: Extract<DashboardAction, { type: 'review' }>,
  ctx: Pick<BotContext, 'client' | 'deps' | 'stores'>,
): Promise<DashboardResult> {
  const { result, notes } = await reviewWithFollowUps(
    { guildId: action.guildId, detectionId: action.detectionId, decision: action.decision, actorId: action.actorId, via: 'dashboard' },
    ctx,
  );
  if (result.status === 'not_found') return { code: 'not_found' };
  if (result.status === 'already_resolved') return { code: 'already_resolved' };
  // Resolve the alerts in Discord too, so nobody acts on a stale one.
  await resolveAlertMessages(ctx.client, result.detection, result.detection.status, action.actorId, [...notes, 'Resolved from the dashboard'].join('\n'));
  return { code: 'reviewed' };
}
