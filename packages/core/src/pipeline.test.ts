import { describe, expect, it } from 'vitest';
import { processSignal } from './pipeline.js';
import { canModerate, reviewDetection } from './review.js';
import { createFakeDeps, makeGuild, makeSignal } from './testing.js';

describe('processSignal', () => {
  it('rejects malformed signals before doing anything', async () => {
    const fake = createFakeDeps([makeGuild()]);
    await expect(processSignal({ ...makeSignal(), guildId: 'not-a-snowflake' }, fake.deps)).rejects.toThrow();
    await expect(processSignal({ ...makeSignal(), heuristicScore: 5 }, fake.deps)).rejects.toThrow();
    expect(fake.audit).toHaveLength(0);
  });

  it('ignores guilds that are not registered', async () => {
    const fake = createFakeDeps([]);
    expect(await processSignal(makeSignal(), fake.deps)).toEqual({ status: 'ignored', reason: 'guild_not_registered' });
  });

  it('does nothing for clean signals', async () => {
    const fake = createFakeDeps([makeGuild()]);
    const result = await processSignal(makeSignal({ heuristicScore: 0.1 }), fake.deps);
    expect(result.status).toBe('clean');
    expect(fake.executed).toHaveLength(0);
    expect(fake.audit).toHaveLength(0);
  });

  it('flows a fake signal end to end in alert_only: detection, alert, audit', async () => {
    const fake = createFakeDeps([makeGuild({ mode: 'alert_only' })]);
    const result = await processSignal(makeSignal(), fake.deps);

    expect(result.status).toBe('detected');
    if (result.status !== 'detected') return;
    expect(fake.executed.map((e) => e.action)).toEqual(['alert']);
    expect(fake.detections.get(result.detection.id)?.actionsTaken).toEqual([{ action: 'alert', ok: true }]);
    expect(fake.audit.map((a) => a.action)).toEqual(['detection.created', 'action.alert']);
    expect(fake.audit.every((a) => a.actor === 'bot')).toBe(true);
  });

  it('deletes then alerts in protect mode', async () => {
    const fake = createFakeDeps([makeGuild({ mode: 'protect' })]);
    await processSignal(makeSignal(), fake.deps);
    expect(fake.executed.map((e) => e.action)).toEqual(['delete', 'alert']);
  });

  it('keeps going when an action fails, and never leaks error internals', async () => {
    const fake = createFakeDeps([makeGuild({ mode: 'protect' })]);
    fake.failing.add('delete');
    const result = await processSignal(makeSignal(), fake.deps);
    if (result.status !== 'detected') throw new Error('expected detection');

    expect(result.outcomes).toEqual([
      { action: 'delete', ok: false, detail: 'Action failed' },
      { action: 'alert', ok: true },
    ]);
    expect(JSON.stringify(fake.audit)).not.toContain('boom');
  });

  it('lets the tenant allowlist override a high score: no detection, no audit noise', async () => {
    const fake = createFakeDeps([makeGuild()]);
    const signal = makeSignal({ heuristicScore: 1 });
    fake.allowlist.add(`${signal.guildId}:${signal.subject}`);
    expect((await processSignal(signal, fake.deps)).status).toBe('clean');
    expect(fake.detections.size).toBe(0);
    expect(fake.audit).toHaveLength(0);
  });

  it('stores outcomes under the signal’s own tenant', async () => {
    const fake = createFakeDeps([makeGuild()]);
    const result = await processSignal(makeSignal(), fake.deps);
    if (result.status !== 'detected') throw new Error('expected detection');
    expect(fake.detections.get(result.detection.id)?.guildId).toBe('100000000000000001');
    expect(fake.audit.every((a) => a.guildId === '100000000000000001')).toBe(true);
  });

  it('treats blocklisted subjects as malicious even with a low heuristic score', async () => {
    const fake = createFakeDeps([makeGuild()]);
    const signal = makeSignal({ heuristicScore: 0 });
    fake.blocklist.add(signal.subject);
    const result = await processSignal(signal, fake.deps);
    expect(result.status === 'detected' && result.verdict.level).toBe('malicious');
  });
});

describe('reviewDetection', () => {
  async function detectedInStrictJoin() {
    const guild = makeGuild({ mode: 'strict' });
    const fake = createFakeDeps([guild]);
    const result = await processSignal(makeSignal({ kind: 'member_join', heuristicScore: 0.95 }), fake.deps);
    if (result.status !== 'detected') throw new Error('expected detection');
    return { fake, guild, detection: result.detection };
  }

  it('restore reverts reversible actions and audits the moderator', async () => {
    const { fake, guild, detection } = await detectedInStrictJoin();
    const result = await reviewDetection(
      { guildId: guild.id, detectionId: detection.id, decision: 'restore', actorId: '500000000000000001' },
      fake.deps,
    );
    expect(result.status).toBe('done');
    expect(fake.reverted.map((r) => r.action)).toEqual(['quarantine']);
    expect(fake.detections.get(detection.id)?.status).toBe('restored');
    expect(fake.audit.at(-1)).toMatchObject({ actor: '500000000000000001', action: 'review.restore' });
  });

  it('confirm keeps actions in place', async () => {
    const { fake, guild, detection } = await detectedInStrictJoin();
    await reviewDetection(
      { guildId: guild.id, detectionId: detection.id, decision: 'confirm', actorId: '500000000000000001' },
      fake.deps,
    );
    expect(fake.reverted).toHaveLength(0);
    expect(fake.detections.get(detection.id)?.status).toBe('confirmed');
  });

  it('false_positive reverts and is terminal', async () => {
    const { fake, guild, detection } = await detectedInStrictJoin();
    const input = { guildId: guild.id, detectionId: detection.id, actorId: '500000000000000001' };
    await reviewDetection({ ...input, decision: 'false_positive' }, fake.deps);
    const again = await reviewDetection({ ...input, decision: 'confirm' }, fake.deps);
    expect(again.status).toBe('already_resolved');
    expect(fake.detections.get(detection.id)?.status).toBe('false_positive');
  });

  it('records a failed undo instead of throwing, and still resolves', async () => {
    const { fake, guild, detection } = await detectedInStrictJoin();
    fake.deps.executor.revert = () => Promise.reject(new Error('internal: token=abc'));
    const result = await reviewDetection(
      { guildId: guild.id, detectionId: detection.id, decision: 'restore', actorId: '500000000000000001' },
      fake.deps,
    );
    expect(result.status === 'done' && result.reverted).toEqual([{ action: 'quarantine', ok: false, detail: 'Action failed' }]);
    expect(fake.detections.get(detection.id)?.status).toBe('restored');
    expect(JSON.stringify(fake.audit)).not.toContain('token=abc');
  });

  it('does not try to undo actions that failed the first time', async () => {
    const guild = makeGuild({ mode: 'strict' });
    const fake = createFakeDeps([guild]);
    fake.failing.add('quarantine');
    const result = await processSignal(makeSignal({ kind: 'member_join', heuristicScore: 0.95 }), fake.deps);
    if (result.status !== 'detected') throw new Error('expected detection');
    await reviewDetection(
      { guildId: guild.id, detectionId: result.detection.id, decision: 'restore', actorId: '500000000000000001' },
      fake.deps,
    );
    expect(fake.reverted).toHaveLength(0);
  });

  it('cannot reach a detection through another guild (IDOR)', async () => {
    const { fake, detection } = await detectedInStrictJoin();
    const other = makeGuild({ id: '100000000000000099' });
    fake.guildMap.set(other.id, other);
    const result = await reviewDetection(
      { guildId: other.id, detectionId: detection.id, decision: 'restore', actorId: '500000000000000001' },
      fake.deps,
    );
    expect(result.status).toBe('not_found');
    expect(fake.reverted).toHaveLength(0);
  });
});

describe('canModerate', () => {
  it('allows Manage Server', () => {
    expect(canModerate({ hasManageGuild: true, roleIds: [] }, [])).toBe(true);
  });
  it('allows a configured mod role', () => {
    expect(canModerate({ hasManageGuild: false, roleIds: ['1', '2'] }, ['2'])).toBe(true);
  });
  it('denies by default', () => {
    expect(canModerate({ hasManageGuild: false, roleIds: ['1'] }, [])).toBe(false);
  });
});
