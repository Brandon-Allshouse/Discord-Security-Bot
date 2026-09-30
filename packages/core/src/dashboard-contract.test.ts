import { describe, expect, it } from 'vitest';
import {
  ACTION_MAX_AGE_MS,
  dashboardActionQueue,
  guildSnapshotSchema,
  shardForGuild,
  signAction,
  verifyAction,
  type DashboardAction,
} from './dashboard-contract.js';
import { reviewDetection } from './review.js';
import { createFakeDeps, makeGuild, makeSignal } from './testing.js';
import { processSignal } from './pipeline.js';

const KEY = 'ab'.repeat(32);
const OTHER_KEY = 'cd'.repeat(32);
const review: DashboardAction = {
  type: 'review',
  guildId: '100000000000000001',
  actorId: '500000000000000001',
  detectionId: '0b7f5c8e-1d2a-4c3b-9e8f-7a6b5c4d3e2f',
  decision: 'restore',
};

describe('shardForGuild', () => {
  it('follows Discord’s sharding formula', () => {
    // (id >> 22) % shards, checked by hand for a known ID.
    const id = '41771983423143937';
    const expected = Number((41771983423143937n >> 22n) % 4n);
    expect(shardForGuild(id, 4)).toBe(expected);
    expect(shardForGuild(id, 1)).toBe(0);
  });

  it('refuses a nonsense shard count', () => {
    expect(() => shardForGuild('41771983423143937', 0)).toThrow();
    expect(() => shardForGuild('41771983423143937', 1.5)).toThrow();
  });

  it('names one queue per shard', () => {
    expect(dashboardActionQueue(0)).not.toBe(dashboardActionQueue(1));
    expect(dashboardActionQueue(3)).not.toContain(':');
  });
});

describe('signed dashboard requests', () => {
  const now = 1_800_000_000_000;

  it('accepts a request signed with the shared key', () => {
    expect(verifyAction(KEY, signAction(KEY, review, now), now + 1000)).toEqual(review);
  });

  it('does not depend on the order fields were written in', () => {
    const reordered = { decision: 'restore', detectionId: review.detectionId, actorId: review.actorId, guildId: review.guildId, type: 'review' } as const;
    expect(verifyAction(KEY, signAction(KEY, reordered, now), now)).toEqual(review);
  });

  it('refuses a request signed with another key', () => {
    expect(verifyAction(KEY, signAction(OTHER_KEY, review, now), now)).toBeNull();
  });

  it('refuses a request that was changed after signing', () => {
    const signed = signAction(KEY, review, now);
    const tampered = { ...signed, action: { ...review, guildId: '100000000000000002' } };
    expect(verifyAction(KEY, tampered, now)).toBeNull();
    const promoted = { ...signed, action: { ...review, decision: 'confirm' } };
    expect(verifyAction(KEY, promoted, now)).toBeNull();
    expect(verifyAction(KEY, { ...signed, issuedAt: signed.issuedAt + 1 }, now)).toBeNull();
  });

  it('refuses old requests (replays) and ones from the future', () => {
    const signed = signAction(KEY, review, now);
    expect(verifyAction(KEY, signed, now + ACTION_MAX_AGE_MS + 1)).toBeNull();
    expect(verifyAction(KEY, signed, now - ACTION_MAX_AGE_MS - 1)).toBeNull();
    expect(verifyAction(KEY, signed, now + ACTION_MAX_AGE_MS - 1)).toEqual(review);
  });

  it('refuses malformed requests and invalid actions even when signed', () => {
    expect(verifyAction(KEY, null, now)).toBeNull();
    expect(verifyAction(KEY, { action: review, issuedAt: now, signature: 'nope' }, now)).toBeNull();
    expect(() => signAction(KEY, { ...review, detectionId: 'not-a-uuid' }, now)).toThrow();
    expect(() => signAction(KEY, { ...review, decision: 'ban' } as unknown as DashboardAction, now)).toThrow();
  });
});

describe('guild snapshot', () => {
  it('rejects snapshots that are too big or malformed', () => {
    const base = { channels: [], roles: [], missingPermissions: [], updatedAt: new Date().toISOString() };
    expect(guildSnapshotSchema.safeParse(base).success).toBe(true);
    const channel = { id: '300000000000000001', name: 'x', canPostAlerts: true };
    expect(guildSnapshotSchema.safeParse({ ...base, channels: Array(501).fill(channel) }).success).toBe(false);
    expect(guildSnapshotSchema.safeParse({ ...base, channels: [{ ...channel, id: 'nope' }] }).success).toBe(false);
  });
});

describe('where a review was made', () => {
  it('is recorded in the audit log', async () => {
    const fake = createFakeDeps([makeGuild()]);
    const result = await processSignal(makeSignal(), fake.deps);
    if (result.status !== 'detected') throw new Error('expected detection');
    await reviewDetection(
      { guildId: result.detection.guildId, detectionId: result.detection.id, decision: 'confirm', actorId: '500000000000000001', via: 'dashboard' },
      fake.deps,
    );
    expect(fake.audit.at(-1)).toMatchObject({ action: 'review.confirm', details: { via: 'dashboard' } });
    await reviewDetection(
      { guildId: result.detection.guildId, detectionId: result.detection.id, decision: 'restore', actorId: '500000000000000001' },
      fake.deps,
    );
    expect(fake.audit.at(-1)).toMatchObject({ action: 'review.restore', details: { via: 'discord' } });
  });
});
