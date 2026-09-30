import { randomUUID } from 'node:crypto';
import type { IntelSummary } from './intel/types.js';
import type { AuditEntry, PipelineDeps } from './ports.js';
import type { ActionKind, ActionOutcome, Detection, DetectionStatus, GuildSettings, Signal } from './types.js';

/** In-memory implementations of the pipeline ports, for tests. */
export function createFakeDeps(guilds: GuildSettings[] = []) {
  const guildMap = new Map(guilds.map((guild) => [guild.id, guild]));
  const detections = new Map<string, Detection>();
  const audit: AuditEntry[] = [];
  const executed: { action: ActionKind; detectionId: string; escalatedFrom?: string }[] = [];
  const reverted: { action: ActionKind; detectionId: string }[] = [];
  const allowlist = new Set<string>();
  const blocklist = new Set<string>();
  const failing = new Set<ActionKind>();
  /** Cached intel by subject. Set `intelDown.value` to make the intel cache throw. */
  const intel = new Map<string, IntelSummary>();
  const intelDown = { value: false };

  const deps: PipelineDeps = {
    guilds: { get: (id) => Promise.resolve(guildMap.get(id) ?? null) },
    indicators: {
      isAllowlisted: (guildId, signal: Signal) => Promise.resolve(allowlist.has(`${guildId}:${signal.subject}`)),
      isBlocklisted: (signal: Signal) => Promise.resolve(blocklist.has(signal.subject)),
    },
    detections: {
      create: ({ signal, verdict }) => {
        const detection: Detection = {
          id: randomUUID(),
          guildId: signal.guildId,
          userId: signal.userId,
          channelId: signal.channelId ?? null,
          messageId: signal.messageId ?? null,
          signalKind: signal.kind,
          subject: signal.subject,
          verdict,
          actionsTaken: [],
          status: 'open',
          createdAt: signal.createdAt,
        };
        detections.set(detection.id, detection);
        return Promise.resolve(detection);
      },
      recordOutcomes: (guildId, id, outcomes: ActionOutcome[]) => {
        const detection = detections.get(id);
        if (detection && detection.guildId === guildId) detection.actionsTaken = outcomes;
        return Promise.resolve();
      },
      get: (guildId, id) => {
        const detection = detections.get(id);
        return Promise.resolve(detection && detection.guildId === guildId ? { ...detection } : null);
      },
      setStatus: (guildId, id, status: DetectionStatus) => {
        const detection = detections.get(id);
        if (detection && detection.guildId === guildId) detection.status = status;
        return Promise.resolve();
      },
      findForMessage: (guildId, messageId, subject) => {
        const found = [...detections.values()].find(
          (d) => d.guildId === guildId && d.messageId === messageId && d.subject === subject,
        );
        return Promise.resolve(found ? { ...found } : null);
      },
      updateVerdict: (guildId, id, verdict) => {
        const detection = detections.get(id);
        if (detection && detection.guildId === guildId) detection.verdict = verdict;
        return Promise.resolve();
      },
    },
    intel: {
      summaryFor: (signal: Signal) =>
        intelDown.value ? Promise.reject(new Error('redis down')) : Promise.resolve(intel.get(signal.subject) ?? null),
    },
    audit: {
      write: (entry) => {
        audit.push(entry);
        return Promise.resolve();
      },
    },
    executor: {
      execute: (action, { detection, escalatedFrom }) => {
        if (failing.has(action)) return Promise.reject(new Error('boom: internal detail'));
        executed.push({ action, detectionId: detection.id, ...(escalatedFrom ? { escalatedFrom } : {}) });
        return Promise.resolve({ action, ok: true });
      },
      revert: (action, _guild, detection) => {
        reverted.push({ action, detectionId: detection.id });
        return Promise.resolve({ action, ok: true });
      },
    },
  };

  return { deps, detections, audit, executed, reverted, allowlist, blocklist, failing, guildMap, intel, intelDown };
}

export function makeGuild(overrides: Partial<GuildSettings> = {}): GuildSettings {
  return {
    id: '100000000000000001',
    mode: 'alert_only',
    alertChannelId: '100000000000000002',
    quarantineRoleId: '100000000000000003',
    modRoleIds: [],
    ...overrides,
  };
}

export function makeSignal(overrides: Partial<Signal> = {}): Signal {
  return {
    id: randomUUID(),
    kind: 'url',
    guildId: '100000000000000001',
    userId: '200000000000000001',
    channelId: '300000000000000001',
    messageId: '400000000000000001',
    subject: 'https://discord-nitro-free.example/claim',
    heuristicScore: 0.9,
    reasons: ['Lookalike of discord.com'],
    createdAt: new Date('2026-01-01T00:00:00Z'),
    ...overrides,
  };
}
