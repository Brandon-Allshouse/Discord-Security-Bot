import type { ActionKind, GuildMode, SignalKind, VerdictLevel } from './types.js';

type PolicyTable = Record<GuildMode, Record<SignalKind, Record<VerdictLevel, readonly ActionKind[]>>>;

const ALERT_ONLY = { clean: [], suspicious: ['alert'], malicious: ['alert'] } as const;

/**
 * The single place that maps (mode, signal kind, verdict) to actions.
 *
 * Rules the tests hold this table to:
 * - clean verdicts never act
 * - alert_only never does anything but alert
 * - kick and ban are never automatic; they need a moderator
 * - every non-clean verdict alerts, so nothing happens silently
 *
 * Enforcement actions come before 'alert' so the alert can report what was done.
 */
export const POLICY: PolicyTable = {
  alert_only: {
    url: ALERT_ONLY,
    file: ALERT_ONLY,
    message_fingerprint: ALERT_ONLY,
    member_join: ALERT_ONLY,
    report: ALERT_ONLY,
  },
  protect: {
    url: { clean: [], suspicious: ['alert'], malicious: ['delete', 'alert'] },
    file: { clean: [], suspicious: ['alert'], malicious: ['delete', 'alert'] },
    message_fingerprint: { clean: [], suspicious: ['alert'], malicious: ['delete', 'quarantine', 'alert'] },
    member_join: ALERT_ONLY,
    report: ALERT_ONLY,
  },
  strict: {
    url: { clean: [], suspicious: ['delete', 'alert'], malicious: ['delete', 'alert'] },
    file: { clean: [], suspicious: ['delete', 'alert'], malicious: ['delete', 'alert'] },
    message_fingerprint: {
      clean: [],
      suspicious: ['delete', 'alert'],
      malicious: ['delete', 'quarantine', 'alert'],
    },
    member_join: { clean: [], suspicious: ['alert'], malicious: ['quarantine', 'alert'] },
    report: ALERT_ONLY,
  },
};

export function actionsFor(mode: GuildMode, kind: SignalKind, level: VerdictLevel): readonly ActionKind[] {
  return POLICY[mode][kind][level];
}

/** Actions a moderator can undo, and whether undoing is possible at all. */
export const REVERSIBLE_ACTIONS: ReadonlySet<ActionKind> = new Set(['quarantine', 'timeout', 'ban']);
