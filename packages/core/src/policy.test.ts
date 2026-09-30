import { describe, expect, it } from 'vitest';
import { actionsFor, POLICY } from './policy.js';
import { GUILD_MODES, SIGNAL_KINDS, VERDICT_LEVELS } from './types.js';

const allCombos = GUILD_MODES.flatMap((mode) =>
  SIGNAL_KINDS.flatMap((kind) => VERDICT_LEVELS.map((level) => ({ mode, kind, level }))),
);

describe('policy table', () => {
  it('defines every (mode, kind, level) combination', () => {
    expect(allCombos).toHaveLength(GUILD_MODES.length * SIGNAL_KINDS.length * VERDICT_LEVELS.length);
    for (const { mode, kind, level } of allCombos) {
      expect(Array.isArray(POLICY[mode][kind][level]), `${mode}/${kind}/${level}`).toBe(true);
    }
  });

  it.each(allCombos)('$mode / $kind / $level follows the invariants', ({ mode, kind, level }) => {
    const actions = actionsFor(mode, kind, level);

    // Clean never acts.
    if (level === 'clean') expect(actions).toEqual([]);
    // Nothing happens silently.
    else expect(actions).toContain('alert');
    // alert_only is alert only.
    if (mode === 'alert_only') expect(actions.every((a) => a === 'alert')).toBe(true);
    // Kick and ban always need a human.
    expect(actions).not.toContain('kick');
    expect(actions).not.toContain('ban');
    // The alert comes last, so it can report what was done.
    if (actions.length > 0) expect(actions.at(-1)).toBe('alert');
    // No duplicates.
    expect(new Set(actions).size).toBe(actions.length);
  });

  it('matches the expected snapshot', () => {
    expect(POLICY).toMatchInlineSnapshot(`
      {
        "alert_only": {
          "file": {
            "clean": [],
            "malicious": [
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
          "member_join": {
            "clean": [],
            "malicious": [
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
          "message_fingerprint": {
            "clean": [],
            "malicious": [
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
          "report": {
            "clean": [],
            "malicious": [
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
          "url": {
            "clean": [],
            "malicious": [
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
        },
        "protect": {
          "file": {
            "clean": [],
            "malicious": [
              "delete",
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
          "member_join": {
            "clean": [],
            "malicious": [
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
          "message_fingerprint": {
            "clean": [],
            "malicious": [
              "delete",
              "quarantine",
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
          "report": {
            "clean": [],
            "malicious": [
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
          "url": {
            "clean": [],
            "malicious": [
              "delete",
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
        },
        "strict": {
          "file": {
            "clean": [],
            "malicious": [
              "delete",
              "alert",
            ],
            "suspicious": [
              "delete",
              "alert",
            ],
          },
          "member_join": {
            "clean": [],
            "malicious": [
              "quarantine",
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
          "message_fingerprint": {
            "clean": [],
            "malicious": [
              "delete",
              "quarantine",
              "alert",
            ],
            "suspicious": [
              "delete",
              "alert",
            ],
          },
          "report": {
            "clean": [],
            "malicious": [
              "alert",
            ],
            "suspicious": [
              "alert",
            ],
          },
          "url": {
            "clean": [],
            "malicious": [
              "delete",
              "alert",
            ],
            "suspicious": [
              "delete",
              "alert",
            ],
          },
        },
      }
    `);
  });
});
