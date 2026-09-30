import { describe, expect, it } from 'vitest';
import { createLogger } from './logger.js';

/** Captures what the logger writes, as parsed JSON lines. */
function capture() {
  const lines: Record<string, unknown>[] = [];
  const stream = { write: (line: string) => void lines.push(JSON.parse(line) as Record<string, unknown>) };
  return { lines, stream };
}

describe('bot logger', () => {
  it('blanks out secrets wherever they turn up in a log line', () => {
    const { lines, stream } = capture();
    const logger = createLogger('info', { shard: '0' }, stream);
    logger.info(
      {
        DISCORD_TOKEN: 'real-bot-token',
        config: { INTERNAL_SIGNING_KEY: 'k'.repeat(64), DATABASE_URL: 'postgres://u:hunter2@db/x', API_SIGNING_KEY: 'a'.repeat(64) },
        headers: { authorization: 'Bearer abc', cookie: 'eq_session=abc', 'x-equinox-session': 'sess', 'x-equinox-signature': 'sig' },
        token: 'oauth-token',
        password: 'hunter2',
        sessionId: 'session-value',
      },
      'test',
    );
    const text = JSON.stringify(lines);
    for (const secret of ['real-bot-token', 'k'.repeat(64), 'hunter2', 'Bearer abc', 'eq_session=abc', 'sess"', 'sig"', 'oauth-token', 'session-value', 'a'.repeat(64)]) {
      expect(text, secret).not.toContain(secret);
    }
    expect(lines[0]).toMatchObject({ service: 'bot', shard: '0', msg: 'test', DISCORD_TOKEN: '[redacted]' });
  });

  it('respects the log level', () => {
    const { lines, stream } = capture();
    const logger = createLogger('warn', {}, stream);
    logger.info('hidden');
    logger.warn('shown');
    expect(lines.map((l) => l.msg)).toEqual(['shown']);
  });
});
