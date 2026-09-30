import { describe, expect, it } from 'vitest';
import { createLogger } from './logger.js';

describe('worker logger', () => {
  it('blanks out intel keys and connection strings', () => {
    const lines: string[] = [];
    const logger = createLogger('info', {}, { write: (line: string) => void lines.push(line) });
    logger.warn(
      {
        VT_API_KEY: 'v'.repeat(64),
        URLHAUS_AUTH_KEY: 'urlhaus-secret-key',
        config: { REDIS_URL: 'redis://:hunter2@redis:6379', VT_API_KEY: 'w'.repeat(64) },
        headers: { 'x-apikey': 'header-key', 'auth-key': 'header-auth' },
      },
      'provider failed',
    );
    const text = lines.join('');
    for (const secret of ['v'.repeat(64), 'w'.repeat(64), 'urlhaus-secret-key', 'hunter2', 'header-key', 'header-auth']) {
      expect(text, secret).not.toContain(secret);
    }
    expect(JSON.parse(lines[0]!)).toMatchObject({ service: 'worker', msg: 'provider failed' });
  });
});
