import { describe, expect, it } from 'vitest';
import { loadApiConfig, loadConfig, loadDashboardConfig, loadWorkerConfig } from './index.js';

const valid = {
  DISCORD_TOKEN: 'x'.repeat(70),
  DISCORD_CLIENT_ID: '123456789012345678',
  DATABASE_URL: 'postgres://u:p@localhost:5432/db',
  REDIS_URL: 'redis://:p@localhost:6379',
};

describe('loadConfig', () => {
  it('accepts a valid environment and applies defaults', () => {
    const config = loadConfig(valid);
    expect(config.NODE_ENV).toBe('development');
    expect(config.LOG_LEVEL).toBe('info');
  });

  it('rejects missing secrets without echoing values', () => {
    const secret = 'super-secret-value';
    expect(() => loadConfig({ ...valid, DISCORD_TOKEN: secret })).toThrow(/DISCORD_TOKEN/);
    try {
      loadConfig({ ...valid, DISCORD_TOKEN: secret });
    } catch (error) {
      expect(String(error)).not.toContain(secret);
    }
  });

  it('rejects database URLs with the wrong protocol', () => {
    expect(() => loadConfig({ ...valid, DATABASE_URL: 'http://evil.example' })).toThrow(/DATABASE_URL/);
  });

  it('rejects malformed snowflakes', () => {
    expect(() => loadConfig({ ...valid, DISCORD_CLIENT_ID: 'abc' })).toThrow(/DISCORD_CLIENT_ID/);
  });

  it('treats blank variables as unset', () => {
    expect(loadConfig({ ...valid, DEV_GUILD_ID: '', LOG_LEVEL: ' ' }).DEV_GUILD_ID).toBeUndefined();
    expect(() => loadConfig({ ...valid, DISCORD_TOKEN: '' })).toThrow(/DISCORD_TOKEN/);
  });

  it('refuses DEV_GUILD_ID in production', () => {
    expect(() =>
      loadConfig({ ...valid, NODE_ENV: 'production', DEV_GUILD_ID: '123456789012345678' }),
    ).toThrow(/DEV_GUILD_ID/);
  });
});

const API_KEY = 'cd'.repeat(32);
const BOT_KEY = 'ab'.repeat(32);

describe('loadDashboardConfig (the frontend)', () => {
  const dashboard = { API_SIGNING_KEY: API_KEY };

  it('needs only the API address and its signing key, with local defaults', () => {
    expect(loadDashboardConfig(dashboard)).toMatchObject({
      DASHBOARD_URL: 'http://localhost:3000',
      DASHBOARD_HOST: '127.0.0.1',
      DASHBOARD_PORT: 3000,
      API_URL: 'http://127.0.0.1:4000',
    });
  });

  it('holds no database, Redis or Discord secrets and no bot key, even if they are in the environment', () => {
    const config = loadDashboardConfig({
      ...dashboard,
      DATABASE_URL: valid.DATABASE_URL,
      REDIS_URL: valid.REDIS_URL,
      DISCORD_TOKEN: valid.DISCORD_TOKEN,
      DISCORD_CLIENT_SECRET: 's'.repeat(32),
      INTERNAL_SIGNING_KEY: BOT_KEY,
    });
    for (const secret of ['DATABASE_URL', 'REDIS_URL', 'DISCORD_TOKEN', 'DISCORD_CLIENT_SECRET', 'INTERNAL_SIGNING_KEY']) {
      expect(config).not.toHaveProperty(secret);
    }
  });

  it('refuses to start without a proper API signing key, without echoing it', () => {
    expect(() => loadDashboardConfig({})).toThrow(/API_SIGNING_KEY/);
    try {
      loadDashboardConfig({ API_SIGNING_KEY: 'short-key-value' });
      expect.unreachable();
    } catch (error) {
      expect(String(error)).toMatch(/API_SIGNING_KEY/);
      expect(String(error)).not.toContain('short-key-value');
    }
  });

  it('requires https in production', () => {
    expect(() => loadDashboardConfig({ ...dashboard, NODE_ENV: 'production' })).toThrow(/DASHBOARD_URL/);
    expect(loadDashboardConfig({ ...dashboard, NODE_ENV: 'production', DASHBOARD_URL: 'https://app.example' }).DASHBOARD_URL).toBe(
      'https://app.example',
    );
  });

  it('rejects a bad port or API address', () => {
    expect(() => loadDashboardConfig({ ...dashboard, DASHBOARD_PORT: '99999' })).toThrow(/DASHBOARD_PORT/);
    expect(() => loadDashboardConfig({ ...dashboard, API_URL: 'file:///etc/passwd' })).toThrow(/API_URL/);
  });
});

describe('loadApiConfig (the backend)', () => {
  const api = {
    API_SIGNING_KEY: API_KEY,
    DISCORD_CLIENT_ID: valid.DISCORD_CLIENT_ID,
    DISCORD_CLIENT_SECRET: 's'.repeat(32),
    DATABASE_URL: valid.DATABASE_URL,
    REDIS_URL: valid.REDIS_URL,
  };

  it('holds the data and Discord login credentials, but never the bot token', () => {
    const config = loadApiConfig({ ...api, DISCORD_TOKEN: valid.DISCORD_TOKEN });
    expect(config).toMatchObject({ API_HOST: '127.0.0.1', API_PORT: 4000, DASHBOARD_URL: 'http://localhost:3000' });
    expect(config).not.toHaveProperty('DISCORD_TOKEN');
    expect(config.INTERNAL_SIGNING_KEY).toBeUndefined();
  });

  it('rejects a short client secret or signing key without echoing them', () => {
    for (const [name, value] of [['DISCORD_CLIENT_SECRET', 'tiny-value'], ['API_SIGNING_KEY', 'short-key-value']] as const) {
      try {
        loadApiConfig({ ...api, [name]: value });
        expect.unreachable();
      } catch (error) {
        expect(String(error)).toMatch(new RegExp(name));
        expect(String(error)).not.toContain(value);
      }
    }
  });

  it('refuses the same key for signing API and bot requests', () => {
    expect(() => loadApiConfig({ ...api, INTERNAL_SIGNING_KEY: API_KEY })).toThrow(/must be different/);
    expect(() => loadApiConfig({ ...api, INTERNAL_SIGNING_KEY: API_KEY.toUpperCase() })).toThrow(/must be different/);
    expect(loadApiConfig({ ...api, INTERNAL_SIGNING_KEY: BOT_KEY }).INTERNAL_SIGNING_KEY).toBe(BOT_KEY);
  });

  it('requires an https dashboard address in production', () => {
    expect(() => loadApiConfig({ ...api, NODE_ENV: 'production' })).toThrow(/DASHBOARD_URL/);
  });
});

describe('INTERNAL_SIGNING_KEY', () => {
  it('is optional for the bot', () => {
    expect(loadConfig(valid).INTERNAL_SIGNING_KEY).toBeUndefined();
  });

  it('must be long, random-looking hex, and is never echoed back', () => {
    expect(loadConfig({ ...valid, INTERNAL_SIGNING_KEY: BOT_KEY }).INTERNAL_SIGNING_KEY).toBe(BOT_KEY);
    for (const bad of ['short', 'z'.repeat(64), 'ab'.repeat(31)]) {
      try {
        loadConfig({ ...valid, INTERNAL_SIGNING_KEY: bad });
        expect.unreachable();
      } catch (error) {
        expect(String(error)).toMatch(/INTERNAL_SIGNING_KEY/);
        expect(String(error)).not.toContain(bad);
      }
    }
  });
});

describe('loadWorkerConfig', () => {
  const worker = {
    DATABASE_URL: 'postgres://u:p@localhost:5432/db',
    REDIS_URL: 'redis://:p@localhost:6379',
  };
  const key = 'a'.repeat(64);

  it('runs without any intel keys, on free-tier VirusTotal defaults', () => {
    expect(loadWorkerConfig(worker)).toMatchObject({ VT_TIER: 'public', VT_PER_MINUTE: 4, VT_DAILY_BUDGET: 500 });
    expect(loadWorkerConfig({ ...worker, VT_API_KEY: '', URLHAUS_AUTH_KEY: '' }).VT_API_KEY).toBeUndefined();
  });

  it('never needs or accepts the Discord token', () => {
    expect(loadWorkerConfig({ ...worker, DISCORD_TOKEN: 'x'.repeat(60) })).not.toHaveProperty('DISCORD_TOKEN');
  });

  it('refuses public-tier limits above what VirusTotal allows', () => {
    expect(() => loadWorkerConfig({ ...worker, VT_API_KEY: key, VT_PER_MINUTE: '10' })).toThrow(/VT_PER_MINUTE/);
    expect(() => loadWorkerConfig({ ...worker, VT_API_KEY: key, VT_DAILY_BUDGET: '1000' })).toThrow(/VT_DAILY_BUDGET/);
    expect(loadWorkerConfig({ ...worker, VT_TIER: 'premium', VT_PER_MINUTE: '500' }).VT_PER_MINUTE).toBe(500);
  });

  it('rejects a malformed key without echoing it', () => {
    try {
      loadWorkerConfig({ ...worker, VT_API_KEY: 'not-a-real-key-value' });
      expect.unreachable();
    } catch (error) {
      expect(String(error)).toMatch(/VT_API_KEY/);
      expect(String(error)).not.toContain('not-a-real-key-value');
    }
  });
});
