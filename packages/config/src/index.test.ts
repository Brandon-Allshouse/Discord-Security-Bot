import { describe, expect, it } from 'vitest';
import { loadConfig, loadDashboardConfig, loadWorkerConfig } from './index.js';

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

describe('loadDashboardConfig', () => {
  const dashboard = {
    DISCORD_CLIENT_ID: valid.DISCORD_CLIENT_ID,
    DISCORD_CLIENT_SECRET: 's'.repeat(32),
    DATABASE_URL: valid.DATABASE_URL,
    REDIS_URL: valid.REDIS_URL,
  };

  it('defaults to a local address and does not need the bot token', () => {
    const config = loadDashboardConfig(dashboard);
    expect(config).toMatchObject({ DASHBOARD_URL: 'http://localhost:3000', DASHBOARD_HOST: '127.0.0.1', DASHBOARD_PORT: 3000 });
  });

  it('rejects a missing client secret without echoing values', () => {
    expect(() => loadDashboardConfig({ ...dashboard, DISCORD_CLIENT_SECRET: 'tiny-value' })).toThrow(/DISCORD_CLIENT_SECRET/);
    try {
      loadDashboardConfig({ ...dashboard, DISCORD_CLIENT_SECRET: 'tiny-value' });
    } catch (error) {
      expect(String(error)).not.toContain('tiny-value');
    }
  });

  it('requires https in production', () => {
    expect(() => loadDashboardConfig({ ...dashboard, NODE_ENV: 'production' })).toThrow(/DASHBOARD_URL/);
    expect(loadDashboardConfig({ ...dashboard, NODE_ENV: 'production', DASHBOARD_URL: 'https://app.example' }).DASHBOARD_URL).toBe(
      'https://app.example',
    );
  });

  it('rejects a bad port', () => {
    expect(() => loadDashboardConfig({ ...dashboard, DASHBOARD_PORT: '99999' })).toThrow(/DASHBOARD_PORT/);
  });
});

describe('INTERNAL_SIGNING_KEY', () => {
  const dashboard = {
    DISCORD_CLIENT_ID: '123456789012345678',
    DISCORD_CLIENT_SECRET: 's'.repeat(32),
    DATABASE_URL: 'postgres://u:p@localhost:5432/db',
    REDIS_URL: 'redis://:p@localhost:6379',
  };

  it('is optional for both the bot and the dashboard', () => {
    expect(loadConfig(valid).INTERNAL_SIGNING_KEY).toBeUndefined();
    expect(loadDashboardConfig(dashboard).INTERNAL_SIGNING_KEY).toBeUndefined();
  });

  it('must be long, random-looking hex, and is never echoed back', () => {
    const key = 'ab'.repeat(32);
    expect(loadConfig({ ...valid, INTERNAL_SIGNING_KEY: key }).INTERNAL_SIGNING_KEY).toBe(key);
    for (const bad of ['short', 'z'.repeat(64), 'ab'.repeat(31)]) {
      try {
        loadDashboardConfig({ ...dashboard, INTERNAL_SIGNING_KEY: bad });
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
