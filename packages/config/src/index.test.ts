import { describe, expect, it } from 'vitest';
import { loadConfig, loadDashboardConfig } from './index.js';

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
