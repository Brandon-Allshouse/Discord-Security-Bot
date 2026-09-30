import { z } from 'zod';

const snowflake = z.string().regex(/^\d{17,20}$/, 'must be a Discord snowflake ID');

const urlWithProtocol = (protocols: string[]) =>
  z.url().refine((value) => protocols.includes(new URL(value).protocol), {
    message: `protocol must be one of ${protocols.join(', ')}`,
  });

export const configSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  DISCORD_TOKEN: z.string().min(50, 'DISCORD_TOKEN looks too short'),
  DISCORD_CLIENT_ID: snowflake,
  DEV_GUILD_ID: snowflake.optional(),

  DATABASE_URL: urlWithProtocol(['postgres:', 'postgresql:']),
  REDIS_URL: urlWithProtocol(['redis:', 'rediss:']),
});

export type Config = z.infer<typeof configSchema>;

/** The dashboard is its own process. It never gets the bot token, only the OAuth client secret. */
export const dashboardConfigSchema = z.object({
  NODE_ENV: configSchema.shape.NODE_ENV,
  LOG_LEVEL: configSchema.shape.LOG_LEVEL,

  DISCORD_CLIENT_ID: snowflake,
  DISCORD_CLIENT_SECRET: z.string().min(20, 'DISCORD_CLIENT_SECRET looks too short'),

  /** Public address of the dashboard. The OAuth redirect is this plus /auth/callback. */
  DASHBOARD_URL: urlWithProtocol(['http:', 'https:']).default('http://localhost:3000'),
  DASHBOARD_HOST: z.string().min(1).default('127.0.0.1'),
  DASHBOARD_PORT: z.coerce.number().int().min(1).max(65535).default(3000),

  DATABASE_URL: configSchema.shape.DATABASE_URL,
  REDIS_URL: configSchema.shape.REDIS_URL,
});

export type DashboardConfig = z.infer<typeof dashboardConfigSchema>;

type Env = Record<string, string | undefined>;

function parseEnv<T>(schema: z.ZodType<T>, env: Env): T {
  // Blank lines like "DEV_GUILD_ID=" in .env mean "not set".
  const present = Object.fromEntries(Object.entries(env).filter(([, value]) => value !== undefined && value.trim() !== ''));
  const result = schema.safeParse(present);
  if (!result.success) {
    const problems = result.error.issues
      .map((issue) => `  - ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid configuration:\n${problems}`);
  }
  return result.data;
}

/**
 * Checks the config once at startup and refuses to run if anything is wrong.
 * Error messages name the offending variable but never echo its value,
 * so secrets can't end up in logs.
 */
export function loadConfig(env: Env = process.env): Config {
  const config = parseEnv(configSchema, env);
  if (config.NODE_ENV === 'production' && config.DEV_GUILD_ID) {
    throw new Error('Invalid configuration:\n  - DEV_GUILD_ID: must not be set in production');
  }
  return config;
}

export function loadDashboardConfig(env: Env = process.env): DashboardConfig {
  const config = parseEnv(dashboardConfigSchema, env);
  // Session cookies are only marked Secure over https, so plain http is for local development only.
  if (config.NODE_ENV === 'production' && !config.DASHBOARD_URL.startsWith('https://')) {
    throw new Error('Invalid configuration:\n  - DASHBOARD_URL: must use https in production');
  }
  return config;
}

/**
 * Fields pino blanks out before writing a log line: our own secrets, plus the usual
 * places credentials hide.
 */
export const logRedactPaths = [
  'DISCORD_TOKEN',
  'DISCORD_CLIENT_SECRET',
  'DATABASE_URL',
  'REDIS_URL',
  '*.DISCORD_TOKEN',
  '*.DISCORD_CLIENT_SECRET',
  '*.DATABASE_URL',
  '*.REDIS_URL',
  'token',
  '*.token',
  'password',
  '*.password',
  'authorization',
  '*.authorization',
  'headers.authorization',
  'cookie',
  '*.cookie',
  'headers.cookie',
  'access_token',
  '*.access_token',
];
