import { z } from 'zod';

const snowflake = z.string().regex(/^\d{17,20}$/, 'must be a Discord snowflake ID');

const urlWithProtocol = (protocols: string[]) =>
  z.url().refine((value) => protocols.includes(new URL(value).protocol), {
    message: `protocol must be one of ${protocols.join(', ')}`,
  });

/**
 * Shared by the bot and the dashboard to sign requests from the dashboard to the bot.
 * 32+ random bytes as hex, e.g. `openssl rand -hex 32`. Optional: without it, the dashboard's
 * review, setup and test buttons are off, and the bot ignores requests.
 */
const signingKey = z
  .string()
  .regex(/^[0-9a-f]{64,}$/i, 'INTERNAL_SIGNING_KEY must be at least 64 hex characters (openssl rand -hex 32)')
  .optional();

export const configSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  DISCORD_TOKEN: z.string().min(50, 'DISCORD_TOKEN looks too short'),
  DISCORD_CLIENT_ID: snowflake,
  DEV_GUILD_ID: snowflake.optional(),

  DATABASE_URL: urlWithProtocol(['postgres:', 'postgresql:']),
  REDIS_URL: urlWithProtocol(['redis:', 'rediss:']),

  INTERNAL_SIGNING_KEY: signingKey,
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

  INTERNAL_SIGNING_KEY: signingKey,
});

export type DashboardConfig = z.infer<typeof dashboardConfigSchema>;

/** Free VirusTotal API limits (spec §4). The public tier may never be configured above them. */
export const VT_PUBLIC_LIMITS = { perMinute: 4, perDay: 500 } as const;

/**
 * The intel worker fetches links posted by strangers, so it gets as little as possible:
 * no Discord credentials at all, only the databases and its intel API keys.
 */
export const workerConfigSchema = z.object({
  NODE_ENV: configSchema.shape.NODE_ENV,
  LOG_LEVEL: configSchema.shape.LOG_LEVEL,

  DATABASE_URL: configSchema.shape.DATABASE_URL,
  REDIS_URL: configSchema.shape.REDIS_URL,

  /** Optional: without a key, VirusTotal is skipped and the other sources still run. */
  VT_API_KEY: z.string().regex(/^[a-f0-9]{64}$/i, 'VT_API_KEY should be the 64-character key from your VirusTotal profile').optional(),
  VT_TIER: z.enum(['public', 'premium']).default('public'),
  VT_DAILY_BUDGET: z.coerce.number().int().min(0).max(1_000_000).default(VT_PUBLIC_LIMITS.perDay),
  VT_PER_MINUTE: z.coerce.number().int().min(1).max(10_000).default(VT_PUBLIC_LIMITS.perMinute),

  /** Optional: abuse.ch Auth-Key for the URLhaus feed. Without it, the feed isn't synced. */
  URLHAUS_AUTH_KEY: z.string().min(20, 'URLHAUS_AUTH_KEY looks too short').max(200).optional(),
});

export type WorkerConfig = z.infer<typeof workerConfigSchema>;

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

export function loadWorkerConfig(env: Env = process.env): WorkerConfig {
  const config = parseEnv(workerConfigSchema, env);
  if (config.VT_TIER === 'public') {
    const problems: string[] = [];
    if (config.VT_PER_MINUTE > VT_PUBLIC_LIMITS.perMinute) {
      problems.push(`  - VT_PER_MINUTE: the public API allows at most ${VT_PUBLIC_LIMITS.perMinute}`);
    }
    if (config.VT_DAILY_BUDGET > VT_PUBLIC_LIMITS.perDay) {
      problems.push(`  - VT_DAILY_BUDGET: the public API allows at most ${VT_PUBLIC_LIMITS.perDay}`);
    }
    if (problems.length > 0) throw new Error(`Invalid configuration:\n${problems.join('\n')}`);
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
  'VT_API_KEY',
  'URLHAUS_AUTH_KEY',
  'INTERNAL_SIGNING_KEY',
  '*.DISCORD_TOKEN',
  '*.DISCORD_CLIENT_SECRET',
  '*.VT_API_KEY',
  '*.URLHAUS_AUTH_KEY',
  '*.INTERNAL_SIGNING_KEY',
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
  'headers["x-apikey"]',
  'headers["auth-key"]',
  'access_token',
  '*.access_token',
];
