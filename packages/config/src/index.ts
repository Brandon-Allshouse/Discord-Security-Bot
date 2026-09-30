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

/**
 * Checks the config once at startup and refuses to run if anything is wrong.
 * Error messages name the offending variable but never echo its value,
 * so secrets can't end up in logs.
 */
export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  // Blank lines like "DEV_GUILD_ID=" in .env mean "not set".
  const present = Object.fromEntries(Object.entries(env).filter(([, value]) => value !== undefined && value.trim() !== ''));
  const result = configSchema.safeParse(present);
  if (!result.success) {
    const problems = result.error.issues
      .map((issue) => `  - ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid configuration:\n${problems}`);
  }
  const config = result.data;
  if (config.NODE_ENV === 'production' && config.DEV_GUILD_ID) {
    throw new Error('Invalid configuration:\n  - DEV_GUILD_ID: must not be set in production');
  }
  return config;
}

/**
 * Fields pino blanks out before writing a log line: our own secrets, plus the usual
 * places credentials hide.
 */
export const logRedactPaths = [
  'DISCORD_TOKEN',
  'DATABASE_URL',
  'REDIS_URL',
  '*.DISCORD_TOKEN',
  '*.DATABASE_URL',
  '*.REDIS_URL',
  'token',
  '*.token',
  'password',
  '*.password',
  'authorization',
  '*.authorization',
  'headers.authorization',
];
