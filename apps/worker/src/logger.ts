import { logRedactPaths } from '@equinox/config';
import { pino } from 'pino';

export function createLogger(level: string, bindings: Record<string, unknown> = {}) {
  return pino({
    level,
    base: { service: 'worker', ...bindings },
    redact: { paths: logRedactPaths, censor: '[redacted]' },
  });
}

export type Logger = ReturnType<typeof createLogger>;
