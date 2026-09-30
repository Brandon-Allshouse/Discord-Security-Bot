import { logRedactPaths } from '@equinox/config';
import { pino, type DestinationStream } from 'pino';

/** `destination` is for tests; services log to standard output. */
export function createLogger(level: string, bindings: Record<string, unknown> = {}, destination?: DestinationStream) {
  const options = {
    level,
    base: { service: 'bot', ...bindings },
    redact: { paths: logRedactPaths, censor: '[redacted]' },
  };
  return destination ? pino(options, destination) : pino(options);
}

export type Logger = ReturnType<typeof createLogger>;
