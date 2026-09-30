import { pino } from 'pino';
import { loadDashboardConfig, logRedactPaths } from '@equinox/config';
import { ApiClient, httpTransport } from './api-client.js';
import { buildApp } from './app.js';

const config = loadDashboardConfig();
const logger = pino({
  level: config.LOG_LEVEL,
  base: { service: 'dashboard' },
  redact: { paths: logRedactPaths, censor: '[redacted]' },
});

// The dashboard's only connection: signed requests to the API. No database, Redis or Discord secrets here.
const app = await buildApp({
  api: new ApiClient(httpTransport(config.API_URL), config.API_SIGNING_KEY),
  publicUrl: config.DASHBOARD_URL,
  logger,
});

async function shutdown(signal: string) {
  logger.info({ signal }, 'shutting down');
  await app.close();
  process.exit(0);
}
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

try {
  await app.listen({ host: config.DASHBOARD_HOST, port: config.DASHBOARD_PORT });
  logger.info(`Dashboard: ${config.DASHBOARD_URL} (OAuth redirect: ${new URL('/auth/callback', config.DASHBOARD_URL).toString()})`);
} catch (error) {
  logger.fatal({ err: { message: error instanceof Error ? error.message : 'unknown error' } }, 'startup failed');
  process.exit(1);
}
