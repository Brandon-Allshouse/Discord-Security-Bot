import { runMigrations } from './client.js';

const url = process.env.DATABASE_URL;
if (!url) {
  console.error('DATABASE_URL is not set');
  process.exit(1);
}

try {
  await runMigrations(url);
  console.log('Migrations applied');
} catch (error) {
  // Print only the message: the error object can include the connection string.
  console.error('Migration failed:', error instanceof Error ? error.message : 'unknown error');
  process.exit(1);
}
