import { Worker, type ConnectionOptions } from 'bullmq';
import { INTEL_LOOKUP_QUEUE, INTEL_VT_QUEUE, intelLookupJobSchema, QUEUE_PREFIX } from '@equinox/core';
import { processLookup, processVirusTotal, RateLimitedError, type JobDeps, type VirusTotalJob } from './jobs.js';
import type { Logger } from './logger.js';
import { VirusTotalAuthError } from './providers/virustotal.js';

export interface WorkerOptions {
  deps: JobDeps;
  connection: ConnectionOptions;
  logger: Pick<Logger, 'debug' | 'warn' | 'error'>;
  vtPerMinute: number;
  lookupConcurrency?: number;
  /** BullMQ limiter window; only tests shorten it. */
  vtLimiterDurationMs?: number;
}

const errMessage = (err: unknown) => ({ message: err instanceof Error ? err.message : 'unknown' });

/** The lookup worker, and the VirusTotal worker when VirusTotal is configured. */
export function startIntelWorkers(options: WorkerOptions): Worker[] {
  const { deps, connection, logger } = options;
  const base = { connection, prefix: QUEUE_PREFIX };
  const workers: Worker[] = [];

  workers.push(
    new Worker(
      INTEL_LOOKUP_QUEUE,
      async (job) => {
        const outcome = await processLookup(intelLookupJobSchema.parse(job.data), deps);
        logger.debug({ job: job.id, ...outcome }, 'lookup done');
        return outcome;
      },
      { ...base, concurrency: options.lookupConcurrency ?? 4 },
    ),
  );

  if (deps.vt) {
    // Two layers keep us inside VirusTotal's terms: BullMQ's limiter paces the queue,
    // and ApiBudget refuses outright past the per-minute and daily limits.
    const vtWorker: Worker = new Worker(
      INTEL_VT_QUEUE,
      async (job) => {
        try {
          const outcome = await processVirusTotal(job.data as VirusTotalJob, deps);
          logger.debug({ job: job.id, outcome }, 'virustotal done');
          return outcome;
        } catch (error) {
          if (error instanceof RateLimitedError) {
            // Put the job back without spending an attempt, and hold the queue until a slot frees up.
            await vtWorker.rateLimit(error.retryInMs);
            throw Worker.RateLimitError();
          }
          if (error instanceof VirusTotalAuthError) {
            logger.error('VirusTotal rejected VT_API_KEY; pausing VirusTotal lookups until restart');
            void vtWorker.pause(true);
          }
          throw error;
        }
      },
      {
        ...base,
        concurrency: 1,
        limiter: { max: options.vtPerMinute, duration: options.vtLimiterDurationMs ?? 60_000 },
      },
    );
    workers.push(vtWorker);
  }

  for (const worker of workers) {
    worker.on('failed', (job, err) => logger.warn({ queue: worker.name, job: job?.id, err: errMessage(err) }, 'job failed'));
    worker.on('error', (err) => logger.error({ queue: worker.name, err: errMessage(err) }, 'worker error'));
  }
  return workers;
}
