/**
 * Requests to the intel APIs themselves (IANA, RDAP registries, URLhaus, VirusTotal).
 * These are fixed, well-known hosts, not links from Discord, so they use plain fetch,
 * but still with a timeout and a size cap so a slow or huge answer can't stall the worker,
 * and redirects are refused so even a trusted host can't send the worker somewhere else.
 */

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly url: string,
  ) {
    super(`HTTP ${status} from ${new URL(url).host}`);
    this.name = 'HttpError';
  }
}

export interface ReadOptions {
  fetch?: FetchLike;
  headers?: Record<string, string>;
  timeoutMs?: number;
  maxBytes?: number;
}

/** GET a URL and return the body as text. Throws HttpError on any non-2xx status. */
export async function getText(url: string, options: ReadOptions = {}): Promise<string> {
  const doFetch = options.fetch ?? fetch;
  const response = await doFetch(url, {
    headers: options.headers ?? {},
    signal: AbortSignal.timeout(options.timeoutMs ?? 5000),
    redirect: 'error',
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new HttpError(response.status, url);
  }
  return readCapped(response, options.maxBytes ?? 1024 * 1024);
}

export async function getJson(url: string, options: ReadOptions = {}): Promise<unknown> {
  return JSON.parse(await getText(url, options)) as unknown;
}

async function readCapped(response: Response, maxBytes: number): Promise<string> {
  if (!response.body) return '';
  const reader: ReadableStreamDefaultReader<Uint8Array> = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      throw new Error(`response larger than ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}
