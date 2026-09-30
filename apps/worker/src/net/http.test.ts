import { describe, expect, it } from 'vitest';
import { getJson, getText, HttpError, type FetchLike } from './http.js';

function capture(response: () => Response) {
  const calls: RequestInit[] = [];
  const fetch: FetchLike = (_url, init) => {
    calls.push(init ?? {});
    return Promise.resolve(response());
  };
  return { fetch, calls };
}

describe('intel API requests', () => {
  it('returns the body, refuses redirects and always sets a timeout', async () => {
    const { fetch, calls } = capture(() => new Response('hello'));
    expect(await getText('https://api.test/x', { fetch, headers: { a: 'b' } })).toBe('hello');
    expect(calls[0]).toMatchObject({ redirect: 'error', headers: { a: 'b' } });
    expect(calls[0]?.signal).toBeInstanceOf(AbortSignal);
  });

  it('throws an HttpError naming only the host, never the path or query', async () => {
    const { fetch } = capture(() => new Response('no', { status: 503 }));
    const error = await getText('https://api.test/secret/path?key=abc', { fetch }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(HttpError);
    expect((error as HttpError).status).toBe(503);
    expect((error as Error).message).toBe('HTTP 503 from api.test');
  });

  it('stops reading past the size cap', async () => {
    const { fetch } = capture(() => new Response('x'.repeat(5000)));
    await expect(getText('https://api.test/big', { fetch, maxBytes: 1000 })).rejects.toThrow(/larger than 1000 bytes/);
    expect(await getText('https://api.test/big', { fetch, maxBytes: 5000 })).toHaveLength(5000);
  });

  it('parses JSON, and handles empty bodies', async () => {
    expect(await getJson('https://api.test/j', capture(() => new Response('{"a":1}')))).toEqual({ a: 1 });
    expect(await getText('https://api.test/e', capture(() => new Response(null)))).toBe('');
  });
});
