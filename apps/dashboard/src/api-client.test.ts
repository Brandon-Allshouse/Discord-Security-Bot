import { describe, expect, it } from 'vitest';
import { API_HEADERS, verifyApiRequest } from '@equinox/core';
import { ApiClient, ApiError, httpTransport, type Transport, type TransportRequest } from './api-client.js';

const KEY = 'cd'.repeat(32);
const SESSION = 'a'.repeat(43);

function client(answer: (request: TransportRequest) => { status: number; body: string } | Promise<never>) {
  const sent: TransportRequest[] = [];
  const transport: Transport = (request) => {
    sent.push(request);
    const result = answer(request);
    return result instanceof Promise ? result : Promise.resolve(result);
  };
  return { api: new ApiClient(transport, KEY), sent };
}

/** The error a call fails with (and a failure if it doesn't fail). */
const failure = (call: Promise<unknown>) =>
  call.then(
    () => {
      throw new Error('expected the call to fail');
    },
    (error: unknown) => error as ApiError,
  );

const ME = { user: { id: '500000000000000001', username: 'admin' }, csrf: 'x'.repeat(43), guilds: [] };

describe('ApiClient', () => {
  it('signs every request so the API can verify it, including the session', async () => {
    const { api, sent } = client(() => ({ status: 200, body: JSON.stringify(ME) }));
    await api.me(SESSION);
    const request = sent[0]!;
    expect(request.headers[API_HEADERS.session]).toBe(SESSION);
    expect(verifyApiRequest(KEY, { method: 'GET', path: '/v1/me', body: '' }, request.headers)).toMatchObject({ ok: true });
    expect(verifyApiRequest('ab'.repeat(32), { method: 'GET', path: '/v1/me', body: '' }, request.headers)).toMatchObject({ ok: false });
  });

  it('uses a fresh nonce for every request', async () => {
    const { api, sent } = client(() => ({ status: 200, body: JSON.stringify(ME) }));
    await api.me(SESSION);
    await api.me(SESSION);
    expect(sent[0]!.headers[API_HEADERS.nonce]).not.toBe(sent[1]!.headers[API_HEADERS.nonce]);
  });

  it('keeps IDs from changing the path', async () => {
    const { api, sent } = client(() => ({ status: 404, body: '{"error":"not_found"}' }));
    await expect(api.guild(SESSION, '../../admin')).rejects.toBeInstanceOf(ApiError);
    expect(sent[0]!.path).toBe('/v1/guilds/..%2F..%2Fadmin');
  });

  it('turns API errors into fixed codes, and anything unrecognised into "unavailable"', async () => {
    const cases: [number, string, string][] = [
      [401, '{"error":"unauthenticated"}', 'unauthenticated'],
      [403, '{"error":"csrf"}', 'csrf'],
      [500, '{"error":"unavailable","ref":"0123abcd"}', 'unavailable'],
      [500, '<html>proxy error</html>', 'unavailable'],
      [418, '{"error":"<script>"}', 'unavailable'],
    ];
    for (const [status, body, code] of cases) {
      const { api } = client(() => ({ status, body }));
      const error = await failure(api.me(SESSION));
      expect(error).toBeInstanceOf(ApiError);
      expect(error.code).toBe(code);
    }
    const { api } = client(() => ({ status: 500, body: '{"error":"unavailable","ref":"0123abcd"}' }));
    expect((await failure(api.me(SESSION))).ref).toBe('0123abcd');
  });

  it('never uses a response that doesn’t match the contract', async () => {
    const { api } = client(() => ({ status: 200, body: JSON.stringify({ ...ME, user: { id: 'x', username: 'y' } }) }));
    await expect(api.me(SESSION)).rejects.toMatchObject({ status: 502, code: 'unavailable' });
    const { api: garbage } = client(() => ({ status: 200, body: 'not json' }));
    await expect(garbage.me(SESSION)).rejects.toMatchObject({ code: 'unavailable' });
  });

  it('treats a network failure as the API being unavailable', async () => {
    const { api } = client(() => Promise.reject(new Error('ECONNREFUSED 10.0.0.5:4000')));
    await expect(api.me(SESSION)).rejects.toMatchObject({ status: 503, code: 'unavailable' });
  });

  it('sends bodies as JSON and reads each kind of answer', async () => {
    const { api, sent } = client((request) =>
      request.path.endsWith('/test') ? { status: 200, body: '{"outcome":"test_sent"}' } : { status: 204, body: '' },
    );
    expect(await api.test(SESSION, '100000000000000001', 'csrf-token')).toBe('test_sent');
    await api.logout(SESSION, 'csrf-token');
    expect(JSON.parse(sent[0]!.body!)).toEqual({ csrf: 'csrf-token' });
    expect(sent[1]!.path).toBe('/v1/auth/logout');
  });
});

describe('httpTransport', () => {
  it('refuses redirects and sets a timeout and JSON content type', async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const original = globalThis.fetch;
    globalThis.fetch = ((url: URL, init: RequestInit) => {
      calls.push({ url: url.toString(), init });
      return Promise.resolve(new Response('{"ok":true}', { status: 200 }));
    }) as typeof fetch;
    try {
      const response = await httpTransport('http://api:4000')({ method: 'POST', path: '/v1/x', headers: { a: 'b' }, body: '{}' });
      expect(response).toEqual({ status: 200, body: '{"ok":true}' });
      expect(calls[0]!.url).toBe('http://api:4000/v1/x');
      expect(calls[0]!.init).toMatchObject({ method: 'POST', redirect: 'error', headers: { a: 'b', 'content-type': 'application/json' } });
      expect(calls[0]!.init.signal).toBeInstanceOf(AbortSignal);
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe('the login redirect', () => {
  const answer = (url: string) => client(() => ({ status: 200, body: JSON.stringify({ url }) })).api;
  const state = 's'.repeat(43);

  it('accepts only Discord’s own authorize page, for this login’s state', async () => {
    expect(await answer(`https://discord.com/oauth2/authorize?state=${state}`).authorizeUrl(state)).toContain('discord.com');
    for (const url of [
      `https://evil.example/oauth2/authorize?state=${state}`,
      `http://discord.com/oauth2/authorize?state=${state}`,
      `https://discord.com.evil.example/oauth2/authorize?state=${state}`,
      `https://discord.com/oauth2/authorize?state=someone-elses`,
      `https://discord.com/api/other?state=${state}`,
    ]) {
      await expect(answer(url).authorizeUrl(state), url).rejects.toMatchObject({ code: 'unavailable' });
    }
  });
});
