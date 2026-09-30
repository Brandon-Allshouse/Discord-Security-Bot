import { describe, expect, it } from 'vitest';
import {
  API_HEADERS,
  API_REQUEST_MAX_AGE_MS,
  apiErrorSchema,
  guildPageSchema,
  signApiRequest,
  verifyApiRequest,
  type ApiRequestParts,
} from './api-contract.js';

const KEY = 'cd'.repeat(32);
const now = 1_800_000_000_000;
const parts: ApiRequestParts = { method: 'POST', path: '/v1/guilds/100000000000000001/mode', body: '{"csrf":"x","mode":"strict"}', session: 'a'.repeat(43) };

/** Verifies against the request as the API receives it: the session comes from the headers, not the parts. */
const verify = (headers: Record<string, string>, override: Partial<ApiRequestParts> = {}, at = now) => {
  const received = { ...parts, ...override };
  return verifyApiRequest(KEY, { method: received.method, path: received.path, body: received.body }, headers, at);
};

describe('API request signing', () => {
  it('accepts a request signed with the key, and returns its nonce', () => {
    const headers = signApiRequest(KEY, parts, now, 'n'.repeat(24));
    expect(verify(headers)).toEqual({ ok: true, nonce: 'n'.repeat(24) });
    expect(headers[API_HEADERS.session]).toBe(parts.session);
  });

  it('leaves out the session header when there is no session', () => {
    expect(signApiRequest(KEY, { ...parts, session: '' }, now)).not.toHaveProperty(API_HEADERS.session);
  });

  it('refuses any change to what was signed', () => {
    const headers = signApiRequest(KEY, parts, now);
    expect(verify(headers, { method: 'GET' })).toEqual({ ok: false, problem: 'bad_signature' });
    expect(verify(headers, { path: '/v1/guilds/100000000000000002/mode' })).toEqual({ ok: false, problem: 'bad_signature' });
    expect(verify(headers, { body: '{"csrf":"x","mode":"alert_only"}' })).toEqual({ ok: false, problem: 'bad_signature' });
    expect(verify({ ...headers, [API_HEADERS.session]: 'b'.repeat(43) })).toEqual({ ok: false, problem: 'bad_signature' });
    expect(verify({ ...headers, [API_HEADERS.nonce]: 'm'.repeat(24) })).toEqual({ ok: false, problem: 'bad_signature' });
  });

  it('refuses another key, stale or future timestamps, and missing or malformed headers', () => {
    expect(verify(signApiRequest('ab'.repeat(32), parts, now))).toEqual({ ok: false, problem: 'bad_signature' });
    const headers = signApiRequest(KEY, parts, now);
    expect(verify(headers, {}, now + API_REQUEST_MAX_AGE_MS + 1)).toEqual({ ok: false, problem: 'stale' });
    expect(verify(headers, {}, now - API_REQUEST_MAX_AGE_MS - 1)).toEqual({ ok: false, problem: 'stale' });
    expect(verify({})).toEqual({ ok: false, problem: 'missing' });
    expect(verify({ ...headers, [API_HEADERS.signature]: 'zz' })).toEqual({ ok: false, problem: 'missing' });
    expect(verify({ ...headers, [API_HEADERS.nonce]: 'short' })).toEqual({ ok: false, problem: 'missing' });
    expect(verify({ ...headers, [API_HEADERS.timestamp]: 'soon' })).toEqual({ ok: false, problem: 'missing' });
  });

  it('treats the method case-insensitively but everything else exactly', () => {
    const headers = signApiRequest(KEY, { ...parts, method: 'post' }, now);
    expect(verify(headers)).toMatchObject({ ok: true });
  });

  it('uses a new random nonce each time by default', () => {
    expect(signApiRequest(KEY, parts, now)[API_HEADERS.nonce]).not.toBe(signApiRequest(KEY, parts, now)[API_HEADERS.nonce]);
  });
});

describe('response contract', () => {
  it('only accepts known error codes and well-formed references', () => {
    expect(apiErrorSchema.safeParse({ error: 'csrf' }).success).toBe(true);
    expect(apiErrorSchema.safeParse({ error: 'unavailable', ref: '0123abcd' }).success).toBe(true);
    expect(apiErrorSchema.safeParse({ error: 'unavailable', ref: '<script>' }).success).toBe(false);
    expect(apiErrorSchema.safeParse({ error: 'anything' }).success).toBe(false);
  });

  it('turns dates in pages back into dates, and rejects bad IDs', () => {
    const page = {
      viewer: { username: 'a', csrf: 'x'.repeat(43) },
      name: 'Server',
      guild: { id: '100000000000000001', mode: 'alert_only', alertChannelId: null, quarantineRoleId: null, modRoleIds: [] },
      openCount: 0,
      detections: [],
      allowlist: [{ value: 'example.com', addedBy: '500000000000000001', createdAt: '2026-09-30T00:00:00.000Z' }],
      audit: [],
      intelStatus: null,
      snapshot: null,
      botEnabled: false,
    };
    const parsed = guildPageSchema.parse(page);
    expect(parsed.allowlist[0]!.createdAt).toBeInstanceOf(Date);
    expect(guildPageSchema.safeParse({ ...page, guild: { ...page.guild, id: '1; drop table' } }).success).toBe(false);
    expect(guildPageSchema.safeParse({ ...page, guild: { ...page.guild, mode: 'yolo' } }).success).toBe(false);
  });
});
