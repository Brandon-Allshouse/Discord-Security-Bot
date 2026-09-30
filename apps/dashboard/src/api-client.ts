import type { z } from 'zod';
import {
  apiErrorSchema,
  authorizeUrlSchema,
  botOutcomeSchema,
  guildPageSchema,
  linkCheckResponseSchema,
  meSchema,
  sessionCreatedSchema,
  signApiRequest,
  type ApiErrorCode,
  type BotOutcome,
  type GuildPage,
  type Me,
} from '@equinox/core';

/**
 * The dashboard's only way to data: signed requests to the API. The dashboard has no database,
 * Redis or Discord credentials of its own. Every response is validated before it's used.
 */

export interface TransportRequest {
  method: 'GET' | 'POST';
  path: string;
  headers: Record<string, string>;
  body?: string;
}
export type Transport = (request: TransportRequest) => Promise<{ status: number; body: string }>;

/** A non-2xx answer (or a broken one) from the API. `code` is always from a fixed list. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: ApiErrorCode,
    /** The API's log reference for unexpected failures. */
    readonly ref?: string,
  ) {
    super(`API ${status} ${code}`);
    this.name = 'ApiError';
  }
}

/** Talks to the API over HTTP. Redirects are refused, and every call has a timeout. */
export function httpTransport(baseUrl: string, timeoutMs = 10_000): Transport {
  const base = new URL(baseUrl);
  return async ({ method, path, headers, body }) => {
    const response = await fetch(new URL(path, base), {
      method,
      headers: { ...headers, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
      ...(body !== undefined ? { body } : {}),
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
    return { status: response.status, body: await response.text() };
  };
}

export class ApiClient {
  constructor(
    private readonly transport: Transport,
    private readonly signingKey: string,
  ) {}

  private async call<T extends z.ZodType>(
    schema: T | null,
    method: 'GET' | 'POST',
    path: string,
    session: string,
    payload?: unknown,
  ): Promise<z.infer<T>> {
    const body = payload === undefined ? undefined : JSON.stringify(payload);
    const headers = signApiRequest(this.signingKey, { method, path, body: body ?? '', session });
    let response: { status: number; body: string };
    try {
      response = await this.transport({ method, path, headers, ...(body !== undefined ? { body } : {}) });
    } catch {
      throw new ApiError(503, 'unavailable');
    }
    const json = (() => {
      try {
        return response.body ? (JSON.parse(response.body) as unknown) : undefined;
      } catch {
        return undefined;
      }
    })();
    if (response.status >= 400) {
      const error = apiErrorSchema.safeParse(json);
      throw new ApiError(response.status, error.success ? error.data.error : 'unavailable', error.success ? error.data.ref : undefined);
    }
    if (!schema) return undefined as z.infer<T>;
    const parsed = schema.safeParse(json);
    // An answer that doesn't match the contract is treated as an outage, never rendered.
    if (!parsed.success) throw new ApiError(502, 'unavailable');
    return parsed.data;
  }

  /** Only Discord IDs and UUIDs go into paths, and they're checked before they get here. */
  private static guildPath(guildId: string, rest = ''): string {
    return `/v1/guilds/${encodeURIComponent(guildId)}${rest}`;
  }

  /**
   * Where to send the browser to log in. Only ever Discord's own authorize page, so even a
   * misbehaving API can't turn the login button into a redirect to somewhere else.
   */
  async authorizeUrl(state: string): Promise<string> {
    const { url } = await this.call(authorizeUrlSchema, 'GET', `/v1/auth/authorize-url?state=${encodeURIComponent(state)}`, '');
    const parsed = new URL(url);
    if (parsed.origin !== 'https://discord.com' || parsed.pathname !== '/oauth2/authorize' || parsed.searchParams.get('state') !== state) {
      throw new ApiError(502, 'unavailable');
    }
    return url;
  }

  async createSession(code: string, replaces: string | undefined): Promise<string> {
    return (await this.call(sessionCreatedSchema, 'POST', '/v1/auth/session', '', { code, ...(replaces ? { replaces } : {}) })).sessionId;
  }

  async logout(session: string, csrf: string): Promise<void> {
    await this.call(null, 'POST', '/v1/auth/logout', session, { csrf });
  }

  me(session: string): Promise<Me> {
    return this.call(meSchema, 'GET', '/v1/me', session);
  }

  guild(session: string, guildId: string): Promise<GuildPage> {
    return this.call(guildPageSchema, 'GET', ApiClient.guildPath(guildId), session);
  }

  async setMode(session: string, guildId: string, csrf: string, mode: string): Promise<void> {
    await this.call(null, 'POST', ApiClient.guildPath(guildId, '/mode'), session, { csrf, mode });
  }

  async allowlistAdd(session: string, guildId: string, csrf: string, domain: string): Promise<void> {
    await this.call(null, 'POST', ApiClient.guildPath(guildId, '/allowlist'), session, { csrf, domain });
  }

  async allowlistRemove(session: string, guildId: string, csrf: string, domain: string): Promise<void> {
    await this.call(null, 'POST', ApiClient.guildPath(guildId, '/allowlist/remove'), session, { csrf, domain });
  }

  checkLink(session: string, guildId: string, csrf: string, url: string) {
    return this.call(linkCheckResponseSchema, 'POST', ApiClient.guildPath(guildId, '/check'), session, { csrf, url });
  }

  async review(session: string, guildId: string, csrf: string, detectionId: string, decision: string): Promise<BotOutcome> {
    const path = ApiClient.guildPath(guildId, `/detections/${encodeURIComponent(detectionId)}/review`);
    return (await this.call(botOutcomeSchema, 'POST', path, session, { csrf, decision })).outcome;
  }

  async setup(
    session: string,
    guildId: string,
    csrf: string,
    ids: { alertChannelId: string; modRoleId: string | null; quarantineRoleId: string | null },
  ): Promise<BotOutcome> {
    return (await this.call(botOutcomeSchema, 'POST', ApiClient.guildPath(guildId, '/setup'), session, { csrf, ...ids })).outcome;
  }

  async test(session: string, guildId: string, csrf: string): Promise<BotOutcome> {
    return (await this.call(botOutcomeSchema, 'POST', ApiClient.guildPath(guildId, '/test'), session, { csrf })).outcome;
  }
}
