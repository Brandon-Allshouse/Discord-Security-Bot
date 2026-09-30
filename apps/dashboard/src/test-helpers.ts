import { createTestApi, TEST_API_KEY } from '@equinox/api/testing';
import { ApiClient, type Transport } from './api-client.js';
import { buildApp } from './app.js';

export { ADMIN, OTHER_TENANT, TENANT } from '@equinox/api/testing';
/** The Host header of the public address the test app is configured with. */
export const HOST = { host: 'localhost:3000' };

/**
 * The whole web stack in one process: the dashboard, talking through its real API client (with
 * real request signing) to the real API, which runs on in-memory stores. Every test here goes
 * browser → dashboard → signed request → API, the same path as production.
 */
export async function createTestApp(publicUrl = 'http://localhost:3000') {
  const backend = await createTestApi();
  const requests: { method: string; path: string }[] = [];
  const transport: Transport = async ({ method, path, headers, body }) => {
    requests.push({ method, path });
    const response = await backend.api.inject({
      method,
      url: path,
      headers: { ...headers, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
      ...(body !== undefined ? { payload: body } : {}),
    });
    return { status: response.statusCode, body: response.body };
  };
  const app = await buildApp({ api: new ApiClient(transport, TEST_API_KEY), publicUrl });

  /** Goes through the real login routes and returns the session cookie and CSRF token. */
  async function logIn() {
    const start = await app.inject({ method: 'GET', url: '/auth/login', headers: HOST });
    const state = backend.discord.states.at(-1)!;
    const callback = await app.inject({
      method: 'GET',
      url: `/auth/callback?code=abc&state=${state}`,
      cookies: { eq_oauth_state: start.cookies.find((c) => c.name === 'eq_oauth_state')!.value },
    });
    const id = callback.cookies.find((c) => c.name === 'eq_session')!.value;
    return { cookies: { eq_session: id }, csrf: backend.sessions.sessions.get(id)!.csrf, callback };
  }

  return { ...backend, app, logIn, requests };
}
