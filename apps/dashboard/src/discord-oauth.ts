import { z } from 'zod';

const API = 'https://discord.com/api/v10';
const TIMEOUT_MS = 5000;
const MAX_GUILDS = 200;

const ADMINISTRATOR = 0x8n;
const MANAGE_GUILD = 0x20n;

const tokenSchema = z.object({ access_token: z.string().min(1) });
const userSchema = z.object({
  id: z.string().regex(/^\d{17,20}$/),
  username: z.string().max(100),
});
const guildsSchema = z.array(
  z.object({
    id: z.string().regex(/^\d{17,20}$/),
    name: z.string().max(200),
    owner: z.boolean().optional(),
    permissions: z.string().regex(/^\d+$/),
  }),
);

export interface DiscordLogin {
  user: { id: string; username: string };
  /** Servers where the user is an admin in the same sense as the bot: owner, Administrator or Manage Server. */
  manageableGuilds: { id: string; name: string }[];
}

export interface DiscordOAuth {
  authorizeUrl(state: string): string;
  login(code: string): Promise<DiscordLogin>;
}

export function canManage(guild: { owner?: boolean | undefined; permissions: string }): boolean {
  return guild.owner === true || (BigInt(guild.permissions) & (ADMINISTRATOR | MANAGE_GUILD)) !== 0n;
}

/** Log in with Discord (authorization code flow). Only asks for `identify` and `guilds`. */
export class DiscordOAuthClient implements DiscordOAuth {
  private readonly redirectUri: string;

  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
    dashboardUrl: string,
  ) {
    this.redirectUri = new URL('/auth/callback', dashboardUrl).toString();
  }

  authorizeUrl(state: string): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      response_type: 'code',
      redirect_uri: this.redirectUri,
      scope: 'identify guilds',
      state,
      prompt: 'none',
    });
    return `https://discord.com/oauth2/authorize?${params.toString()}`;
  }

  async login(code: string): Promise<DiscordLogin> {
    const { access_token: token } = tokenSchema.parse(
      await this.post('/oauth2/token', { grant_type: 'authorization_code', code, redirect_uri: this.redirectUri }),
    );
    try {
      const [user, guilds] = await Promise.all([
        this.get('/users/@me', token).then((body) => userSchema.parse(body)),
        this.get('/users/@me/guilds', token).then((body) => guildsSchema.parse(body)),
      ]);
      return {
        user: { id: user.id, username: user.username },
        manageableGuilds: guilds
          .filter(canManage)
          .slice(0, MAX_GUILDS)
          .map(({ id, name }) => ({ id, name })),
      };
    } finally {
      // We only needed the token to read who the user is, so hand it back instead of storing it.
      await this.post('/oauth2/token/revoke', { token, token_type_hint: 'access_token' }).catch(() => undefined);
    }
  }

  private async post(path: string, form: Record<string, string>): Promise<unknown> {
    const response = await fetch(`${API}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ ...form, client_id: this.clientId, client_secret: this.clientSecret }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    // Status only: Discord's error bodies can echo what we sent.
    if (!response.ok) throw new Error(`Discord OAuth error ${response.status}`);
    return response.json();
  }

  private async get(path: string, token: string): Promise<unknown> {
    const response = await fetch(`${API}${path}`, {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) throw new Error(`Discord API error ${response.status}`);
    return response.json();
  }
}
