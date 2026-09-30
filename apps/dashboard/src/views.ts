import { BRAND, defang, GUILD_MODES, slash, truncate, type Detection, type GuildSettings } from '@equinox/core';
import { html, type Html } from './html.js';
import type { Session } from './sessions.js';

/*
 * Plain server-rendered pages. This is the first, deliberately bare version of the
 * dashboard: no client-side JavaScript, one stylesheet, everything through `html`.
 */

export const STYLESHEET = `
:root { color-scheme: light dark; --line: #8884; --muted: #888; --accent: #5865f2; --bad: #d83c3e; --warn: #b8860b; }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 system-ui, sans-serif; }
header, main { max-width: 1000px; margin: 0 auto; padding: 16px; }
header { display: flex; gap: 16px; align-items: center; justify-content: space-between; border-bottom: 1px solid var(--line); }
header a { font-weight: 600; text-decoration: none; color: inherit; }
h1 { font-size: 22px; } h2 { font-size: 17px; margin-top: 32px; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 13px; color: var(--muted); font-weight: 600; }
code { font-size: 13px; overflow-wrap: anywhere; }
form.inline { display: inline; }
button, select, input { font: inherit; padding: 4px 10px; }
a.primary { display: inline-block; background: var(--accent); color: #fff; border-radius: 4px; padding: 8px 16px; text-decoration: none; }
.muted { color: var(--muted); }
.malicious { color: var(--bad); font-weight: 600; }
.suspicious { color: var(--warn); font-weight: 600; }
.notice { border: 1px solid var(--line); border-left: 4px solid var(--accent); padding: 8px 12px; margin: 16px 0; }
.notice.error { border-left-color: var(--bad); }
`;

function layout(title: string, body: Html, session?: Session): Html {
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · ${BRAND.name}</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<header>
<a href="/">${BRAND.name}</a>
${
  session &&
  html`<form class="inline" method="post" action="/auth/logout">
<input type="hidden" name="_csrf" value="${session.csrf}">
<span class="muted">${session.username}</span>
<button type="submit">Log out</button>
</form>`
}
</header>
<main>
${body}
</main>
</body>
</html>`;
}

export function landingPage(): Html {
  return layout(
    'Log in',
    html`<h1>${BRAND.name}</h1>
<p>See what ${BRAND.name} has caught in your Discord server and manage its settings.</p>
<p><a class="primary" href="/auth/login">Log in with Discord</a></p>
<p class="muted">You need the Manage Server permission in a server that has ${BRAND.name} installed.</p>`,
  );
}

export function messagePage(title: string, message: string, session?: Session): Html {
  return layout(title, html`<h1>${title}</h1><p>${message}</p><p><a href="/">Back</a></p>`, session);
}

export function serversPage(session: Session, tenants: readonly { id: string; name: string }[]): Html {
  const body = tenants.length
    ? html`<table>
<tr><th>Server</th><th>ID</th></tr>
${tenants.map((t) => html`<tr><td><a href="/servers/${t.id}">${t.name}</a></td><td><code>${t.id}</code></td></tr>`)}
</table>`
    : html`<p>None of the servers you manage have ${BRAND.name} installed yet. Add the bot to a server where you have Manage Server, then log in again.</p>`;
  return layout('Your servers', html`<h1>Your servers</h1>${body}`, session);
}

function when(date: Date): string {
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

const STATUS_LABEL: Record<Detection['status'], string> = {
  open: 'Open',
  confirmed: 'Confirmed',
  false_positive: 'False positive',
  restored: 'Restored',
};

export const NOTICES = {
  mode: 'Mode updated. The bot picks it up within 30 seconds.',
  added: 'Domain added to the allowlist.',
  removed: 'Domain removed from the allowlist.',
} as const;

export const ERRORS = {
  mode: 'Unknown mode.',
  domain: 'Enter a domain like example.com (no path, no IP address).',
  missing: 'That domain isn’t on the allowlist.',
} as const;

export interface TenantView {
  session: Session;
  name: string;
  guild: GuildSettings;
  openCount: number;
  detections: readonly Detection[];
  allowlist: readonly { value: string; addedBy: string; createdAt: Date }[];
  audit: readonly { actor: string; action: string; target: string | null; createdAt: Date }[];
  notice?: keyof typeof NOTICES | undefined;
  error?: keyof typeof ERRORS | undefined;
}

export function tenantPage(view: TenantView): Html {
  const { session, guild } = view;
  const base = `/servers/${guild.id}`;
  const csrf = html`<input type="hidden" name="_csrf" value="${session.csrf}">`;

  const settings = html`<h2>Settings</h2>
<table>
<tr><th>Mode</th><td>
<form class="inline" method="post" action="${base}/mode">${csrf}
<select name="mode">${GUILD_MODES.map((mode) => html`<option value="${mode}"${mode === guild.mode && html` selected`}>${mode}</option>`)}</select>
<button type="submit">Save</button>
</form>
</td></tr>
<tr><th>Alert channel</th><td>${guild.alertChannelId ? html`<code>${guild.alertChannelId}</code>` : 'Not set'}</td></tr>
<tr><th>Mod roles</th><td>${guild.modRoleIds.length ? html`<code>${guild.modRoleIds.join(', ')}</code>` : 'Manage Server only'}</td></tr>
<tr><th>Quarantine role</th><td>${guild.quarantineRoleId ? html`<code>${guild.quarantineRoleId}</code>` : 'Not set'}</td></tr>
</table>
<p class="muted">Channel and roles are set in Discord with <code>${slash('setup')}</code>.</p>`;

  const detections = html`<h2>Detections</h2>
<p>${view.openCount} open. Showing the latest ${view.detections.length}. Review them with the buttons on the alert in Discord.</p>
${
  view.detections.length > 0 &&
  html`<div class="scroll"><table>
<tr><th>When</th><th>Verdict</th><th>Type</th><th>Subject</th><th>User</th><th>Actions</th><th>Status</th></tr>
${view.detections.map(
  (d) => html`<tr>
<td>${when(d.createdAt)}</td>
<td><span class="${d.verdict.level}">${d.verdict.level}</span> ${Math.round(d.verdict.score * 100)}%</td>
<td>${d.signalKind}</td>
<td><code>${truncate(d.signalKind === 'url' ? defang(d.subject) : d.subject, 120)}</code></td>
<td><code>${d.userId}</code></td>
<td>${d.actionsTaken.map((a) => `${a.ok ? '✓' : '✗'} ${a.action}`).join(', ') || 'None'}</td>
<td>${STATUS_LABEL[d.status]}</td>
</tr>`,
)}
</table></div>`
}`;

  const allowlist = html`<h2>Allowlist</h2>
<p>Domains that are never flagged in this server.</p>
${
  view.allowlist.length > 0 &&
  html`<table>
<tr><th>Domain</th><th>Added by</th><th>When</th><th></th></tr>
${view.allowlist.map(
  (row) => html`<tr>
<td><code>${row.value}</code></td>
<td><code>${row.addedBy}</code></td>
<td>${when(row.createdAt)}</td>
<td><form class="inline" method="post" action="${base}/allowlist/remove">${csrf}
<input type="hidden" name="domain" value="${row.value}"><button type="submit">Remove</button></form></td>
</tr>`,
)}
</table>`
}
<form method="post" action="${base}/allowlist">${csrf}
<input name="domain" placeholder="example.com" maxlength="253" required>
<button type="submit">Add domain</button>
</form>`;

  const audit = html`<h2>Audit log</h2>
<div class="scroll"><table>
<tr><th>When</th><th>Who</th><th>What</th><th>Target</th></tr>
${view.audit.map(
  (row) => html`<tr>
<td>${when(row.createdAt)}</td>
<td><code>${row.actor}</code></td>
<td>${row.action}</td>
<td>${row.target ? html`<code>${truncate(row.target, 80)}</code>` : ''}</td>
</tr>`,
)}
</table></div>`;

  return layout(
    view.name,
    html`<p><a href="/servers">← Your servers</a></p>
<h1>${view.name}</h1>
${view.notice && html`<p class="notice">${NOTICES[view.notice]}</p>`}
${view.error && html`<p class="notice error">${ERRORS[view.error]}</p>`}
${settings}${detections}${allowlist}${audit}`,
    session,
  );
}
