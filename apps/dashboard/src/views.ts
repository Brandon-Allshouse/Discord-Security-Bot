import {
  BRAND,
  defang,
  GUILD_MODES,
  slash,
  truncate,
  type GuildPage,
  type GuildSnapshot,
  type IntelStatus,
  type LinkCheck,
  type Viewer,
} from '@equinox/core';
import { html, type Html } from './html.js';

/** A detection as the API sends it. */
type DetectionRow = GuildPage['detections'][number];

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
.status-off { border: 1px solid var(--line); border-left: 4px solid var(--bad); padding: 8px 12px; margin: 16px 0; }
ul.reasons { margin: 0; padding-left: 18px; }
.ok { color: #23a55a; font-weight: 600; }
input.wide { width: min(100%, 520px); }
`;

function layout(title: string, body: Html, viewer?: Viewer): Html {
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
  viewer &&
  html`<form class="inline" method="post" action="/auth/logout">
<input type="hidden" name="_csrf" value="${viewer.csrf}">
<span class="muted">${viewer.username}</span>
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

export function messagePage(title: string, message: string, viewer?: Viewer): Html {
  return layout(title, html`<h1>${title}</h1><p>${message}</p><p><a href="/">Back</a></p>`, viewer);
}

export function serversPage(viewer: Viewer, tenants: readonly { id: string; name: string }[]): Html {
  const body = tenants.length
    ? html`<table>
<tr><th>Server</th><th>ID</th></tr>
${tenants.map((t) => html`<tr><td><a href="/servers/${t.id}">${t.name}</a></td><td><code>${t.id}</code></td></tr>`)}
</table>`
    : html`<p>None of the servers you manage have ${BRAND.name} installed yet. Add the bot to a server where you have Manage Server, then log in again.</p>`;
  return layout('Your servers', html`<h1>Your servers</h1>${body}`, viewer);
}

function when(date: Date): string {
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

const STATUS_LABEL: Record<DetectionRow['status'], string> = {
  open: 'Open',
  confirmed: 'Confirmed',
  false_positive: 'False positive',
  restored: 'Restored',
};

export const NOTICES = {
  mode: 'Mode updated. The bot picks it up within 30 seconds.',
  added: 'Domain added to the allowlist.',
  removed: 'Domain removed from the allowlist.',
  reviewed: 'Done. The alert in Discord was updated too.',
  setup: 'Settings saved.',
  test: 'Test alert sent. Check your alert channel in Discord.',
} as const;

export const ERRORS = {
  mode: 'Unknown mode.',
  domain: 'Enter a domain like example.com (no path, no IP address).',
  missing: 'That domain isn’t on the allowlist.',
  url: 'Enter a link like https://example.com/page.',
  already_resolved: 'That detection was already resolved.',
  detection_missing: 'That detection no longer exists.',
  setup_channel: 'The bot can’t post in that channel. It needs View Channel, Send Messages and Embed Links there.',
  setup_mod_role: 'Pick a regular role for moderators, not @everyone or a bot’s role.',
  setup_quarantine_role: 'The bot can’t hand out that role. Move the bot’s role above it in Server Settings → Roles.',
  test_failed: 'The test signal didn’t go through. Check the bot’s logs.',
  bot_unavailable: 'The bot isn’t reachable right now, so nothing was changed. Try again in a minute.',
  bot_timeout: 'The bot didn’t answer in time, so nothing was changed. Try again in a minute.',
  bot_rejected: 'The bot refused the request. Check that INTERNAL_SIGNING_KEY is the same for the bot and the API.',
  bot_off: 'This needs INTERNAL_SIGNING_KEY to be set for the bot and the API.',
} as const;

export interface TenantView {
  viewer: Viewer;
  name: string;
  guild: GuildPage['guild'];
  openCount: number;
  detections: readonly DetectionRow[];
  allowlist: readonly { value: string; addedBy: string; createdAt: Date }[];
  audit: readonly { actor: string; action: string; target: string | null; createdAt: Date }[];
  /** The intel worker's heartbeat; null when it isn't running (or can't be read). */
  intelStatus: IntelStatus | null;
  /** The bot's view of the server (channel and role names); null if the bot hasn't reported it. */
  snapshot: GuildSnapshot | null;
  /** Review, setup and test go through the bot; off without a signing key. */
  botEnabled: boolean;
  notice?: keyof typeof NOTICES | undefined;
  error?: keyof typeof ERRORS | undefined;
}

export function tenantPage(view: TenantView): Html {
  const { viewer, guild } = view;
  const base = `/servers/${guild.id}`;
  const csrf = html`<input type="hidden" name="_csrf" value="${viewer.csrf}">`;

  const { snapshot, botEnabled } = view;
  const channelName = (id: string | null) => {
    if (!id) return 'Not set';
    const found = snapshot?.channels.find((c) => c.id === id);
    return found ? `#${found.name}` : id;
  };
  const roleName = (id: string | null) => {
    if (!id) return null;
    const found = snapshot?.roles.find((r) => r.id === id);
    return found ? `@${found.name}` : id;
  };
  const botOff = !botEnabled
    ? html`<p class="muted">Changing the alert channel and roles, reviewing detections and sending a test alert here need
<code>INTERNAL_SIGNING_KEY</code> (see <code>docs/dashboard.md</code>). Until then, use <code>${slash('setup')}</code>,
<code>${slash('test')}</code> and the buttons on the alert in Discord.</p>`
    : null;

  const health = html`${
    snapshot && snapshot.missingPermissions.length > 0 &&
    html`<p class="status-off">The bot is missing these permissions in this server, so some actions will fail:
<strong>${snapshot.missingPermissions.join(', ')}</strong>. Fix it in Server Settings → Roles, on the bot’s role.</p>`
  }${
    snapshot && guild.alertChannelId && snapshot.channels.find((c) => c.id === guild.alertChannelId)?.canPostAlerts === false &&
    html`<p class="status-off">The bot can’t post in the alert channel any more, so alerts won’t arrive. Pick another channel below or fix its permissions.</p>`
  }${
    guild.alertChannelId === null &&
    html`<p class="status-off">No alert channel is set, so detections won’t be announced anywhere. Pick one below.</p>`
  }`;

  const setupForm =
    botEnabled && snapshot
      ? html`<h3>Alert channel and roles</h3>
<form method="post" action="${base}/setup">${csrf}
<table>
<tr><th><label for="alert_channel">Alert channel</label></th><td><select id="alert_channel" name="alert_channel" required>
${snapshot.channels.map(
  (c) => html`<option value="${c.id}"${c.id === guild.alertChannelId && html` selected`}${!c.canPostAlerts && html` disabled`}>#${c.name}${
    !c.canPostAlerts && ' (bot can’t post here)'
  }</option>`,
)}
</select></td></tr>
<tr><th><label for="mod_role">Mod role</label></th><td><select id="mod_role" name="mod_role">
<option value="">None (Manage Server only)</option>
${snapshot.roles
  .filter((r) => r.canBeModRole)
  .map((r) => html`<option value="${r.id}"${guild.modRoleIds.includes(r.id) && html` selected`}>@${r.name}</option>`)}
</select></td></tr>
<tr><th><label for="quarantine_role">Quarantine role</label></th><td><select id="quarantine_role" name="quarantine_role">
<option value="">Keep the current one</option>
${snapshot.roles
  .filter((r) => r.canBeQuarantineRole)
  .map((r) => html`<option value="${r.id}"${r.id === guild.quarantineRoleId && html` selected`}>@${r.name}</option>`)}
</select></td></tr>
</table>
<p><button type="submit">Save</button> <span class="muted">Only channels the bot can post in and roles it can hand out can be picked.</span></p>
</form>
<h3>Test alert</h3>
<form method="post" action="${base}/test">${csrf}
<p><button type="submit">Send a test alert</button> <span class="muted">A harmless alert in your alert channel, like <code>${slash('test')}</code>.</span></p>
</form>`
      : botEnabled
        ? html`<p class="muted">The bot hasn’t reported this server’s channels and roles yet (is it running?). Until it does, use <code>${slash('setup')}</code> in Discord.</p>`
        : botOff;

  const settings = html`<h2>Settings</h2>
${health}
<table>
<tr><th>Mode</th><td>
<form class="inline" method="post" action="${base}/mode">${csrf}
<select name="mode">${GUILD_MODES.map((mode) => html`<option value="${mode}"${mode === guild.mode && html` selected`}>${mode}</option>`)}</select>
<button type="submit">Save</button>
</form>
<span class="muted">alert_only: alerts only · protect: also deletes malicious links · strict: also deletes suspicious ones</span>
</td></tr>
<tr><th>Alert channel</th><td>${channelName(guild.alertChannelId)}</td></tr>
<tr><th>Mod roles</th><td>${guild.modRoleIds.length ? guild.modRoleIds.map((id) => roleName(id)).join(', ') : 'Manage Server only'}</td></tr>
<tr><th>Quarantine role</th><td>${roleName(guild.quarantineRoleId) ?? 'Not set'}</td></tr>
</table>
${setupForm}`;

  const reviewButtons = (d: DetectionRow) => {
    if (!botEnabled || d.status === 'restored' || d.status === 'false_positive') return null;
    const button = (decision: string, label: string) =>
      html`<form class="inline" method="post" action="${base}/detections/${d.id}/review">${csrf}<input type="hidden" name="decision" value="${decision}"><button type="submit">${label}</button></form>`;
    return html`${button('restore', 'Restore')} ${button('false_positive', 'False positive')} ${d.status !== 'confirmed' && button('confirm', 'Confirm')}`;
  };

  const detections = html`<h2>Detections</h2>
<p>${view.openCount} open. Showing the latest ${view.detections.length}. ${
    botEnabled
      ? 'Review them here or with the buttons on the alert in Discord: Restore undoes what the bot did, False positive also allowlists the link’s host in this server, Confirm keeps it.'
      : 'Review them with the buttons on the alert in Discord.'
  }</p>
${
  view.detections.length > 0 &&
  html`<div class="scroll"><table>
<tr><th>When</th><th>Verdict</th><th>Type</th><th>Subject</th><th>Why</th><th>User</th><th>Actions</th><th>Status</th><th>Review</th></tr>
${view.detections.map(
  (d) => html`<tr>
<td>${when(d.createdAt)}</td>
<td><span class="${d.verdict.level}">${d.verdict.level}</span> ${Math.round(d.verdict.score * 100)}%</td>
<td>${d.signalKind}</td>
<td><code>${truncate(d.signalKind === 'url' ? defang(d.subject) : d.subject, 120)}</code></td>
<td>${whyCell(d)}</td>
<td><code>${d.userId}</code></td>
<td>${d.actionsTaken.map((a) => `${a.ok ? '✓' : '✗'} ${a.action}`).join(', ') || 'None'}</td>
<td>${STATUS_LABEL[d.status]}</td>
<td>${reviewButtons(d)}</td>
</tr>`,
)}
</table></div>`
}`;

  const intel = html`<h2>Threat intel</h2>
<p>Links nobody has seen before are looked up in outside threat-intel sources: where shortened links really go,
how old the domain is, the URLhaus malware list, and VirusTotal. If a link turns out worse than it first looked,
${BRAND.name} comes back to the message and alerts (or acts, depending on the mode). See <code>docs/threat-intel.md</code>.</p>
${intelStatusTable(view.intelStatus)}
<h3>Check a link</h3>
<p class="muted">Like <code>${slash('check')}</code> in Discord. Nothing is posted anywhere.</p>
<form method="post" action="${base}/check">${csrf}
<input class="wide" name="url" placeholder="https://example.com/page" maxlength="2048" required>
<button type="submit">Check</button>
</form>`;

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
${settings}${detections}${intel}${allowlist}${audit}`,
    viewer,
  );
}

/** Sources that are the sensor's own checks rather than outside threat intel. */
const LOCAL_SOURCES = new Set(['heuristic', 'allowlist', 'blocklist']);

function whyCell(d: DetectionRow): Html {
  const intel = d.verdict.sources.filter((s) => !LOCAL_SOURCES.has(s));
  return html`${
    d.verdict.reasons.length > 0 &&
    html`<ul class="reasons">${d.verdict.reasons.slice(0, 5).map((r) => html`<li>${truncate(r, 160)}</li>`)}</ul>`
  }${intel.length > 0 && html`<span class="muted">Threat intel: ${intel.join(', ')}</span>`}`;
}

function intelStatusTable(status: IntelStatus | null): Html {
  if (!status) {
    return html`<p class="status-off">The threat-intel worker isn’t running right now, so links are only checked locally.
Detection still works; lookups resume when it’s back.</p>`;
  }
  return html`<table>
<tr><th>Worker</th><td><span class="ok">Running</span> <span class="muted">(last seen ${when(new Date(status.heartbeatAt))})</span></td></tr>
<tr><th>URLhaus malware list</th><td>${
    status.urlhaus
      ? html`${status.urlhaus.count.toLocaleString('en-US')} links, ${
          status.urlhaus.syncedAt ? `updated ${when(new Date(status.urlhaus.syncedAt))}` : 'last update time not known yet'
        }`
      : 'Not downloaded yet'
  }</td></tr>
<tr><th>Domain age (RDAP)</th><td>On</td></tr>
<tr><th>VirusTotal</th><td>${
    status.virustotal ? 'On, for links that look off or show up in several servers' : 'Off (no API key configured)'
  }</td></tr>
</table>`;
}

const CHECK_LEVEL: Record<LinkCheck['level'], string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  clean: 'No known issues',
};

export interface CheckResultView {
  viewer: Viewer;
  guildId: string;
  name: string;
  result: LinkCheck;
  /** A lookup was queued for this link just now. */
  queued: boolean;
}

export function checkResultPage(view: CheckResultView): Html {
  const { result, viewer } = view;
  const base = `/servers/${view.guildId}`;
  const level = result.allowlisted
    ? 'Clean (allowlisted in this server)'
    : result.blocklisted
      ? `Malicious (on the ${BRAND.name} blocklist)`
      : CHECK_LEVEL[result.level];

  const intelLine =
    result.intelState === 'not_needed'
      ? html`<p class="muted">${
          result.knownSafe ? 'A well-known site, so it isn’t sent to outside sources.' : 'Settled locally, so outside sources weren’t needed.'
        }</p>`
      : result.intelState === 'checked'
        ? html`<p>Threat intel: ${result.intel?.sources.length ? result.intel.sources.join(', ') : 'no source knows of problems with it'}.</p>`
        : view.queued
          ? html`<p class="notice">Not looked up yet. A lookup is queued now; check again in a minute to see what the sources say.</p>`
          : html`<p class="notice error">Not looked up yet, and the lookup couldn’t be queued. Try again later.</p>`;

  return layout(
    'Link check',
    html`<p><a href="${base}">← ${view.name}</a></p>
<h1>Link check</h1>
<p><code>${defang(result.url)}</code></p>
<p><span class="${result.level}">${level}</span> · score ${Math.round(result.score * 100)}%</p>
${
  result.reasons.length > 0 &&
  html`<ul class="reasons">${result.reasons.map((r) => html`<li>${r}</li>`)}</ul>`
}
${intelLine}
<form method="post" action="${base}/check"><input type="hidden" name="_csrf" value="${viewer.csrf}">
<input type="hidden" name="url" value="${result.url}">
<button type="submit">Check again</button>
</form>`,
    viewer,
  );
}
