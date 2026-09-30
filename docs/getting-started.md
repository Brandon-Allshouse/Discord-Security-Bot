# Getting started: setup, modes and alerts

This guide is for the people running a Discord server with Equinox in it: how to set it up, what the modes do, how to read an alert, and what each button does. Running the service itself (Docker, keys) is covered in the [README](../README.md#getting-started).

- [Adding Equinox to a server](#adding-equinox-to-a-server)
- [Who can do what](#who-can-do-what)
- [Setup](#setup)
- [Modes](#modes)
- [Alerts](#alerts)
- [Reviewing a detection](#reviewing-a-detection)
- [Checking that it works](#checking-that-it-works)
- [The audit log](#the-audit-log)
- [If Equinox leaves your server](#if-equinox-leaves-your-server)
- [Troubleshooting](#troubleshooting)

## Adding Equinox to a server

When the bot starts, its log prints an invite link. It asks for exactly the permissions Equinox uses and nothing more: View Channels, Send Messages, Embed Links, Manage Messages, Manage Roles and Moderate Members. It never asks for Administrator, Kick Members or Ban Members.

When it joins, Equinox:

1. registers your server as its own tenant, in **`alert_only`** mode, so it can't act on its own until you say so;
2. creates an **Equinox Quarantine** role with no permissions (if it has Manage Roles);
3. writes `guild.joined` to your server's audit log.

Move the bot's role **above** the quarantine role and any role you want it to manage (Server Settings → Roles). Discord only lets a bot hand out roles below its own.

> **About the quarantine role.** It starts with no permissions, which on its own doesn't stop anyone from posting. To make quarantine mean something, deny **Send Messages** for that role in your channels (or in each category). Nothing in Equinox quarantines people yet; that starts with hijacked-account detection (M7).

## Who can do what

| | Admins (Manage Server, owner or Administrator) | Mods (the mod role you pick) | Everyone else |
|---|---|---|---|
| `/equinox setup`, `/equinox mode`, `/equinox allow add/remove` | ✅ | ❌ | ❌ |
| `/equinox status`, `/equinox test`, `/equinox check`, `/equinox allow list` | ✅ | ✅ | ❌ |
| The buttons on alerts | ✅ | ✅ | ❌ |
| The web dashboard | ✅ | ❌ | ❌ |

Discord hides the commands from members without Manage Server unless you change that in Server Settings → Integrations. Every refused attempt is written to the audit log as `authz.denied`. Commands and buttons are limited to 10 a minute per person.

## Setup

Run **`/equinox setup`** in Discord, or use **Settings → Alert channel and roles** on your server's dashboard page. Both do the same checks.

| Option | What it's for | Rules |
|---|---|---|
| Alert channel (required) | Where alerts go. Make it a private staff channel. | The bot needs View Channel, Send Messages and Embed Links there. |
| Mod role | People who can review alerts without having Manage Server. | Not @everyone, and not a role that belongs to another bot. |
| Quarantine role | Replaces the one Equinox created. | The bot must be able to hand it out (its role is above it). |

## Modes

| Mode | Suspicious | Malicious |
|---|---|---|
| `alert_only` (default) | Alert | Alert |
| `protect` | Alert | Delete the message, then alert |
| `strict` | Delete the message, then alert | Delete the message, then alert |

Change it with **`/equinox mode`** or on the dashboard. The bot picks up a new mode within 30 seconds. Start in `alert_only`, watch the alerts for a few days, then move to `protect` once you trust them. Kicks and bans are never automatic in any mode.

What counts as suspicious or malicious is explained in [link-protection.md](link-protection.md) and [threat-intel.md](threat-intel.md).

## Alerts

An alert in your alert channel shows:

- **Title**: 🚨 malicious or ⚠️ suspicious, and what was found (a link). "⬆️ Now malicious…" means threat intel made an earlier detection worse (see [threat-intel.md](threat-intel.md#how-it-works)).
- **User** and **Channel**: who posted it, and where.
- **Score**: how sure Equinox is (0–100%), and which checks contributed (`heuristic`, `blocklist`, `urlhaus`, `virustotal`…).
- **Subject**: the link, *defanged* (`hxxps://evil[.]com`) so nobody opens it by accident.
- **Why**: the reasons, in plain words.
- **Actions taken**: what the bot did (✅ delete) or tried and couldn't (❌ delete, with why).
- **Threat intel**: which outside sources flagged it, if any.
- The footer has the mode at the time and the detection ID.

Alerts never ping anyone, whatever the posted text contained.

## Reviewing a detection

Every alert has three buttons. The same three are on the dashboard next to each detection, and deciding in one place updates the other: the Discord alert is marked resolved and its buttons removed.

| Button | What it does | When to use it |
|---|---|---|
| **Restore** | Undoes what the bot did that can be undone (a quarantine, a timeout) and marks the detection *restored*. | The bot acted on something harmless. |
| **Mark false positive** | Same as Restore, and also adds the link's exact host to your server's allowlist, so it isn't flagged again here. | The link is fine and will keep being posted. |
| **Confirm** | Keeps everything as it is and marks the detection *confirmed*. From M5, confirmed links help protect every server on the network. | It really was a scam. |

A **deleted message can't be brought back**: Discord has no undelete, and Equinox doesn't keep message text. After a Restore, the alert says so, and the person has to post it again. Restore and false positive are final; a confirmed detection can still be restored later.

## Checking that it works

- **`/equinox status`** (or the top of the dashboard's Settings) shows the mode, the alert channel, the roles, how many detections are open, and **any permission the bot is missing**.
- **`/equinox test`** (or **Send a test alert** on the dashboard) pushes a harmless test detection through the whole pipeline. You should see an alert in your alert channel within seconds.
- To test link detection in a channel, post `https://equinox-test.invalid/anything`. **Don't post real scam links, not even lookalikes**: Discord may suspend the account that posts them. See [link-protection.md](link-protection.md#testing-safely).

## The audit log

Everything Equinox does, and everything anyone does with it, is recorded, and the log can't be edited or deleted, not even by Equinox. Your server's log is on the dashboard (latest 50 entries).

| Entry | Meaning |
|---|---|
| `guild.joined`, `guild.left` | The bot joined or left the server. |
| `detection.created` | Something was flagged. |
| `detection.escalated` | Threat intel made a detection worse. |
| `action.alert`, `action.delete`, … | What the bot did for a detection, and whether it worked. |
| `review.restore`, `review.false_positive`, `review.confirm` | A decision on a detection, with who made it and whether it was from Discord or the dashboard. |
| `settings.mode`, `settings.setup` | Settings changes (with `via: dashboard` when made there). |
| `allowlist.add`, `allowlist.remove` | Allowlist changes, including ones made by a false-positive click. |
| `authz.denied` | Someone without permission tried a command or button. |

## If Equinox leaves your server

Your server's tenant is deactivated, not deleted. If you add the bot back, your mode, channel, roles and allowlist come back too. Detections are deleted after 90 days either way.

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| Slash commands don't show up | During development, commands only register in `DEV_GUILD_ID`. Otherwise they're hidden from members without Manage Server. | Check `DEV_GUILD_ID`, or give the command permission in Server Settings → Integrations. |
| No alerts arrive | No alert channel, or the bot lost permission in it. | `/equinox status` or the dashboard lists missing permissions. Run setup again. |
| "You don't have permission to use this command." | The command is admin-only, or you don't have the mod role. | See [Who can do what](#who-can-do-what). |
| Deletes fail (❌ delete) | The bot lacks Manage Messages in that channel. | Grant it on the bot's role or the channel. |
| "I can't manage @role. Move my role above it." | The bot's role is below the role you picked. | Server Settings → Roles, drag the bot's role higher. |
| "You're doing that too fast." | More than 10 commands or button clicks in a minute. | Wait a minute. |
| "Something went wrong (ref `abc12345`)." | An unexpected error. The details are in the bot's log under that reference. | Send the reference to whoever runs Equinox. |
