# Link protection

How Equinox finds links in messages and decides whether they're dangerous, using only what it knows locally. Outside sources (URLhaus, VirusTotal and others) are covered in [threat-intel.md](threat-intel.md).

- [What it catches](#what-it-catches)
- [Finding links](#finding-links)
- [How a link is scored](#how-a-link-is-scored)
- [Blocklist and allowlist](#blocklist-and-allowlist)
- [Checking a link yourself](#checking-a-link-yourself)
- [Testing safely](#testing-safely)
- [Limits and known gaps](#limits-and-known-gaps)
- [Troubleshooting false alarms](#troubleshooting-false-alarms)

## What it catches

The scams that spread on Discord mostly imitate something people trust: fake Nitro gifts, fake Steam trade pages, fake wallet "airdrops", "I accidentally reported you" messages. Equinox looks for:

- **Lookalike domains** of Discord, Steam, Epic Games, Roblox, MetaMask, Phantom, Trust Wallet, Coinbase and OpenSea: `dlscord.gift`, `d1sc0rd.com`, `dіscord.com` (with a Cyrillic і), `steamcomnunity.ru`.
- **Brand names on domains the brand doesn't own**, especially with bait words: `discord-nitro-free.xyz`, `steam-gift-claim.com`.
- **Hidden destinations**: `https://discord.com@evil.example`, raw IP addresses, punycode (`xn--…`) domains.
- **Scam wording** in the message around the link: "free nitro", "claim your reward", "first 100 people", "try my new game".
- **Known bad domains** on the network blocklist.

Every check runs on every message, including **edited** messages (scammers edit a harmless message into a link after it passes review). A check takes well under a millisecond.

## Finding links

Equinox finds links however they're written:

| Written as | Found as |
|---|---|
| `https://evil.example/x` | as is |
| `[Free Nitro](https://evil.example)` (a masked link) | the real target, `https://evil.example` |
| `evil.example/claim` (no `https://`) | `http://evil.example/claim`, if it ends in a real domain ending like `.com` or `.gift` |
| `hxxps://evil[.]example`, `evil(.)example`, `evil[dot]example`, `evil . example` | `https://evil.example` |
| Zero-width or other invisible characters inside the link | removed |

Each link is then **normalized**: lowercase domain, both punycode and Unicode forms kept for the lookalike checks, tracking parameters (`utm_…`, `fbclid`, `gclid` and similar) removed, and anything after `#` dropped. Only `http` and `https` links count; `javascript:`, `file:` and the like are ignored.

## How a link is scored

Each sign adds a weight. Weights combine so that independent weak signs add up but never pass 100%. **50%** or more is *suspicious*, **80%** or more *malicious*. One weak sign on its own never reaches "suspicious", because a false alarm is worse than a miss.

| Sign | Weight |
|---|---|
| Looks like a brand with swapped characters (`dlscord`, `d1sc0rd`, Cyrillic letters) | 85% |
| A misspelling of a brand (`dicsord`, `steamcomnunity`) | 70% |
| Uses the brand's name on a domain it doesn't own (`discord-fans.net`) | 45% |
| …and the domain also has bait words (gift, nitro, free, claim, login, verify, airdrop…) | +35% |
| Hides the real destination with an `@` (`https://discord.com@evil.example`) | 50% |
| A raw IP address instead of a domain | 35% |
| Punycode (non-Latin lookalike characters) in the domain | 35% |
| A domain ending often used for scams (`.gift`, `.xyz`, `.top`, `.click`, `.ru` and others) | 20% |
| Scam wording in the message | 25%, up to 45% for several |

Examples:

- `https://discord.com/channels/…`: the real site, **never scored**.
- `https://discord-fan-art.com`: brand name only (45%), **not flagged**.
- `https://discord-nitro-gift.xyz`: brand name (45%) + bait words (35%) + risky ending (20%) = 71%, **suspicious**.
- `https://dlscord.gift/abc`: a lookalike (85%) + bait word "gift" (35%) + risky ending (20%) = 92%, **malicious**.

The brands' real domains (`discord.com`, `discord.gg`, `steampowered.com` and their subdomains) and a list of popular sites (GitHub, YouTube, Google, Reddit, Twitch, Tenor, top.gg and others) are **never flagged** and never sent to outside sources. The full list is `SAFE_DOMAINS` in `packages/core/src/links/heuristics.ts`.

## Blocklist and allowlist

| | Blocklist | Allowlist |
|---|---|---|
| Whose | The whole network | Your server only |
| What it does | Anything on it is **malicious**, whatever the score | Anything on it is **clean**, whatever the score or blocklist says |
| Matches | The domain and all its subdomains | The domain and all its subdomains |
| Changed by | A seed list of known scam domains today; network confirmations from M5 | `/equinox allow add|remove`, the dashboard, and **Mark false positive** (which adds the exact host only) |

Your allowlist always wins, so your server can override any false alarm without affecting anyone else. **Mark false positive** adds only the exact host (`files.example.com`, not `example.com`), so one click can't open up a whole domain.

## Checking a link yourself

Use **`/equinox check url:<link>`** in Discord (mods), or **Check a link** on the dashboard. Nothing is posted in any channel. The answer shows the verdict, the score, every reason, and what threat intel says. The check is mods-only so outsiders can't use it to test links against the blocklist.

## Testing safely

**Never post real scam links in Discord, not even lookalikes like the examples on this page.** Discord scans messages for phishing and can suspend the account that posted one, test or not.

Instead:

- Post `https://equinox-test.invalid/anything`. It's on the seed blocklist, so Equinox treats it as malicious, but `.invalid` is a reserved name that can never be a real site. It needs the `https://`.
- Use `/equinox check` or the dashboard's **Check a link** for anything else: nothing is posted.
- Use `/equinox test` or **Send a test alert** to see an alert without any link.

## Limits and known gaps

- At most **10 links** and the first **8,000 characters** of a message are checked, so a message stuffed with links can't slow the bot down.
- Text without `https://` that looks like a file name is not treated as a link: `setup.exe`, `notes.txt`, `photo.png`, `archive.zip`. `.zip` is also a real domain ending, so `archive.zip` could be a site; written with `https://` it *is* checked.
- Links in images, embeds from other bots, attachments and files aren't checked yet. File scanning comes with M6.
- A brand-new scam domain that doesn't imitate anyone and has no scam wording scores low locally. That's the gap threat intel covers.

## Troubleshooting false alarms

| Problem | Fix |
|---|---|
| A site your server trusts keeps getting flagged | `/equinox allow add <domain>` or the dashboard's Allowlist. It covers subdomains too. |
| One alert was wrong | **Mark false positive** on the alert (or the dashboard). The exact host is allowlisted here. |
| A fan site uses the brand name (`discord-fan-art.com`) | The name alone is 45%, below "suspicious". If it's flagged, something else about it also looks off. `/equinox check` shows every reason. |
| A real scam wasn't caught | Report it with `/equinox check` output to whoever runs Equinox. From M5, confirmed scams are blocked across the network. |
