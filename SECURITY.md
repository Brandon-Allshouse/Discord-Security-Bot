# Security Policy

Equinox runs with moderation permissions in a lot of Discord servers at once, and every one of those servers is its own tenant. A bug here doesn't stay in one place, so if you find one, please tell us privately first.

## Standards we build against

| Standard | What we use it for |
|---|---|
| [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | Security and privacy controls: access control (AC), audit and accountability (AU), configuration management (CM), identification and authentication (IA), system and communications protection (SC), system and information integrity (SI), PII processing (PT), supply chain (SR) |
| [NIST SP 800-218 (SSDF)](https://csrc.nist.gov/pubs/sp/800/218/final) | How we build and ship: prepare the organization (PO), protect the software (PS), produce well-secured software (PW), respond to vulnerabilities (RV) |
| [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/) | Requirements for encoding (V1), validation (V2), authorization (V8), configuration (V13), data protection (V14), logging and error handling (V16) and more |
| [OWASP Top 10 (2025)](https://owasp.org/Top10/) | The risk categories we check every change against, cited by name |

[docs/security-controls.md](docs/security-controls.md) lists each control, the standard behind it, where it lives in the code, and whether it's done yet. If something listed as done doesn't actually hold, that counts as a vulnerability.

## Supported versions

There are no releases yet. Until there are, only the latest commit on `main` is supported.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| Anything older | ❌ |

## Reporting a vulnerability

**Please don't open a public issue, discussion or pull request for a security problem.**

Use GitHub's [private vulnerability reporting](../../security/advisories/new) instead (the **Security** tab, then **Report a vulnerability**).

It helps if you include:

- What the problem is, and which part it affects (`bot`, `api`, `worker`, `dashboard`, `core`, `db` or `config`).
- How to reproduce it, or a proof of concept.
- What you think the impact is. For example, which servers or users are affected, and whether it could reach across tenants or spread through the network.
- A fix, if you have one in mind.

### What we do with it

We follow the "Respond to Vulnerabilities" part of the NIST SSDF:

1. Confirm the problem (RV.1).
2. Work out how bad it is and fix it. Anything that crosses tenants or spreads through the network goes first (RV.2).
3. Find the root cause, look for the same kind of bug elsewhere, and add a test so it can't come back (RV.3).

### How long it takes

| Step | Target |
|---|---|
| We confirm we got your report | Within 3 business days |
| First assessment | Within 7 days |
| Fix or workaround for critical issues | As soon as we can, usually within 30 days |

We'll keep you posted, agree on a disclosure date with you, and credit you in the advisory unless you'd rather stay anonymous.

## Scope

### In scope

These are what we most want to hear about, because they'd break the promises the network makes:

- **Leaks between tenants.** One server seeing another server's detections, evidence, settings, allowlist or audit log. Getting around the database's row-level security. One user seeing another user's data through `/equinox data`. *(NIST AC-3, AC-4, SC-4 · ASVS V8 · OWASP Top 10: Broken Access Control)*
- **Poisoning the blocklist.** Getting a legitimate domain, file hash or user marked `confirmed` across the network, or a real threat marked `false_positive`, without going through the scoring, trust and review rules. *(NIST SI-4, SI-7 · OWASP Top 10: Software or Data Integrity Failures)*
- **Report brigading.** Getting around trust scores, rate limits or anomaly detection so reports spread when they shouldn't (M10). *(NIST SI-4 · ASVS V2)*
- **Actions without permission.** Making the bot delete, quarantine, time out, kick or ban in a server, or using the alert buttons (**Restore**, **Mark false positive**, **Confirm**, **Release**) without the right role. *(NIST AC-3, AC-6 · ASVS V8 · OWASP Top 10: Broken Access Control)*
- **Injection.** SQL injection, markdown or mention injection in alerts (like getting an alert to ping `@everyone`), or anything that gets the bot to run or render content an attacker controls. *(NIST SI-10 · ASVS V1, V2 · OWASP Top 10: Injection)*
- **SSRF when following redirects.** Getting the worker to reach private, loopback, link-local or cloud-metadata addresses, including through DNS rebinding or redirect chains. *(NIST SC-7 · OWASP Top 10: Server-Side Request Forgery)*
- **User files getting out.** Any way a user's file gets uploaded to VirusTotal or another third party when the server hasn't opted in. *(NIST PT-2 · ASVS V14)*
- **Dashboard and API.** Authentication or OAuth flaws, session problems, CSRF, XSS, IDOR, or admin and internal endpoints missing authorization. *(NIST IA-2, AC-3 · ASVS V6–V10 · OWASP Top 10: Authentication Failures, Broken Access Control)*
- **Leaked secrets.** Tokens, API keys or session secrets showing up in logs, errors, the dashboard or the API. *(NIST IA-5, AU-9 · ASVS V13, V16 · OWASP Top 10: Security Misconfiguration)*
- **Tampering with the audit log.** Doing something that doesn't get recorded, or changing or deleting audit entries. *(NIST AU-2, AU-9 · ASVS V16 · OWASP Top 10: Logging and Alerting Failures)*
- **Supply chain.** Any way to get malicious code into a build, a CI run or a release. *(NIST SSDF PS.1–PS.3, PW.4 · NIST SR-3 · OWASP Top 10: Software Supply Chain Failures)*
- **Keeping data too long.** Anything kept past the retention periods we document. *(NIST SI-12, AU-11)*

### Out of scope

- Bugs in Discord, VirusTotal, URLhaus or other third-party services. Please report those to the vendor.
- A scam link or file that Equinox missed. Open a normal issue, or report it through the bot once that's available.
- A single false alarm. Use the **Mark false positive** button or open a normal issue.
- Denial of service by sheer volume, or anything that needs a server admin's Discord account to already be compromised.
- Missing best-practice headers, or scanner output with no real impact behind it.
- Social engineering of maintainers or server moderators.

## Testing guidelines

- Only test against your own servers, bots and local setups (`docker compose up`).
- Don't send fake reports, poisoned indicators or brigade traffic to the live network. Reproduce those locally.
- Don't access, change or delete other people's data. If you run into some by accident, stop and let us know.
- Don't upload real malware to public services while testing. Use a test file like EICAR.
- Give us a reasonable amount of time to fix things before you go public.

If you follow this policy in good faith, we won't take legal action against you.

## How it's built to be safe

These are the protections Equinox is designed around, and the controls they cover. If you can get around any of them, that's in scope. Anything marked *planned* comes in a later milestone; [docs/security-controls.md](docs/security-controls.md) has the full status.

| Protection | Standards |
|---|---|
| **Tenant isolation.** Each Discord server is a tenant. Tenant queries run as a restricted database role under row-level security, so data can't cross between servers even if a query forgets its filter. Only indicators (domains, hashes) are shared across the network, never anything a server's members wrote. | NIST AC-4, SC-4 · ASVS V8 · OWASP Top 10: Broken Access Control |
| **Deny by default.** Changing settings needs Manage Server. Alert buttons need Manage Server or the server's mod role. Denied attempts get logged. | NIST AC-3, AC-6, AC-7 · ASVS V8 · OWASP Top 10: Broken Access Control |
| **Least privilege.** The bot only asks for the intents and permissions it uses. The container runs as a non-root user on a read-only filesystem, with all capabilities dropped. | NIST AC-6, CM-7 · OWASP Top 10: Security Misconfiguration |
| **Input validation.** Every signal, command option and button ID is checked with zod or strict parsing. Database queries are always parameterized. | NIST SI-10 · ASVS V1, V2 · OWASP Top 10: Injection |
| **Safe output.** Alerts escape markdown, defang bad links and can't ping anyone. | ASVS V1 · OWASP Top 10: Injection |
| **An audit log you can't rewrite.** Every detection, action, review and settings change is recorded with who did it and to whom. The database rejects updates, deletes and truncates on the audit log. | NIST AU-2, AU-3, AU-9, AU-12 · ASVS V16 |
| **Safe errors.** When something breaks, users get a reference ID, never a stack trace. One failed action doesn't stop the rest. | NIST SI-11 · ASVS V16 · OWASP Top 10: Mishandling of Exceptional Conditions |
| **Secrets** only live in environment variables. They're checked at startup without ever being printed, and blanked out of logs. | NIST IA-5, CM-6 · ASVS V13 |
| **Rate limits** on commands and buttons, and a cap on how much work one message can cause. | NIST SC-5 · ASVS V2 |
| **Following redirects** (*planned*, M4) will block private, loopback, link-local and cloud-metadata addresses, checked again after DNS resolution and on every redirect. It follows at most 5 hops with a 5-second timeout and a 1 MB cap, doesn't run JavaScript and doesn't send cookies. | NIST SC-7 · OWASP Top 10: Server-Side Request Forgery |
| **Downloaded content** is never run or opened. Attachments will be hashed as they stream in and never written to disk (*planned*, M6). | NIST SI-3 |
| **VirusTotal** is only used for lookups. Uploading files is a per-server opt-in, off by default. The free tier is non-commercial, so we'll move to a licensed source before any paid use. | NIST PT-2, SA-9 · ASVS V14 |
| **Keeping little, briefly.** We store IDs, hashes and normalized URLs. Message content is only kept as evidence for confirmed detections. Fingerprints expire after 24 hours, unconfirmed indicators after 30 days and detection records after 90, and a job cleans them up. | NIST PT-2, SI-12, AU-11 · ASVS V14 |
| **Supply chain.** Frozen lockfile, exact versions, install scripts blocked by default, nothing newer than 3 days, `pnpm audit` in CI, Dependabot updates, Actions pinned to commit SHAs, and a read-only CI token. | NIST SSDF PO.5, PS.2, PS.3, PW.4, RV.1 · NIST SR-3, RA-5 · OWASP Top 10: Software Supply Chain Failures |
| **Security testing.** Authorization, tenant isolation, the audit log and input handling all have automated tests, and they run in CI against real Postgres and Redis. CodeQL scans every push and pull request, plus once a week. | NIST SSDF PW.7, PW.8 · NIST SA-11, RA-5 |
| **Undo.** Every automatic action is logged and can be reversed from Discord (and later the dashboard). | NIST AU-2 |
| **Careful defaults.** New servers start in `alert_only`. Kicks and bans are never automatic. Hijacked accounts get quarantined, not banned. | NIST CM-6 |
