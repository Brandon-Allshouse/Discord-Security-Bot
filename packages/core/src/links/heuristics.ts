import { combineWeights } from '../verdict.js';
import { domainCandidates, type NormalizedUrl } from './normalize.js';

interface Brand {
  name: string;
  /** Keywords scammers imitate. Matched against the domain label after homoglyph folding. */
  keywords: string[];
  /** Real domains. The brand's own subdomains are covered too. */
  official: string[];
}

export const BRANDS: Brand[] = [
  {
    name: 'Discord',
    keywords: ['discord', 'discordapp', 'discordnitro', 'discordgift'],
    official: [
      'discord.com',
      'discord.gg',
      'discordapp.com',
      'discordapp.net',
      'discord.media',
      'discord.new',
      'discord.gift',
      'discord.dev',
      'discordstatus.com',
      'dis.gd',
    ],
  },
  {
    name: 'Steam',
    keywords: ['steam', 'steamcommunity', 'steampowered'],
    official: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com', 'steamgames.com', 'steamdeck.com', 'steam.tv'],
  },
  { name: 'Epic Games', keywords: ['epicgames'], official: ['epicgames.com', 'unrealengine.com', 'fortnite.com'] },
  { name: 'Roblox', keywords: ['roblox'], official: ['roblox.com', 'rbxcdn.com', 'roblox.qq.com'] },
  { name: 'MetaMask', keywords: ['metamask'], official: ['metamask.io'] },
  { name: 'Phantom', keywords: ['phantom'], official: ['phantom.app', 'phantom.com'] },
  { name: 'Trust Wallet', keywords: ['trustwallet'], official: ['trustwallet.com'] },
  { name: 'Coinbase', keywords: ['coinbase'], official: ['coinbase.com'] },
  { name: 'OpenSea', keywords: ['opensea'], official: ['opensea.io'] },
];

/**
 * Popular, legitimate domains that happen to contain brand keywords or look risky.
 * Keeps false positives down. Each server can add its own entries with the allow command.
 */
export const SAFE_DOMAINS = new Set([
  'discordjs.guide',
  'discord.js.org',
  'discordpy.readthedocs.io',
  'discordbotlist.com',
  'discordservers.com',
  'discords.com',
  'discordlookup.com',
  'discohook.org',
  'top.gg',
  'disboard.org',
  'steamdb.info',
  'steamcharts.com',
  'steamspy.com',
  'steamgriddb.com',
  'protondb.com',
  'robloxden.com',
  'github.com',
  'githubusercontent.com',
  'gitlab.com',
  'youtube.com',
  'youtu.be',
  'google.com',
  'wikipedia.org',
  'reddit.com',
  'twitter.com',
  'x.com',
  'twitch.tv',
  'tenor.com',
  'giphy.com',
  'imgur.com',
  'spotify.com',
  'npmjs.com',
  'stackoverflow.com',
  'microsoft.com',
  'apple.com',
  'amazon.com',
]);

/** TLDs with a disproportionate share of abuse. Weak signal on its own. */
const RISKY_TLDS = new Set([
  'gift', 'xyz', 'top', 'click', 'link', 'tk', 'ml', 'ga', 'cf', 'gq', 'ru', 'su', 'cn', 'icu', 'rest', 'monster',
  'buzz', 'cyou', 'cfd', 'sbs', 'lat', 'bond', 'fun', 'site', 'online', 'store', 'shop', 'live', 'pw', 'cc', 'ws',
  'info', 'biz', 'io.vn', 'com.ru',
]);

const SCAM_PHRASES: { pattern: RegExp; reason: string }[] = [
  { pattern: /\bfree\s+(?:discord\s+)?nitro\b/i, reason: 'Mentions free Nitro' },
  { pattern: /\bnitro\s+(?:for\s+free|giveaway|gift|drop)\b/i, reason: 'Nitro giveaway language' },
  { pattern: /\b(?:\d+|three|one)\s+months?\s+(?:of\s+)?(?:discord\s+)?nitro\b/i, reason: 'Nitro offer language' },
  { pattern: /\bsteam\s+(?:gift|giveaway|wallet|free)\b/i, reason: 'Steam gift language' },
  { pattern: /\b(?:free|claim)\s+(?:skins?|robux|v-?bucks|gift\s*cards?)\b/i, reason: 'Free in-game currency language' },
  { pattern: /\b(?:airdrop|mint\s+(?:is\s+)?live|free\s+mint|claim\s+your\s+(?:tokens?|nft|reward))\b/i, reason: 'Crypto airdrop language' },
  { pattern: /\baccidentally\s+reported\s+(?:you|your)\b/i, reason: '"Accidentally reported you" scam' },
  { pattern: /\b(?:verify|confirm)\s+your\s+(?:account|wallet|identity)\b/i, reason: 'Account verification bait' },
  { pattern: /\b(?:first|1st)\s+\d+\s+(?:people|users)\b/i, reason: 'Artificial urgency' },
  { pattern: /\btry\s+my\s+(?:new\s+)?game\b/i, reason: '"Try my game" scam' },
  { pattern: /@everyone|@here/i, reason: 'Mass mention with a link' },
];

// Characters scammers substitute for Latin letters (digits, lookalike letters, Cyrillic, Greek).
// i, l and 1 all fold to "i" because they're interchangeable at a glance ("dlscord").
const HOMOGLYPHS: Record<string, string> = {
  '0': 'o', '1': 'i', l: 'i', '|': 'i', '!': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g',
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ј: 'j', ѕ: 's', ԁ: 'd', ɡ: 'g', ո: 'n', ս: 'u',
  α: 'a', ο: 'o', ρ: 'p', ν: 'v', ι: 'i', κ: 'k', τ: 't', ε: 'e',
  ı: 'i', ł: 'i', ɩ: 'i',
};

/**
 * Folds text to a visual skeleton so "d1sc0rd", "dlscord" and "dіscord" (Cyrillic і)
 * all compare equal to "discord". Apply to both sides of a comparison.
 */
export function foldHomoglyphs(label: string): string {
  const mapped = Array.from(label.toLowerCase().normalize('NFKD').replace(/\p{M}/gu, ''))
    .map((char) => HOMOGLYPHS[char] ?? char)
    .join('');
  return mapped.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/ci/g, 'd').replace(/[^a-z]/g, '');
}

/** Brand keywords never change, so each is folded once instead of on every link. */
const SKELETONS = new Map<string, string>();
function skeletonOf(keyword: string): string {
  let skeleton = SKELETONS.get(keyword);
  if (skeleton === undefined) {
    skeleton = foldHomoglyphs(keyword);
    SKELETONS.set(keyword, skeleton);
  }
  return skeleton;
}

/** Smallest edit distance between `keyword` and any similar-length window of `text`. */
function minWindowDistance(text: string, keyword: string, max: number): number {
  let best = max + 1;
  for (let len = keyword.length - 1; len <= keyword.length + 1; len++) {
    for (let start = 0; start + len <= text.length; start++) {
      best = Math.min(best, editDistance(text.slice(start, start + len), keyword, max));
      if (best === 0) return 0;
    }
  }
  return best;
}

// Words that turn "a domain mentioning a brand" into "a domain baiting users of that brand".
const BAIT_WORDS =
  /gift|nitro|free|claim|promo|drop|verify|login|auth|bonus|reward|event|giveaway|support|trade|restore|recover|connect|secure|sync|validate|mint/;

/**
 * Damerau-Levenshtein (optimal string alignment) distance, capped for speed: the exact distance
 * when it's at most `max`, otherwise `max + 1`. Runs on every lookalike check, so it keeps only
 * the three rows it needs and stops as soon as the answer can't come back under `max`.
 */
export function editDistance(a: string, b: string, max = 3): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const cols = b.length + 1;
  let older = new Array<number>(cols).fill(0); // row i - 2, for transpositions
  let previous = Array.from({ length: cols }, (_, j) => j); // row i - 1
  let current = new Array<number>(cols).fill(0);
  let previousMin = 0;
  for (let i = 1; i <= a.length; i++) {
    current[0] = i;
    let rowMin = i;
    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let value = Math.min(previous[j]! + 1, current[j - 1]! + 1, previous[j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) value = Math.min(value, older[j - 2]! + 1);
      current[j] = value;
      if (value < rowMin) rowMin = value;
    }
    // Every later cell builds on one of the last two rows, so once both are over `max`, so is the answer.
    if (rowMin > max && previousMin > max) return max + 1;
    previousMin = rowMin;
    [older, previous, current] = [previous, current, older];
  }
  return Math.min(previous[b.length]!, max + 1);
}

/** The brand's own domains and popular sites. Never scored, and never sent to outside intel sources. */
export function isKnownSafe(url: Pick<NormalizedUrl, 'host' | 'domain'>): boolean {
  const candidates = domainCandidates(url);
  if (candidates.some((c) => SAFE_DOMAINS.has(c))) return true;
  return BRANDS.some((brand) => brand.official.some((official) => candidates.includes(official)));
}

export interface LinkAssessment {
  score: number;
  reasons: string[];
}

/**
 * Scores one normalized URL (0..1) using only local information.
 * Tuned so a single weak signal stays below "suspicious" (0.5):
 * false positives are worse than misses.
 */
export function assessUrl(url: NormalizedUrl, messageText = ''): LinkAssessment {
  if (isKnownSafe(url)) return { score: 0, reasons: [] };

  const weights: number[] = [];
  const reasons: string[] = [];
  const add = (weight: number, reason: string) => {
    weights.push(weight);
    reasons.push(reason);
  };

  if (url.hadCredentials) add(0.5, 'Link hides its real destination with an "@" trick');
  if (url.isIp) add(0.35, 'Link points to a raw IP address');
  if (url.host !== url.unicodeHost) add(0.35, 'Domain uses non-Latin lookalike characters (punycode)');

  // Brand impersonation, checked on every label of the host (e.g. "discord.gift-claim.ru").
  const labels = url.unicodeHost.split('.').filter((l) => l.length >= 4);
  const rank = { homoglyph: 3, typo: 2, name: 1 } as const;
  const best: { kind: keyof typeof rank | null; brand: string } = { kind: null, brand: '' };
  const record = (brand: string, kind: keyof typeof rank) => {
    if (!best.kind || rank[kind] > rank[best.kind]) Object.assign(best, { kind, brand });
  };
  for (const label of labels) {
    const raw = label.toLowerCase().replace(/[^a-z]/g, '');
    const folded = foldHomoglyphs(label);
    for (const brand of BRANDS) {
      const named = brand.keywords.filter((keyword) => raw.includes(keyword));
      if (named.length > 0) {
        // One character off the whole brand name ("discordd") is a typosquat, not a fan site.
        const typosquat = named.some((k) => k.length >= 7 && raw !== k && editDistance(raw, k, 1) <= 1);
        record(brand.name, typosquat ? 'typo' : 'name');
      }
      for (const keyword of brand.keywords) {
        if (named.includes(keyword)) continue;
        const skeleton = skeletonOf(keyword);
        // Spelled differently but looks the same: "dlscord", "d1sc0rd", Cyrillic letters.
        if (folded.includes(skeleton)) {
          record(brand.name, 'homoglyph');
          continue;
        }
        // Typos ("dicsord", "steamcomnunity"). Only for long names: short ones hit real words.
        // Skip when the label already has a keyword and differs only in a short suffix
        // ("discordtips" is not a typo of "discordapp").
        const shortSuffixOfNamed = named.some((k) => keyword.startsWith(k) && keyword.length - k.length < 5);
        if (
          keyword.length >= 7 &&
          !shortSuffixOfNamed &&
          minWindowDistance(folded, skeleton, 2) <= (keyword.length >= 10 ? 2 : 1)
        )
          record(brand.name, 'typo');
      }
    }
  }
  const { kind, brand } = best;
  if (kind === 'homoglyph') add(0.85, `Lookalike of a ${brand} domain`);
  else if (kind === 'typo') add(0.7, `Misspelling of a ${brand} domain`);
  else if (kind === 'name') add(0.45, `Uses the ${brand} name on a domain ${brand} doesn't own`);
  if (kind && BAIT_WORDS.test(url.host)) add(0.35, 'Domain combines a brand with giveaway or login bait');

  const suffix = url.publicSuffix ?? '';
  if (RISKY_TLDS.has(suffix)) add(0.2, `Domain ends in .${suffix}, common in scams`);

  const phrases = SCAM_PHRASES.filter(({ pattern }) => pattern.test(messageText));
  if (phrases.length > 0) add(Math.min(0.25 + 0.1 * (phrases.length - 1), 0.45), phrases.map((p) => p.reason).join('; '));

  return { score: Number(combineWeights(weights).toFixed(3)), reasons };
}
