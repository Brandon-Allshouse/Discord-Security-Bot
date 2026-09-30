import { extractUrls } from './extract.js';
import { assessUrl, type LinkAssessment } from './heuristics.js';
import { normalizeUrl, type NormalizedUrl } from './normalize.js';

export * from './extract.js';
export * from './heuristics.js';
export * from './normalize.js';

export interface LinkFinding extends LinkAssessment {
  normalized: NormalizedUrl;
}

/** Extract, normalize, dedupe and score every link in a message, highest score first. */
export function findLinks(text: string): LinkFinding[] {
  const seen = new Set<string>();
  const findings: LinkFinding[] = [];
  for (const raw of extractUrls(text)) {
    const normalized = normalizeUrl(raw);
    if (!normalized || seen.has(normalized.url)) continue;
    seen.add(normalized.url);
    findings.push({ normalized, ...assessUrl(normalized, text) });
  }
  return findings.sort((a, b) => b.score - a.score);
}
