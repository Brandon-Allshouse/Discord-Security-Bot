import type { VerdictLevel } from '../types.js';

export const INTEL_KINDS = ['url', 'domain', 'file_hash'] as const;
export type IntelKind = (typeof INTEL_KINDS)[number];

/** What one intel source says about one subject. `unknown` means it had nothing to say. */
export interface ProviderResult {
  provider: string;
  kind: IntelKind;
  subject: string;
  level: VerdictLevel | 'unknown';
  /** 0..1, how much this result should raise the score. 0 for clean or unknown. */
  weight: number;
  /** Human-readable, shown to mods. */
  reasons: string[];
  /** Small, provider-specific facts worth keeping (engine counts, registration date). Never message content. */
  details: Record<string, unknown>;
}

/**
 * Every threat-intel source implements this, so sources can be swapped, reordered or
 * upgraded (e.g. VirusTotal public to premium) by config alone.
 */
export interface IntelProvider {
  name: string;
  supports: readonly IntelKind[];
  /** Null when the provider can't answer right now (disabled, over budget). Throws on outages. */
  lookup(subject: string, kind: IntelKind): Promise<ProviderResult | null>;
  quota?: { perMinute: number; perDay: number };
}

/** All intel about one URL, combined. This is what the bot reads when judging a link. */
export interface IntelSummary {
  level: VerdictLevel;
  /** 0..1 */
  score: number;
  /** e.g. 'urlhaus', 'virustotal', 'rdap' */
  sources: string[];
  reasons: string[];
}
