/**
 * The product name, in one place. Equinox is a working name, so a rebrand should only
 * need an edit here plus the docs. Internal names (package scope, database role,
 * Redis keys, Docker project) use the lowercase form and have to be renamed by hand.
 */
export const BRAND = {
  name: 'Equinox',
  /** Slash command name. Discord requires lowercase with no spaces. */
  command: 'equinox',
  /**
   * A link that's always on the blocklist but isn't a real scam, so it's safe to post
   * in a live server. `.invalid` is reserved (RFC 2606) and never resolves, and
   * Discord's own filters have no reason to flag it.
   */
  testDomain: 'equinox-test.invalid',
} as const;

/** A slash command as users type it, e.g. `/equinox setup`. */
export function slash(subcommand: string): string {
  return `/${BRAND.command} ${subcommand}`;
}
