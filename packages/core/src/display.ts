/**
 * Makes a URL or domain non-clickable before showing it to moderators, so an
 * alert never becomes a way to spread the link it's warning about.
 */
export function defang(value: string): string {
  return value.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}

/** Truncates to a Discord field limit without splitting surrogate pairs. */
export function truncate(value: string, max: number): string {
  const chars = Array.from(value);
  return chars.length <= max ? value : `${chars.slice(0, max - 1).join('')}…`;
}
