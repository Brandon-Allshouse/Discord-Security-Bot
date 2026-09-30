/**
 * Turns any thrown value into a short message that's safe to show users and keep in
 * the audit log. Stack traces and internal details stay out.
 */
export function safeErrorMessage(error: unknown): string {
  if (error instanceof Error && 'code' in error && typeof error.code === 'number') {
    return `Discord API error ${error.code}`;
  }
  return 'Action failed';
}
