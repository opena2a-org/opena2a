/**
 * Format a scan timestamp as a friendly age string: "today", "1 day ago",
 * "12 days ago", "120 days ago (stale)".
 *
 * Returns null when no timestamp is provided, so callers can omit the label.
 */
export function formatScanAge(lastScannedAt?: string): string | null {
  if (!lastScannedAt) return null;
  const scanned = new Date(lastScannedAt);
  const now = new Date();
  const days = Math.floor(
    (now.getTime() - scanned.getTime()) / (1000 * 60 * 60 * 24)
  );
  if (days === 0) return "today";
  if (days === 1) return "1 day ago";
  if (days > 90) return `${days} days ago (stale)`;
  return `${days} days ago`;
}
