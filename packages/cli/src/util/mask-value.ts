/**
 * Mask a detected value so the CLI never prints a meaningful slice of a
 * secret. Values of 8 chars or fewer are masked entirely -- a fixed-length
 * head would otherwise reveal most of a short password / token / SSN segment.
 * Longer values reveal a 3-char head and 2-char tail only (at most 5 chars,
 * a small fraction), enough to recognize a finding without disclosing it.
 */
export function maskValue(value: string): string {
  const v = value ?? '';
  const n = v.length;
  if (n === 0) return '•';
  if (n <= 8) return '•'.repeat(n);
  const head = v.slice(0, 3);
  const tail = v.slice(-2);
  return `${head}${'•'.repeat(n - 5)}${tail}`;
}
