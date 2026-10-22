/** A value from outside the CLI made safe to echo on one terminal line:
 *  control characters (ESC, newline, the rest of C0 and C1, and DEL) are
 *  removed, so a crafted value cannot inject an escape sequence or forge a
 *  line of its own. */
export function printable(value: string): string {
  return value.replace(/[\x00-\x1f\x7f-\x9f]/g, '');
}
