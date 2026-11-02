/**
 * The consumer-resolution audit's waivers, read a week before their dates.
 *
 * Every waiver in `scripts/audit-consumer-resolution.mjs` (an `ALLOWED` entry,
 * or the `waiver` on a `FORBIDDEN_PACKAGES` entry) carries a `reviewBy` date,
 * and the audit fails from the first day after it. That check fires on the day
 * itself and gives no notice: when the nested `hackmyagent` waiver lapsed, the
 * audit's own test in this directory failed, and with it every push of this
 * repository, on the morning after the date.
 *
 * This test reads the same lists and fails once a date is REVIEW_NOTICE_DAYS
 * or fewer days away, so the re-check comes due here a week before the audit
 * would stop anything. The remedy is the audit's own: re-check whether the
 * edge or advisory still exists, then fix it, or move the date with a fresh
 * reason.
 *
 * Importing the module runs nothing; the audit runs only when it is the
 * program node was started with.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ALLOWED, FORBIDDEN_PACKAGES } from '../audit-consumer-resolution.mjs';

const REVIEW_NOTICE_DAYS = 7;
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Whole days from `today` to `reviewBy`, both UTC calendar dates, or null when
 * `reviewBy` is not one. The audit treats a malformed date as expired, so a
 * null here is due as well.
 */
function daysUntil(reviewBy, today) {
  if (typeof reviewBy !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(reviewBy)) return null;
  const at = Date.parse(`${reviewBy}T00:00:00Z`);
  // A date that does not round-trip (2026-02-30) is not a calendar date.
  if (Number.isNaN(at) || new Date(at).toISOString().slice(0, 10) !== reviewBy) return null;
  return Math.round((at - Date.parse(`${today}T00:00:00Z`)) / DAY_MS);
}

test('fails a week before any consumer-audit waiver reaches its review date', () => {
  // The arithmetic first, on fixed dates, so a green run means every date is
  // far enough off rather than that the subtraction broke.
  assert.equal(daysUntil('2026-11-09', '2026-11-02'), 7);
  assert.equal(daysUntil('2026-11-10', '2026-11-02'), 8);
  assert.equal(daysUntil('2026-11-01', '2026-11-02'), -1);
  assert.equal(daysUntil('2027-01-01', '2026-12-31'), 1);
  assert.equal(daysUntil('2026-02-30', '2026-11-02'), null);
  assert.equal(daysUntil(undefined, '2026-11-02'), null);

  // The same clock the audit reads: a UTC calendar date.
  const today = new Date().toISOString().slice(0, 10);
  const waivers = [
    ...ALLOWED.map((a) => ({ label: `ALLOWED ${a.id} (${a.package})`, reviewBy: a.reviewBy })),
    ...FORBIDDEN_PACKAGES.filter((f) => f.waiver).map((f) => ({
      label: `FORBIDDEN_PACKAGES nested ${f.name}`,
      reviewBy: f.waiver.reviewBy,
    })),
  ];
  const due = waivers
    .map((w) => ({ ...w, days: daysUntil(w.reviewBy, today) }))
    .filter((w) => w.days === null || w.days <= REVIEW_NOTICE_DAYS)
    .map((w) =>
      w.days === null
        ? `${w.label}: reviewBy ${JSON.stringify(w.reviewBy)} is not a YYYY-MM-DD date`
        : `${w.label}: review by ${w.reviewBy}, ${w.days} day(s) from ${today}`
    );

  assert.deepEqual(
    due,
    [],
    `${due.length} consumer-audit waiver(s) are within ${REVIEW_NOTICE_DAYS} days of their ` +
      'review date, or past it:\n' +
      due.map((d) => `  - ${d}`).join('\n') +
      '\nRun `npm run audit:consumer` and re-check whether the edge or advisory still exists, ' +
      'then fix it or move the date with a fresh reason in scripts/audit-consumer-resolution.mjs.'
  );
});
