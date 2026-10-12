const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** True for a real calendar date in YYYY-MM-DD form (rejects e.g. 2026-02-30). */
export function isValidDateOnly(value: string): boolean {
  const m = DATE_RE.exec(value);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (y < 2000 || y > 2100) return false;
  const dt = new Date(Date.UTC(y, mo - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === mo - 1 && dt.getUTCDate() === d;
}

/**
 * Google Tasks stores only the date of `due`; the time portion is discarded by the API.
 * We therefore always send midnight UTC and never invent a time.
 */
export function toGoogleDue(date: string): string {
  return `${date}T00:00:00.000Z`;
}

/** Extracts the date part of a Google `due` timestamp. The time part carries no meaning. */
export function fromGoogleDue(due: string | undefined): string | null {
  if (!due) return null;
  const d = due.slice(0, 10);
  return DATE_RE.test(d) ? d : null;
}

export function todayIn(timeZone: string, now: number): string {
  // en-CA formats as YYYY-MM-DD.
  return new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(now));
}

export function daysBetween(fromDate: string, toDate: string): number {
  const a = Date.parse(`${fromDate}T00:00:00Z`);
  const b = Date.parse(`${toDate}T00:00:00Z`);
  return Math.round((b - a) / 86_400_000);
}

export type Urgency = 'urgent' | 'normal';

/**
 * Google Tasks has no priority field (verified in the Tasks API v1 discovery document), so urgency is only computed
 * for display. A date-only deadline due today or tomorrow can fall within 24 hours, so it is classified as urgent;
 * overdue open tasks are urgent too. Everything else is normal.
 */
export function classifyUrgency(dueDate: string | null, completed: boolean, today: string): { urgency: Urgency | null; days_until_due: number | null; overdue: boolean } {
  if (!dueDate) return { urgency: null, days_until_due: null, overdue: false };
  const days = daysBetween(today, dueDate);
  if (completed) return { urgency: null, days_until_due: days, overdue: false };
  return { urgency: days <= 1 ? 'urgent' : 'normal', days_until_due: days, overdue: days < 0 };
}
