import { createHash } from 'node:crypto';

/**
 * Source marker appended to task notes. It stores a hash of the source identifier (e.g. an Outlook message ID),
 * never the identifier itself or any email content.
 */
const MARKER_PREFIX = '[gtasks-mcp:src=';
const MARKER_RE = /\[gtasks-mcp:src=([a-f0-9]{24})\]/;

export function sourceHash(sourceId: string): string {
  return createHash('sha256').update(`source:${sourceId.trim()}`, 'utf8').digest('hex').slice(0, 24);
}

export function sourceMarker(hash: string): string {
  return `${MARKER_PREFIX}${hash}]`;
}

export function extractSourceHash(notes: string | undefined): string | null {
  if (!notes) return null;
  return MARKER_RE.exec(notes)?.[1] ?? null;
}

export function appendMarker(notes: string | undefined, hash: string): string {
  const marker = sourceMarker(hash);
  if (notes?.includes(marker)) return notes;
  return notes && notes.length > 0 ? `${notes}\n\n${marker}` : marker;
}

export function stripMarker(notes: string | undefined): string | undefined {
  if (notes === undefined) return undefined;
  return notes.replace(MARKER_RE, '').trimEnd();
}

/** Lowercase, remove diacritics and punctuation, collapse whitespace. "Všeobecná psychológia – zápis" -> "vseobecna psychologia zapis". */
export function normalizeTitle(title: string): string {
  return title
    .normalize('NFD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim();
}

/** Sørensen–Dice coefficient over character bigrams of normalized titles (0..1). */
export function titleSimilarity(a: string, b: string): number {
  const na = normalizeTitle(a);
  const nb = normalizeTitle(b);
  if (na === nb) return 1;
  if (na.length < 2 || nb.length < 2) return 0;
  const bigrams = (s: string) => {
    const m = new Map<string, number>();
    for (let i = 0; i < s.length - 1; i++) {
      const g = s.slice(i, i + 2);
      m.set(g, (m.get(g) ?? 0) + 1);
    }
    return m;
  };
  const ba = bigrams(na);
  const bb = bigrams(nb);
  let overlap = 0;
  for (const [g, n] of ba) overlap += Math.min(n, bb.get(g) ?? 0);
  return (2 * overlap) / (na.length - 1 + (nb.length - 1));
}

export type MatchType = 'source_id' | 'exact_title_and_date' | 'exact_title' | 'similar_title';

export const SIMILARITY_THRESHOLD = 0.8;

export interface Candidate {
  id: string;
  title: string;
  dueDate: string | null;
  sourceHash: string | null;
}

export interface DuplicateMatch {
  task_id: string;
  match_type: MatchType;
  similarity: number;
}

const RANK: Record<MatchType, number> = { source_id: 0, exact_title_and_date: 1, exact_title: 2, similar_title: 3 };

/**
 * Deterministic source IDs win over any title comparison. Fuzzy title matching is only a hint and
 * is limited to tasks on the same date (or when no date is given).
 */
export function findDuplicates(query: { title?: string; dueDate?: string | null; sourceHash?: string | null }, candidates: Candidate[]): DuplicateMatch[] {
  const out: DuplicateMatch[] = [];
  const qTitle = query.title ? normalizeTitle(query.title) : null;
  for (const c of candidates) {
    if (query.sourceHash && c.sourceHash === query.sourceHash) {
      out.push({ task_id: c.id, match_type: 'source_id', similarity: 1 });
      continue;
    }
    if (!qTitle || !query.title) continue;
    const sameDate = (query.dueDate ?? null) === c.dueDate;
    if (normalizeTitle(c.title) === qTitle) {
      out.push({ task_id: c.id, match_type: sameDate ? 'exact_title_and_date' : 'exact_title', similarity: 1 });
      continue;
    }
    if (!query.dueDate || sameDate) {
      const sim = titleSimilarity(query.title, c.title);
      if (sim >= SIMILARITY_THRESHOLD) out.push({ task_id: c.id, match_type: 'similar_title', similarity: Math.round(sim * 100) / 100 });
    }
  }
  return out.sort((a, b) => RANK[a.match_type] - RANK[b.match_type] || b.similarity - a.similarity);
}
