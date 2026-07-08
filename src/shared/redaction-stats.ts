/**
 * Module-level redaction counters since worker start.
 * Updated by content-redaction on each redaction; surfaced on GET /api/health.
 */

let totalRedactions = 0;
const byKind: Record<string, number> = {};

export type RedactionStatsSnapshot = {
  totalRedactions: number;
  byKind: Record<string, number>;
};

export function incrementRedactionStats(kind: string, count = 1): void {
  if (count <= 0) return;
  totalRedactions += count;
  byKind[kind] = (byKind[kind] ?? 0) + count;
}

export function getRedactionStats(): RedactionStatsSnapshot {
  return {
    totalRedactions,
    byKind: { ...byKind },
  };
}

export function resetRedactionStats(): void {
  totalRedactions = 0;
  for (const kind of Object.keys(byKind)) {
    delete byKind[kind];
  }
}