import { styleText } from 'node:util';
import type { SessionStore } from '../../services/sqlite/SessionStore.js';
import { ChromaSync } from '../../services/sync/ChromaSync.js';
import {
  detectSecretHits,
  detectSecretHitsInFacts,
  redactContent,
  redactFactsJson,
  type ContentRedactionMode,
  type SecretKind,
} from '../../shared/content-redaction.js';

const FIX_REDACTION_MODE: ContentRedactionMode = 'standard';

const SAMPLE_ID_LIMIT = 5;

const OBSERVATION_TEXT_FIELDS = ['title', 'subtitle', 'narrative', 'text'] as const;
const SUMMARY_TEXT_FIELDS = [
  'request',
  'investigated',
  'learned',
  'completed',
  'next_steps',
  'notes',
] as const;

interface ObservationRow {
  id: number;
  project: string;
  title: string | null;
  subtitle: string | null;
  narrative: string | null;
  facts: string | null;
  text: string | null;
}

interface SummaryRow {
  id: number;
  project: string;
  request: string | null;
  investigated: string | null;
  learned: string | null;
  completed: string | null;
  next_steps: string | null;
  notes: string | null;
}

export interface TableSecretScanReport {
  hitCount: number;
  sampleRowIds: number[];
  byField: Partial<Record<string, number>>;
  kinds: SecretKind[];
}

export interface ProjectSecretScanReport {
  project: string;
  observations: TableSecretScanReport;
  sessionSummaries: TableSecretScanReport;
}

export interface SecretScanResult {
  projects: ProjectSecretScanReport[];
  totalHits: number;
}

export interface SecretFixResult {
  observationsUpdated: number;
  summariesUpdated: number;
  chromaObservationsResynced: number;
  chromaSummariesResynced: number;
  chromaErrors: string[];
}

function emptyTableReport(): TableSecretScanReport {
  return {
    hitCount: 0,
    sampleRowIds: [],
    byField: {},
    kinds: [],
  };
}

function recordFieldHit(
  report: TableSecretScanReport,
  rowId: number,
  field: string,
  kinds: SecretKind[]
): void {
  if (kinds.length === 0) {
    return;
  }

  report.hitCount += 1;
  report.byField[field] = (report.byField[field] ?? 0) + 1;

  if (!report.sampleRowIds.includes(rowId) && report.sampleRowIds.length < SAMPLE_ID_LIMIT) {
    report.sampleRowIds.push(rowId);
  }

  for (const kind of kinds) {
    if (!report.kinds.includes(kind)) {
      report.kinds.push(kind);
    }
  }
}

function scanObservationRow(row: ObservationRow, report: TableSecretScanReport): void {
  for (const field of OBSERVATION_TEXT_FIELDS) {
    recordFieldHit(report, row.id, field, detectSecretHits(row[field]));
  }
  recordFieldHit(report, row.id, 'facts', detectSecretHitsInFacts(row.facts));
}

function scanSummaryRow(row: SummaryRow, report: TableSecretScanReport): void {
  for (const field of SUMMARY_TEXT_FIELDS) {
    recordFieldHit(report, row.id, field, detectSecretHits(row[field]));
  }
}

function ensureProjectReport(
  byProject: Map<string, ProjectSecretScanReport>,
  project: string
): ProjectSecretScanReport {
  let report = byProject.get(project);
  if (!report) {
    report = {
      project,
      observations: emptyTableReport(),
      sessionSummaries: emptyTableReport(),
    };
    byProject.set(project, report);
  }
  return report;
}

/**
 * Scan all observations and session_summaries for secret-shaped content.
 */
export function scanSecretsInDatabase(db: SessionStore): SecretScanResult {
  const byProject = new Map<string, ProjectSecretScanReport>();

  const observations = db.db
    .prepare(
      `SELECT id, project, title, subtitle, narrative, facts, text
       FROM observations
       WHERE project IS NOT NULL AND project != ''`
    )
    .all() as ObservationRow[];

  for (const row of observations) {
    const report = ensureProjectReport(byProject, row.project);
    scanObservationRow(row, report.observations);
  }

  const summaries = db.db
    .prepare(
      `SELECT id, project, request, investigated, learned, completed, next_steps, notes
       FROM session_summaries
       WHERE project IS NOT NULL AND project != ''`
    )
    .all() as SummaryRow[];

  for (const row of summaries) {
    const report = ensureProjectReport(byProject, row.project);
    scanSummaryRow(row, report.sessionSummaries);
  }

  const projects = [...byProject.values()].sort((a, b) => a.project.localeCompare(b.project));
  const totalHits = projects.reduce(
    (sum, project) => sum + project.observations.hitCount + project.sessionSummaries.hitCount,
    0
  );

  return { projects, totalHits };
}

function observationNeedsFix(row: ObservationRow): boolean {
  for (const field of OBSERVATION_TEXT_FIELDS) {
    if (detectSecretHits(row[field]).length > 0) {
      return true;
    }
  }
  return detectSecretHitsInFacts(row.facts).length > 0;
}

function summaryNeedsFix(row: SummaryRow): boolean {
  for (const field of SUMMARY_TEXT_FIELDS) {
    if (detectSecretHits(row[field]).length > 0) {
      return true;
    }
  }
  return false;
}

function redactNullableField(value: string | null): string | null {
  if (value === null) {
    return null;
  }
  return redactContent(value, { mode: FIX_REDACTION_MODE });
}

function redactObservationRow(row: ObservationRow): ObservationRow {
  return {
    ...row,
    title: redactNullableField(row.title),
    subtitle: redactNullableField(row.subtitle),
    narrative: redactNullableField(row.narrative),
    text: redactNullableField(row.text),
    facts: redactFactsJson(row.facts, { mode: FIX_REDACTION_MODE }),
  };
}

function redactSummaryRow(row: SummaryRow): SummaryRow {
  return {
    ...row,
    request: redactNullableField(row.request),
    investigated: redactNullableField(row.investigated),
    learned: redactNullableField(row.learned),
    completed: redactNullableField(row.completed),
    next_steps: redactNullableField(row.next_steps),
    notes: redactNullableField(row.notes),
  };
}

/**
 * Rewrite rows that contain secrets and re-index affected documents in Chroma.
 */
export async function fixSecretsInDatabase(db: SessionStore): Promise<SecretFixResult> {
  const chromaSync = new ChromaSync('claude-mem');
  const result: SecretFixResult = {
    observationsUpdated: 0,
    summariesUpdated: 0,
    chromaObservationsResynced: 0,
    chromaSummariesResynced: 0,
    chromaErrors: [],
  };

  const updateObservation = db.db.prepare(`
    UPDATE observations
    SET title = ?, subtitle = ?, narrative = ?, facts = ?, text = ?
    WHERE id = ?
  `);

  const observations = db.db
    .prepare(
      `SELECT id, project, title, subtitle, narrative, facts, text
       FROM observations
       WHERE project IS NOT NULL AND project != ''`
    )
    .all() as ObservationRow[];

  for (const row of observations) {
    if (!observationNeedsFix(row)) {
      continue;
    }

    const redacted = redactObservationRow(row);
    updateObservation.run(
      redacted.title,
      redacted.subtitle,
      redacted.narrative,
      redacted.facts,
      redacted.text,
      row.id
    );
    result.observationsUpdated += 1;

    try {
      const written = await chromaSync.resyncObservationById(db, row.id);
      if (written > 0) {
        result.chromaObservationsResynced += 1;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      result.chromaErrors.push(`observation ${row.id}: ${message}`);
    }
  }

  const updateSummary = db.db.prepare(`
    UPDATE session_summaries
    SET request = ?, investigated = ?, learned = ?, completed = ?, next_steps = ?, notes = ?
    WHERE id = ?
  `);

  const summaries = db.db
    .prepare(
      `SELECT id, project, request, investigated, learned, completed, next_steps, notes
       FROM session_summaries
       WHERE project IS NOT NULL AND project != ''`
    )
    .all() as SummaryRow[];

  for (const row of summaries) {
    if (!summaryNeedsFix(row)) {
      continue;
    }

    const redacted = redactSummaryRow(row);
    updateSummary.run(
      redacted.request,
      redacted.investigated,
      redacted.learned,
      redacted.completed,
      redacted.next_steps,
      redacted.notes,
      row.id
    );
    result.summariesUpdated += 1;

    try {
      const written = await chromaSync.resyncSummaryById(db, row.id);
      if (written > 0) {
        result.chromaSummariesResynced += 1;
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      result.chromaErrors.push(`summary ${row.id}: ${message}`);
    }
  }

  return result;
}

function formatKinds(kinds: SecretKind[]): string {
  return kinds.length > 0 ? kinds.join(', ') : '(none)';
}

function printTableSection(label: string, report: TableSecretScanReport): void {
  if (report.hitCount === 0) {
    console.log(`    ${label}: no hits`);
    return;
  }

  const fieldSummary = Object.entries(report.byField)
    .map(([field, count]) => `${field}=${count}`)
    .join(', ');
  const sampleIds =
    report.sampleRowIds.length > 0 ? report.sampleRowIds.join(', ') : '(none)';

  console.log(`    ${label}: ${report.hitCount} row(s) with secrets`);
  console.log(`      fields: ${fieldSummary}`);
  console.log(`      kinds: ${formatKinds(report.kinds)}`);
  console.log(`      sample ids: ${sampleIds}`);
}

export function printSecretScanReport(scan: SecretScanResult, dbPath: string): void {
  console.log(styleText('bold', '\nclaude-mem doctor --scan-secrets\n'));
  console.log(`  database: ${styleText('dim', dbPath)}`);
  console.log('');

  if (scan.projects.length === 0) {
    console.log(styleText('green', '  No projects with stored memory found.'));
    return;
  }

  for (const project of scan.projects) {
    const projectHits = project.observations.hitCount + project.sessionSummaries.hitCount;
    if (projectHits === 0) {
      continue;
    }

    console.log(`  ${styleText('bold', project.project)} (${projectHits} hit row(s))`);
    printTableSection('observations', project.observations);
    printTableSection('session_summaries', project.sessionSummaries);
    console.log('');
  }

  if (scan.totalHits === 0) {
    console.log(styleText('green', '  No secret-shaped content detected.'));
  } else {
    console.log(
      styleText('yellow', `  ${scan.totalHits} row(s) contain secret-shaped content.`)
    );
    console.log(styleText('dim', '  Run with --fix to redact stored rows and re-sync Chroma.'));
  }
}

export function printSecretFixReport(fix: SecretFixResult): void {
  console.log(styleText('bold', '\nSecret redaction (--fix)\n'));
  console.log(`  observations updated: ${fix.observationsUpdated}`);
  console.log(`  session_summaries updated: ${fix.summariesUpdated}`);
  console.log(`  chroma observations re-synced: ${fix.chromaObservationsResynced}`);
  console.log(`  chroma summaries re-synced: ${fix.chromaSummariesResynced}`);

  if (fix.chromaErrors.length > 0) {
    console.log(styleText('yellow', `  chroma warnings: ${fix.chromaErrors.length}`));
    for (const warning of fix.chromaErrors.slice(0, 5)) {
      console.log(styleText('dim', `    ${warning}`));
    }
    if (fix.chromaErrors.length > 5) {
      console.log(styleText('dim', `    ... and ${fix.chromaErrors.length - 5} more`));
    }
  }
}