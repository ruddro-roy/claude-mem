import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

import { SessionStore } from '../../src/services/sqlite/SessionStore.js';
import {
  fixSecretsInDatabase,
  scanSecretsInDatabase,
} from '../../src/npx-cli/commands/scan-secrets.js';
import {
  detectSecretHits,
  detectSecretHitsInFacts,
  redactContent,
  redactFactsJson,
  redactionToken,
} from '../../src/shared/content-redaction.js';

const SECRET_KEY = 'sk-test12345678901234567890123456789012';
const PROJECT = 'scan-secrets-project';

describe('content-redaction detect helpers', () => {
  it('detectSecretHits finds api_key patterns', () => {
    const kinds = detectSecretHits(`token ${SECRET_KEY} here`);
    expect(kinds).toContain('api_key');
  });

  it('redactContent replaces secrets with typed tokens', () => {
    expect(redactContent(null, { mode: 'standard' })).toBe('');
    expect(redactContent(`saved ${SECRET_KEY}`, { mode: 'standard' })).toBe(
      `saved ${redactionToken('api_key')}`
    );
  });

  it('detectSecretHitsInFacts scans parsed fact entries', () => {
    const facts = JSON.stringify(['plain fact', `leaked ${SECRET_KEY}`]);
    const kinds = detectSecretHitsInFacts(facts);
    expect(kinds).toContain('api_key');
  });

  it('redactFactsJson redacts each fact string', () => {
    const facts = JSON.stringify(['plain fact', `leaked ${SECRET_KEY}`]);
    const redacted = redactFactsJson(facts, { mode: 'standard' });
    expect(redacted).not.toContain(SECRET_KEY);
    expect(redacted).toContain(redactionToken('api_key'));
    expect(JSON.parse(redacted!)).toEqual([
      'plain fact',
      `leaked ${redactionToken('api_key')}`,
    ]);
  });
});

describe('doctor scan-secrets', () => {
  let tempDir: string;
  let store: SessionStore;
  let memorySessionId: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'claude-mem-scan-secrets-'));
    const dbPath = join(tempDir, 'claude-mem.db');
    store = new SessionStore(dbPath);

    const sessionDbId = store.createSDKSession('scan-secrets-session', PROJECT, 'initial prompt');
    memorySessionId = 'mem-session-1';
    store.ensureMemorySessionIdRegistered(sessionDbId, memorySessionId, 37700);
  });

  afterEach(() => {
    store.close();
    rmSync(tempDir, { recursive: true, force: true });
  });

  function insertObservation(title: string, narrative: string | null = null): number {
    const result = store.storeObservations(
      memorySessionId,
      PROJECT,
      [
        {
          type: 'discovery',
          title,
          subtitle: null,
          facts: [],
          narrative,
          concepts: [],
          files_read: [],
          files_modified: [],
        },
      ],
      null,
      1
    );
    return result.observationIds[0]!;
  }

  function insertSummary(investigated: string): number {
    return store.storeSummary(memorySessionId, PROJECT, {
      request: 'clean request',
      investigated,
      learned: 'nothing sensitive',
      completed: 'done',
      next_steps: 'next',
      notes: null,
    }).id;
  }

  it('scanSecretsInDatabase reports rows with unredacted secrets', () => {
    insertObservation(`Found API key ${SECRET_KEY}`);

    const scan = scanSecretsInDatabase(store);

    expect(scan.totalHits).toBe(1);
    expect(scan.projects).toHaveLength(1);
    expect(scan.projects[0]!.project).toBe(PROJECT);
    expect(scan.projects[0]!.observations.hitCount).toBe(1);
    expect(scan.projects[0]!.observations.kinds).toContain('api_key');
    expect(scan.projects[0]!.observations.byField.title).toBe(1);
    expect(scan.projects[0]!.observations.sampleRowIds).toHaveLength(1);
  });

  it('scanSecretsInDatabase reports session summary hits per project', () => {
    insertSummary('contact ops@example.com');

    const scan = scanSecretsInDatabase(store);

    expect(scan.totalHits).toBe(1);
    expect(scan.projects[0]!.sessionSummaries.hitCount).toBe(1);
    expect(scan.projects[0]!.sessionSummaries.kinds).toContain('email');
    expect(scan.projects[0]!.sessionSummaries.byField.investigated).toBe(1);
  });

  it('scanSecretsInDatabase ignores already-redacted rows', () => {
    insertObservation(`Found API key ${redactionToken('api_key')}`);

    const scan = scanSecretsInDatabase(store);

    expect(scan.totalHits).toBe(0);
  });

  it('fixSecretsInDatabase rewrites secret-shaped content', async () => {
    const obsId = insertObservation(`Leaked ${SECRET_KEY} in title`);

    const fix = await fixSecretsInDatabase(store);

    expect(fix.observationsUpdated).toBe(1);

    const row = store.db
      .prepare('SELECT title FROM observations WHERE id = ?')
      .get(obsId) as { title: string };

    expect(row.title).not.toContain(SECRET_KEY);
    expect(row.title).toContain(redactionToken('api_key'));

    const scan = scanSecretsInDatabase(store);
    expect(scan.totalHits).toBe(0);
  });
});