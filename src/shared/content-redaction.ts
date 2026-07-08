/**
 * Secret redaction for the capture pipeline and shared telemetry helpers.
 *
 * Unlike error-scrub.ts (which also strips home dirs, absolute paths, and URL
 * query strings), this module redacts SECRETS ONLY and emits typed replacement
 * tokens such as `[REDACTED:email]` so downstream systems can distinguish
 * kinds. Telemetry callers collapse typed tokens back to plain `[REDACTED]`.
 *
 * HARD RULES:
 *   - PURE and NEVER THROWS on all public entry points.
 *   - capRawInput() runs BEFORE any regex (ReDoS / CPU-DoS bound).
 *   - Git commit SHAs (7–40 lowercase hex) in git context are allowlisted.
 *   - High-entropy bare-token heuristic runs ONLY in `strict` mode.
 */

import type { SettingsDefaults } from './SettingsDefaultsManager.js';
import { SettingsDefaultsManager } from './SettingsDefaultsManager.js';
import { USER_SETTINGS_PATH } from './paths.js';
import type { ParsedObservation } from '../sdk/parser.js';
import { incrementRedactionStats } from './redaction-stats.js';

export type ContentRedactionMode = 'off' | 'standard' | 'strict';

const VALID_MODES = new Set<ContentRedactionMode>(['off', 'standard', 'strict']);

/** Prefix for typed redaction placeholders, e.g. `[REDACTED:email]`. */
export const REDACTED_TOKEN_PREFIX = '[REDACTED';

/**
 * Hard ceiling on raw string length before any redaction regex runs.
 * Matches the error-scrub discipline (8192 chars).
 */
export const MAX_RAW_INPUT_CHARS = 8192;

export type ContentRedactionStats = {
  totalRedactions: number;
  byKind: Record<string, number>;
};

/** Builds a typed redaction token for a given secret kind. */
export function redactionToken(kind: string): string {
  return `${REDACTED_TOKEN_PREFIX}:${kind}]`;
}

/**
 * Collapses typed tokens (`[REDACTED:email]`, …) to plain `[REDACTED]`.
 * Used by telemetry/error-scrub for backward compatibility.
 */
export function collapseTypedRedactionTokens(text: string): string {
  if (typeof text !== 'string' || text.length === 0) return text ?? '';
  return text.replace(/\[REDACTED:[^\]]+\]/g, '[REDACTED]');
}

/**
 * Hard-truncates raw input to MAX_RAW_INPUT_CHARS before regex work.
 * Pure / never throws.
 */
export function capRawInput(text: unknown): string {
  try {
    if (typeof text !== 'string') {
      if (text === null || text === undefined) return '';
      try {
        text = String(text);
      } catch {
        return '';
      }
    }
    const s = text as string;
    return s.length > MAX_RAW_INPUT_CHARS ? s.slice(0, MAX_RAW_INPUT_CHARS) : s;
  } catch {
    return '';
  }
}

export function getRedactionModeFromSettings(
  settings: Partial<Pick<SettingsDefaults, 'CLAUDE_MEM_REDACTION'>>,
): ContentRedactionMode {
  const raw = settings.CLAUDE_MEM_REDACTION?.trim().toLowerCase();
  if (raw && VALID_MODES.has(raw as ContentRedactionMode)) {
    return raw as ContentRedactionMode;
  }
  return 'standard';
}

/** Returns true when a value looks like a secret (high entropy). */
function isHighEntropySecret(value: string): boolean {
  if (value.length < 8) return false;
  const hasLower = /[a-z]/.test(value);
  const hasUpper = /[A-Z]/.test(value);
  const hasDigit = /\d/.test(value);
  const hasSpecial = /[^A-Za-z0-9]/.test(value);
  if (hasDigit && (hasLower || hasUpper) && (hasLower !== hasUpper || hasSpecial)) return true;
  if (hasDigit && hasSpecial) return true;
  if (value.length >= 16 && hasDigit && (hasLower || hasUpper)) return true;
  return false;
}

/** Placeholder sentinels used to protect git SHAs during hex redaction. */
const GIT_SHA_SENTINEL_PREFIX = '\uE000GIT_SHA_';
const GIT_SHA_SENTINEL_SUFFIX = '\uE001';

type GitShaProtection = {
  text: string;
  restores: string[];
};

const GIT_SHA_CONTEXT_PATTERNS = [
  // commit / sha / ref labels (abbreviated or full SHAs).
  /\b((?:commit|sha|ref)\s*[:=]?\s*)([0-9a-f]{7,40})\b/gi,
  // hash= only for abbreviated SHAs (7–20 chars); full 40-char digests still redact.
  /\b(hash\s*=\s*)([0-9a-f]{7,20})\b/gi,
  // hash <sha> (space-separated).
  /\b(hash\s+)([0-9a-f]{7,40})\b/gi,
];

/** Replaces git-context SHAs with sentinels so later hex rules skip them. */
function protectGitShas(text: string): GitShaProtection {
  const restores: string[] = [];
  let protectedText = text;
  for (const pattern of GIT_SHA_CONTEXT_PATTERNS) {
    protectedText = protectedText.replace(pattern, (_match, prefix: string, sha: string) => {
      const idx = restores.length;
      restores.push(sha);
      return `${prefix}${GIT_SHA_SENTINEL_PREFIX}${idx}${GIT_SHA_SENTINEL_SUFFIX}`;
    });
  }
  return { text: protectedText, restores };
}

function restoreGitShas(text: string, restores: string[]): string {
  if (restores.length === 0) return text;
  return text.replace(
    new RegExp(`${GIT_SHA_SENTINEL_PREFIX}(\\d+)${GIT_SHA_SENTINEL_SUFFIX}`, 'g'),
    (_match, idxStr: string) => restores[Number(idxStr)] ?? _match
  );
}

export class ContentRedactor {
  private stats: ContentRedactionStats = { totalRedactions: 0, byKind: {} };

  resetStats(): void {
    this.stats = { totalRedactions: 0, byKind: {} };
  }

  getStats(): ContentRedactionStats {
    return {
      totalRedactions: this.stats.totalRedactions,
      byKind: { ...this.stats.byKind },
    };
  }

  private recordRedaction(kind: string, count = 1): void {
    this.stats.totalRedactions += count;
    this.stats.byKind[kind] = (this.stats.byKind[kind] ?? 0) + count;
    incrementRedactionStats(kind, count);
  }

  private replaceAll(
    text: string,
    pattern: RegExp,
    kind: string,
    replacer?: string | ((match: string) => string)
  ): string {
    const token = redactionToken(kind);
    let count = 0;
    const out = text.replace(pattern, (match) => {
      if (typeof replacer === 'function') {
        const replacement = replacer(match);
        if (replacement === match) return match;
        count += 1;
        return replacement;
      }
      count += 1;
      if (typeof replacer === 'string') return replacer;
      return token;
    });
    if (count > 0) this.recordRedaction(kind, count);
    return out;
  }

  /**
   * Redacts secret-shaped substrings with typed tokens.
   * Pure / never throws.
   */
  redactSecrets(text: string, options?: { mode?: ContentRedactionMode }): string {
    if (typeof text !== 'string' || text.length === 0) return text ?? '';

    const mode = options?.mode ?? 'standard';
    if (mode === 'off') return text;

    const gitProtection = protectGitShas(text);
    let out = gitProtection.text;

    out = this.replaceAll(
      out,
      /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----/g,
      'private_key'
    );

    out = this.replaceAll(
      out,
      /\b[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/\s@]+:[^@\s]+@[^\s"'()]+/g,
      'connection_string'
    );

    out = this.replaceAll(
      out,
      /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}/g,
      'email'
    );

    out = this.replaceAll(
      out,
      /\b[A-Za-z0-9_-]{10,512}\.[A-Za-z0-9_-]{10,512}\.[A-Za-z0-9_-]{10,512}\b/g,
      'jwt'
    );

    out = this.replaceAll(
      out,
      /\bBearer\s+[A-Za-z0-9._-]{8,512}\b/gi,
      'bearer'
    );

    out = this.replaceAll(
      out,
      /\bgithub_pat_[A-Za-z0-9_]{20,512}\b/g,
      'github_pat'
    );

    out = this.replaceAll(
      out,
      /\b(?:sk-ant|or)-[A-Za-z0-9_-]{8,512}\b/g,
      'api_key'
    );
    out = this.replaceAll(
      out,
      /\b(?:sk|pk|rk|ak|phc|phx|ph|ghp|gho|ghs|xox[bpasr])[-_][A-Za-z0-9_-]{8,512}\b/gi,
      'api_key'
    );

    out = this.replaceAll(
      out,
      /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b/g,
      'aws_key'
    );

    out = this.replaceAll(
      out,
      /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
      'uuid'
    );

    out = this.replaceAll(
      out,
      /(?:^|[\s;])([A-Z][A-Z0-9_]{2,})=([^\s"'`;]{8,512})/gm,
      'env_secret',
      (match) => {
        const eq = match.indexOf('=');
        if (eq < 0) return match;
        const prefix = match.slice(0, eq + 1);
        const value = match.slice(eq + 1);
        if (!isHighEntropySecret(value)) return match;
        return `${prefix}${redactionToken('env_secret')}`;
      }
    );

    out = this.replaceAll(
      out,
      /\b[0-9a-fA-F]{24,4096}\b/g,
      'hex'
    );

    out = this.replaceAll(
      out,
      /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g,
      'ipv4'
    );

    if (mode === 'strict') {
      out = this.replaceAll(
        out,
        /\b(?=[A-Za-z0-9+/_-]{0,4096}\d)[A-Za-z0-9+/_-]{32,4096}={0,2}\b/g,
        'token'
      );
    }

    return restoreGitShas(out, gitProtection.restores);
  }

  /**
   * Main capture-pipeline entry: cap raw input, then redact secrets.
   * Resets stats at the start of each call. Pure / never throws.
   */
  redactContent(text: unknown, options?: { mode?: ContentRedactionMode }): string {
    try {
      this.resetStats();
      const capped = capRawInput(text);
      if (capped.length === 0) return '';
      return this.redactSecrets(capped, options);
    } catch {
      return '';
    }
  }
}

/** Module-level redactor used by convenience exports and last-call stats. */
const defaultRedactor = new ContentRedactor();

/** Redacts secrets with typed tokens. Updates stats without resetting them. */
export function redactSecrets(text: string, options?: { mode?: ContentRedactionMode }): string {
  return defaultRedactor.redactSecrets(text, options);
}

/**
 * Capture-pipeline entry point (secrets only — no path/home redaction).
 * Resets stats before each call. Pure / never throws.
 */
export function redactContent(
  text: unknown,
  options?: { mode?: ContentRedactionMode }
): string {
  return defaultRedactor.redactContent(text, options);
}

/** Stats from the most recent `redactContent` call. */
export function getLastContentRedactionStats(): ContentRedactionStats {
  return defaultRedactor.getStats();
}

export function applyRedaction(
  text: string,
  settings?: Partial<Pick<SettingsDefaults, 'CLAUDE_MEM_REDACTION'>>,
): string {
  if (text == null || typeof text !== 'string') {
    return text ?? '';
  }
  const resolved = settings ?? SettingsDefaultsManager.loadFromFile(USER_SETTINGS_PATH);
  const mode = getRedactionModeFromSettings(resolved);
  return redactContent(text, { mode });
}

export function redactObservationFields<T extends ParsedObservation>(
  obs: T,
  settings?: Partial<Pick<SettingsDefaults, 'CLAUDE_MEM_REDACTION'>>,
): T {
  const redact = (value: string | null): string | null =>
    value == null ? value : applyRedaction(value, settings);
  const redactList = (values: string[]): string[] =>
    values.map(value => applyRedaction(value, settings));

  return {
    ...obs,
    title: redact(obs.title),
    subtitle: redact(obs.subtitle),
    narrative: redact(obs.narrative),
    facts: redactList(obs.facts),
    concepts: redactList(obs.concepts),
    files_read: redactList(obs.files_read),
    files_modified: redactList(obs.files_modified),
  };
}

export type SecretKind =
  | 'private_key'
  | 'connection_string'
  | 'email'
  | 'jwt'
  | 'bearer'
  | 'github_pat'
  | 'api_key'
  | 'aws_key'
  | 'uuid'
  | 'env_secret'
  | 'hex'
  | 'ipv4'
  | 'token';

interface DetectPattern {
  kind: SecretKind;
  regex: RegExp;
  accept?: (match: string) => boolean;
}

const STANDARD_DETECT_PATTERNS: DetectPattern[] = [
  {
    kind: 'private_key',
    regex:
      /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )?PRIVATE KEY-----/g,
  },
  {
    kind: 'connection_string',
    regex: /\b[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/\s@]+:[^@\s]+@[^\s"'()]+/g,
  },
  {
    kind: 'email',
    regex: /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}/g,
  },
  {
    kind: 'jwt',
    regex: /\b[A-Za-z0-9_-]{10,512}\.[A-Za-z0-9_-]{10,512}\.[A-Za-z0-9_-]{10,512}\b/g,
  },
  {
    kind: 'bearer',
    regex: /\bBearer\s+[A-Za-z0-9._-]{8,512}\b/gi,
  },
  {
    kind: 'github_pat',
    regex: /\bgithub_pat_[A-Za-z0-9_]{20,512}\b/g,
  },
  {
    kind: 'api_key',
    regex: /\b(?:sk-ant|or)-[A-Za-z0-9_-]{8,512}\b/g,
  },
  {
    kind: 'api_key',
    regex: /\b(?:sk|pk|rk|ak|phc|phx|ph|ghp|gho|ghs|xox[bpasr])[-_][A-Za-z0-9_-]{8,512}\b/gi,
  },
  {
    kind: 'aws_key',
    regex: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b/g,
  },
  {
    kind: 'uuid',
    regex:
      /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
  },
  {
    kind: 'env_secret',
    regex: /(?:^|[\s;])([A-Z][A-Z0-9_]{2,})=([^\s"'`;]{8,512})/gm,
    accept: (match) => {
      const eq = match.indexOf('=');
      if (eq < 0) return false;
      return isHighEntropySecret(match.slice(eq + 1));
    },
  },
  {
    kind: 'hex',
    regex: /\b[0-9a-fA-F]{24,4096}\b/g,
  },
  {
    kind: 'ipv4',
    regex:
      /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g,
  },
];

const STRICT_DETECT_PATTERNS: DetectPattern[] = [
  {
    kind: 'token',
    regex: /\b(?=[A-Za-z0-9+/_-]{0,4096}\d)[A-Za-z0-9+/_-]{32,4096}={0,2}\b/g,
  },
];

function collectKindsFromPatterns(
  text: string,
  patterns: DetectPattern[],
  found: Set<SecretKind>
): void {
  for (const { kind, regex, accept } of patterns) {
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      if (!accept || accept(match[0])) {
        found.add(kind);
        break;
      }
    }
  }
}

/**
 * Detect-only scan: returns secret kinds present in `text` without modifying it.
 * Uses the same standard/strict pattern set as redactSecrets (git SHAs allowlisted).
 */
export function detectSecretHits(
  text: string | null | undefined,
  options?: { mode?: ContentRedactionMode }
): SecretKind[] {
  if (typeof text !== 'string' || text.length === 0) {
    return [];
  }

  const mode = options?.mode ?? 'standard';
  if (mode === 'off') {
    return [];
  }

  const capped = capRawInput(text);
  if (capped.length === 0) {
    return [];
  }

  const gitProtection = protectGitShas(capped);
  const found = new Set<SecretKind>();
  collectKindsFromPatterns(gitProtection.text, STANDARD_DETECT_PATTERNS, found);
  if (mode === 'strict') {
    collectKindsFromPatterns(gitProtection.text, STRICT_DETECT_PATTERNS, found);
  }

  return [...found];
}

export function hasSecretHits(
  text: string | null | undefined,
  options?: { mode?: ContentRedactionMode }
): boolean {
  return detectSecretHits(text, options).length > 0;
}

/**
 * Scans a facts JSON column (array of strings) for secret-shaped content.
 */
export function detectSecretHitsInFacts(
  factsJson: string | null | undefined,
  options?: { mode?: ContentRedactionMode }
): SecretKind[] {
  const kinds = new Set<SecretKind>(detectSecretHits(factsJson, options));

  if (typeof factsJson !== 'string' || factsJson.length === 0) {
    return [...kinds];
  }

  try {
    const parsed = JSON.parse(factsJson) as unknown;
    if (Array.isArray(parsed)) {
      for (const entry of parsed) {
        if (typeof entry === 'string') {
          for (const kind of detectSecretHits(entry, options)) {
            kinds.add(kind);
          }
        }
      }
    }
  } catch {
    // Malformed JSON — raw-string scan above is sufficient.
  }

  return [...kinds];
}

/**
 * Redacts each string entry in a facts JSON array. Null in → null out.
 */
export function redactFactsJson(
  factsJson: string | null | undefined,
  options?: { mode?: ContentRedactionMode }
): string | null {
  if (factsJson === null || factsJson === undefined) {
    return null;
  }
  if (typeof factsJson !== 'string' || factsJson.length === 0) {
    return factsJson;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(factsJson);
  } catch {
    return redactContent(factsJson, options);
  }

  if (!Array.isArray(parsed)) {
    return redactContent(factsJson, options);
  }

  const redacted = parsed.map((entry) => {
    if (typeof entry === 'string') {
      return redactContent(entry, options);
    }
    return entry;
  });

  return JSON.stringify(redacted);
}