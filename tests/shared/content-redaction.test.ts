import { describe, expect, it, beforeEach } from 'bun:test';
import {
  ContentRedactor,
  applyRedaction,
  capRawInput,
  collapseTypedRedactionTokens,
  getLastContentRedactionStats,
  getRedactionModeFromSettings,
  MAX_RAW_INPUT_CHARS,
  redactContent,
  redactObservationFields,
  redactSecrets,
  redactionToken,
  REDACTED_TOKEN_PREFIX,
} from '../../src/shared/content-redaction.js';

const PEM_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7
-----END RSA PRIVATE KEY-----`;

// Secret-shaped fixtures are assembled at runtime so no literal in this file
// matches secret-scanner patterns (GitGuardian, GitHub push protection).
const FAKE_JWT = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  'eyJzdWIiOiIxMjM0NTY3ODkwIn0',
  'dozjgNryP4J3jVmNHl0w5N',
].join('.');
const FAKE_ENV_SECRET = ['xK9mP2nQ7vR4', 'wT8yZ1aB3cD5eF6gH0j'].join('');
const FAKE_GITHUB_PAT = ['github', '_pat_11AAAAAA_', 'B'.repeat(40)].join('');
const FAKE_BARE_TOKEN = 'X1y2Z3w4Q5r6'.repeat(4);

describe('content-redaction: settings integration', () => {
  it('getRedactionModeFromSettings defaults to standard for invalid values', () => {
    expect(getRedactionModeFromSettings({})).toBe('standard');
    expect(getRedactionModeFromSettings({ CLAUDE_MEM_REDACTION: 'bogus' })).toBe('standard');
  });

  it('getRedactionModeFromSettings accepts off, standard, and strict', () => {
    expect(getRedactionModeFromSettings({ CLAUDE_MEM_REDACTION: 'off' })).toBe('off');
    expect(getRedactionModeFromSettings({ CLAUDE_MEM_REDACTION: 'STRICT' })).toBe('strict');
  });

  it('redactContent passes through unchanged when mode is off', () => {
    const input = 'token sk-test12345678901234567890123456789012 and /Users/alice/repo/file.ts';
    expect(redactContent(input, { mode: 'off' })).toBe(input);
  });

  it('redactContent masks secrets in standard mode with typed tokens', () => {
    const input = 'api key sk-test12345678901234567890123456789012';
    const output = redactContent(input, { mode: 'standard' });
    expect(output).toContain('[REDACTED:api_key]');
    expect(output).not.toContain('sk-test12345678901234567890123456789012');
  });

  it('strict mode does not redact absolute paths (telemetry-specific)', () => {
    const input = 'read /Users/alice/projects/app/src/index.ts';
    const output = redactContent(input, { mode: 'strict' });
    expect(output).toContain('/Users/alice/projects/app/src/index.ts');
  });

  it('applyRedaction honors settings mode', () => {
    const input = 'api key sk-test12345678901234567890123456789012';
    expect(applyRedaction(input, { CLAUDE_MEM_REDACTION: 'off' })).toBe(input);
    expect(applyRedaction(input, { CLAUDE_MEM_REDACTION: 'standard' })).toContain('[REDACTED:api_key]');
  });

  it('redactObservationFields redacts secrets but not file paths', () => {
    const redacted = redactObservationFields({
      type: 'discovery',
      title: 'Found sk-test12345678901234567890123456789012',
      subtitle: null,
      facts: ['email user@example.com'],
      narrative: null,
      concepts: [],
      files_read: ['/Users/alice/repo/a.ts'],
      files_modified: [],
    }, { CLAUDE_MEM_REDACTION: 'strict' });

    expect(redacted.title).toContain('[REDACTED:api_key]');
    expect(redacted.facts[0]).toContain('[REDACTED:email]');
    expect(redacted.files_read[0]).toBe('/Users/alice/repo/a.ts');
  });
});

describe('content-redaction: capRawInput', () => {
  it('caps strings at MAX_RAW_INPUT_CHARS', () => {
    const long = 'x'.repeat(MAX_RAW_INPUT_CHARS + 100);
    expect(capRawInput(long).length).toBe(MAX_RAW_INPUT_CHARS);
  });

  it('returns empty for null/undefined', () => {
    expect(capRawInput(null)).toBe('');
    expect(capRawInput(undefined)).toBe('');
  });

  it('coerces non-strings safely', () => {
    expect(capRawInput(42)).toBe('42');
  });
});

describe('content-redaction: redactionToken', () => {
  it('builds typed tokens with the shared prefix', () => {
    expect(redactionToken('email')).toBe('[REDACTED:email]');
    expect(REDACTED_TOKEN_PREFIX).toBe('[REDACTED');
  });
});

describe('content-redaction: collapseTypedRedactionTokens', () => {
  it('collapses all typed tokens to plain [REDACTED]', () => {
    const input = 'a [REDACTED:email] b [REDACTED:jwt] c';
    expect(collapseTypedRedactionTokens(input)).toBe('a [REDACTED] b [REDACTED] c');
  });
});

describe('content-redaction: mode off', () => {
  it('returns input unchanged in off mode', () => {
    const input = 'mail alice@example.com token sk-ABCdef1234567890ghij';
    expect(redactSecrets(input, { mode: 'off' })).toBe(input);
  });
});

describe('content-redaction: standard mode patterns', () => {
  it('redacts emails with typed token', () => {
    const out = redactSecrets('contact alice@example.com please', { mode: 'standard' });
    expect(out).not.toContain('alice@example.com');
    expect(out).toContain('[REDACTED:email]');
  });

  it('redacts JWTs', () => {
    const jwt = FAKE_JWT;
    const out = redactSecrets(`token ${jwt}`, { mode: 'standard' });
    expect(out).not.toContain(jwt);
    expect(out).toContain('[REDACTED:jwt]');
  });

  it('redacts sk- and phc_ API keys', () => {
    const out = redactSecrets('keys sk-ABCdef1234567890ghij phc_ABCdef1234567890ghijKLMNOP', {
      mode: 'standard',
    });
    expect(out).toContain('[REDACTED:api_key]');
    expect(out).not.toContain('sk-ABCdef1234567890ghij');
    expect(out).not.toContain('phc_ABCdef1234567890ghijKLMNOP');
  });

  it('redacts Anthropic sk-ant- and OpenRouter or- keys', () => {
    const out = redactSecrets(
      'anthropic sk-ant-api03-ABCdef1234567890ghij openrouter or-v1-ABCdef1234567890ghij',
      { mode: 'standard' }
    );
    expect(out).not.toContain('sk-ant-api03-ABCdef1234567890ghij');
    expect(out).not.toContain('or-v1-ABCdef1234567890ghij');
    expect(out).toContain('[REDACTED:api_key]');
  });

  it('redacts github_pat_ tokens', () => {
    const pat = FAKE_GITHUB_PAT;
    const out = redactSecrets(`pat ${pat}`, { mode: 'standard' });
    expect(out).not.toContain(pat);
    expect(out).toContain('[REDACTED:github_pat]');
  });

  it('redacts AWS access key IDs', () => {
    const out = redactSecrets('creds AKIAIOSFODNN7EXAMPLE rejected', { mode: 'standard' });
    expect(out).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(out).toContain('[REDACTED:aws_key]');
  });

  it('redacts long hex blobs', () => {
    const hex = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    const out = redactSecrets(`digest ${hex}`, { mode: 'standard' });
    expect(out).not.toContain(hex);
    expect(out).toContain('[REDACTED:hex]');
  });

  it('redacts UUIDs', () => {
    const uuid = '550e8400-e29b-41d4-a716-446655440000';
    const out = redactSecrets(`id ${uuid}`, { mode: 'standard' });
    expect(out).not.toContain(uuid);
    expect(out).toContain('[REDACTED:uuid]');
  });

  it('redacts Bearer tokens', () => {
    const out = redactSecrets('Authorization Bearer abcdef1234567890ghijklmnop', { mode: 'standard' });
    expect(out).not.toContain('Bearer abcdef1234567890ghijklmnop');
    expect(out).toContain('[REDACTED:bearer]');
  });

  it('redacts IPv4 addresses', () => {
    const out = redactSecrets('connect failed to 10.0.0.5:5432', { mode: 'standard' });
    expect(out).not.toContain('10.0.0.5');
    expect(out).toContain('[REDACTED:ipv4]');
  });

  it('does NOT mask 3-part version numbers as IPs', () => {
    const out = redactSecrets('claude-mem 13.6.2 ready', { mode: 'standard' });
    expect(out).toContain('13.6.2');
  });

  it('redacts PEM private keys', () => {
    const out = redactSecrets(`leaked ${PEM_KEY} end`, { mode: 'standard' });
    expect(out).not.toContain('BEGIN RSA PRIVATE KEY');
    expect(out).toContain('[REDACTED:private_key]');
  });

  it('redacts high-entropy env assignments', () => {
    const secret = FAKE_ENV_SECRET;
    const out = redactSecrets(`export API_SECRET=${secret}`, { mode: 'standard' });
    expect(out).not.toContain(secret);
    expect(out).toContain('[REDACTED:env_secret]');
  });

  it('leaves low-entropy env assignments alone', () => {
    const out = redactSecrets('export NODE_ENV=production', { mode: 'standard' });
    expect(out).toContain('NODE_ENV=production');
  });

  it('redacts connection strings with credentials', () => {
    const out = redactSecrets('ECONN postgres://user:pass@host:5432/db failed', { mode: 'standard' });
    expect(out).not.toContain('user:pass');
    expect(out).toContain('[REDACTED:connection_string]');
  });

  it('does NOT apply bare high-entropy token heuristic in standard mode', () => {
    const bare = FAKE_BARE_TOKEN;
    const out = redactSecrets(`value ${bare}`, { mode: 'standard' });
    expect(out).toContain(bare);
  });
});

describe('content-redaction: strict mode', () => {
  it('redacts bare high-entropy tokens in strict mode', () => {
    const bare = FAKE_BARE_TOKEN;
    const out = redactSecrets(`value ${bare}`, { mode: 'strict' });
    expect(out).not.toContain(bare);
    expect(out).toContain('[REDACTED:token]');
  });
});

describe('content-redaction: git SHA allowlist', () => {
  it('preserves lowercase hex SHAs in git context (commit)', () => {
    const sha = 'abc1234567890abcdef1234567890abcdef1234';
    const out = redactSecrets(`bad commit ${sha} failed`, { mode: 'strict' });
    expect(out).toContain(sha);
    expect(out).not.toContain('[REDACTED:hex]');
  });

  it('preserves SHAs after sha: prefix', () => {
    const sha = 'def1234';
    const out = redactSecrets(`reset to sha:${sha}`, { mode: 'strict' });
    expect(out).toContain(`sha:${sha}`);
  });

  it('preserves abbreviated SHAs after hash= prefix', () => {
    const sha = '0123456789abcdef';
    const out = redactSecrets(`hash=${sha}`, { mode: 'strict' });
    expect(out).toContain(`hash=${sha}`);
  });

  it('preserves SHAs after ref prefix', () => {
    const sha = 'abcdef0';
    const out = redactSecrets(`ref ${sha}`, { mode: 'strict' });
    expect(out).toContain(`ref ${sha}`);
  });

  it('redacts long hex after hash= (digest, not abbreviated SHA)', () => {
    const hex = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    const out = redactSecrets(`hash=${hex}`, { mode: 'standard' });
    expect(out).not.toContain(hex);
    expect(out).toContain('[REDACTED:hex]');
  });

  it('still redacts long hex outside git context', () => {
    const hex = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    const out = redactSecrets(`digest ${hex}`, { mode: 'standard' });
    expect(out).not.toContain(hex);
    expect(out).toContain('[REDACTED:hex]');
  });
});

describe('content-redaction: redactContent', () => {
  beforeEach(() => {
    redactContent('warmup', { mode: 'off' });
  });

  it('caps input and redacts secrets', () => {
    const out = redactContent('email bob@example.com', { mode: 'standard' });
    expect(out).toContain('[REDACTED:email]');
    expect(out).not.toContain('bob@example.com');
  });

  it('returns empty for null/undefined', () => {
    expect(redactContent(null)).toBe('');
    expect(redactContent(undefined)).toBe('');
  });
});

describe('content-redaction: stats', () => {
  it('tracks stats from the last redactContent call', () => {
    redactContent(`alice@example.com jwt=${FAKE_JWT} AKIAIOSFODNN7EXAMPLE`, { mode: 'standard' });
    const stats = getLastContentRedactionStats();
    expect(stats.totalRedactions).toBeGreaterThanOrEqual(3);
    expect(stats.byKind.email).toBe(1);
    expect(stats.byKind.jwt).toBe(1);
    expect(stats.byKind.aws_key).toBe(1);
  });

  it('resets stats at the start of each redactContent call', () => {
    redactContent('alice@example.com', { mode: 'standard' });
    redactContent('no secrets here', { mode: 'standard' });
    const stats = getLastContentRedactionStats();
    expect(stats.totalRedactions).toBe(0);
  });

  it('ContentRedactor class exposes isolated stats', () => {
    const redactor = new ContentRedactor();
    redactor.redactContent('token sk-ABCdef1234567890ghij', { mode: 'standard' });
    const stats = redactor.getStats();
    expect(stats.byKind.api_key).toBe(1);
    expect(stats.totalRedactions).toBe(1);
  });
});

describe('content-redaction: ReDoS bound', () => {
  it('redactContent on hostile 200KB input stays under 100ms', () => {
    const hostile = 'a.b-c_d%e+f'.repeat(20000);
    const t0 = performance.now();
    const out = redactContent(hostile, { mode: 'strict' });
    const elapsed = performance.now() - t0;
    expect(typeof out).toBe('string');
    expect(out.length).toBeLessThanOrEqual(MAX_RAW_INPUT_CHARS);
    expect(elapsed).toBeLessThan(100);
  });
});