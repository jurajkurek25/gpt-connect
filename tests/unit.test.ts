import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { decrypt, encrypt, safeEqual } from '../src/crypto.js';
import { createLogger, redact } from '../src/logger.js';
import { classifyUrgency, fromGoogleDue, isValidDateOnly, toGoogleDue, todayIn } from '../src/tasks/dates.js';
import { appendMarker, extractSourceHash, findDuplicates, normalizeTitle, sourceHash, stripMarker, titleSimilarity } from '../src/tasks/duplicates.js';

const baseEnv = {
  PUBLIC_BASE_URL: 'https://tasks.example.com',
  GOOGLE_CLIENT_ID: 'id.apps.googleusercontent.com',
  GOOGLE_CLIENT_SECRET: 'GOCSPX-secret-value',
  TOKEN_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  OWNER_PASSPHRASE: 'a-long-owner-passphrase',
};

describe('config', () => {
  it('derives URLs from PUBLIC_BASE_URL', () => {
    const c = loadConfig(baseEnv);
    expect(c.mcpResourceUrl).toBe('https://tasks.example.com/mcp');
    expect(c.googleRedirectUri).toBe('https://tasks.example.com/oauth/google/callback');
    expect(c.allowedRedirectUris).toEqual(['https://chatgpt.com/connector_platform_oauth_redirect']);
  });
  it('requires https unless explicitly allowed', () => {
    expect(() => loadConfig({ ...baseEnv, PUBLIC_BASE_URL: 'http://tasks.example.com' })).toThrow(/https/);
  });
  it('requires a 32-byte encryption key', () => {
    expect(() => loadConfig({ ...baseEnv, TOKEN_ENCRYPTION_KEY: randomBytes(16).toString('base64') })).toThrow(/32/);
  });
  it('rejects a short passphrase without echoing secret values', () => {
    let msg = '';
    try {
      loadConfig({ ...baseEnv, OWNER_PASSPHRASE: 'short' });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/OWNER_PASSPHRASE/);
    expect(msg).not.toContain(baseEnv.GOOGLE_CLIENT_SECRET);
    expect(msg).not.toContain('short');
  });
});

describe('crypto', () => {
  const key = randomBytes(32);
  it('round-trips and binds the purpose', () => {
    const c = encrypt('refresh-token', key, 'a');
    expect(c).not.toContain('refresh-token');
    expect(decrypt(c, key, 'a')).toBe('refresh-token');
    expect(() => decrypt(c, key, 'b')).toThrow();
    expect(() => decrypt(c, randomBytes(32), 'a')).toThrow();
  });
  it('detects tampering', () => {
    const c = encrypt('x', key, 'a');
    const raw = Buffer.from(c.slice(3), 'base64');
    raw[raw.length - 1] = (raw[raw.length - 1] as number) ^ 1;
    expect(() => decrypt(`v1:${raw.toString('base64')}`, key, 'a')).toThrow();
  });
  it('safeEqual', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcd')).toBe(false);
  });
});

describe('dates', () => {
  it('validates YYYY-MM-DD strictly', () => {
    expect(isValidDateOnly('2026-10-12')).toBe(true);
    expect(isValidDateOnly('2026-02-30')).toBe(false);
    expect(isValidDateOnly('2026-10-12T10:00:00Z')).toBe(false);
    expect(isValidDateOnly('12.10.2026')).toBe(false);
    expect(isValidDateOnly('1999-01-01')).toBe(false);
  });
  it('never invents a time: midnight UTC carries only the date', () => {
    expect(toGoogleDue('2026-10-20')).toBe('2026-10-20T00:00:00.000Z');
    expect(fromGoogleDue('2026-10-20T00:00:00.000Z')).toBe('2026-10-20');
    expect(fromGoogleDue(undefined)).toBeNull();
  });
  it('computes today in the configured timezone', () => {
    // 23:30 UTC on Oct 11 is already Oct 12 in Bratislava (UTC+2).
    expect(todayIn('Europe/Bratislava', Date.parse('2026-10-11T23:30:00Z'))).toBe('2026-10-12');
  });
  it('classifies urgency', () => {
    expect(classifyUrgency('2026-10-12', false, '2026-10-12').urgency).toBe('urgent');
    expect(classifyUrgency('2026-10-13', false, '2026-10-12').urgency).toBe('urgent');
    expect(classifyUrgency('2026-10-14', false, '2026-10-12').urgency).toBe('normal');
    expect(classifyUrgency('2026-10-10', false, '2026-10-12')).toMatchObject({ urgency: 'urgent', overdue: true });
    expect(classifyUrgency('2026-10-12', true, '2026-10-12').urgency).toBeNull();
    expect(classifyUrgency(null, false, '2026-10-12').urgency).toBeNull();
  });
});

describe('duplicates', () => {
  it('normalizes Slovak titles', () => {
    expect(normalizeTitle('Všeobecná psychológia – zápis témy prezentácie')).toBe('vseobecna psychologia zapis temy prezentacie');
    expect(normalizeTitle('  UCM – žiadosť  o status ')).toBe('ucm ziadost o status');
  });
  it('source markers store only a hash', () => {
    const id = '<AM6PR01MB1234@eurprd01.prod.outlook.com>';
    const h = sourceHash(id);
    const notes = appendMarker('Odovzdať cez AIS', h);
    expect(notes).not.toContain(id);
    expect(extractSourceHash(notes)).toBe(h);
    expect(appendMarker(notes, h)).toBe(notes);
    expect(stripMarker(notes)).toBe('Odovzdať cez AIS');
  });
  it('prefers deterministic source IDs over fuzzy matches', () => {
    const h = sourceHash('msg-1');
    const matches = findDuplicates({ title: 'Všeobecná psychológia – zápis témy prezentácie', dueDate: '2026-10-12', sourceHash: h }, [
      { id: 'a', title: 'Vseobecna psychologia - zapis temy prezentacie', dueDate: '2026-10-12', sourceHash: null },
      { id: 'b', title: 'Something else', dueDate: null, sourceHash: h },
      { id: 'c', title: 'Všeobecná psychológia – zápis témy prezentácií', dueDate: '2026-10-12', sourceHash: null },
      { id: 'd', title: 'Všeobecná psychológia – zápis témy prezentácie', dueDate: '2026-11-01', sourceHash: null },
      { id: 'e', title: 'Úplne iná úloha', dueDate: '2026-10-12', sourceHash: null },
    ]);
    expect(matches.map((m) => [m.task_id, m.match_type])).toEqual([
      ['b', 'source_id'],
      ['a', 'exact_title_and_date'],
      ['d', 'exact_title'],
      ['c', 'similar_title'],
    ]);
  });
  it('similarity is symmetric and bounded', () => {
    const s = titleSimilarity('UCM – žiadosť o status', 'UCM žiadosť o štatút');
    expect(s).toBeGreaterThan(0);
    expect(s).toBeLessThan(1);
    expect(titleSimilarity('a b c', 'a b c')).toBe(1);
  });
});

describe('logger', () => {
  it('redacts sensitive keys and token-shaped strings', () => {
    const lines: string[] = [];
    const log = createLogger('debug', (l) => lines.push(l));
    log.info('auth header Bearer abc.def-ghi and ya29.A0AfH6SMB', {
      access_token: 'x1',
      refresh_token: 'x2',
      code: 'x3',
      nested: { client_secret: 'x4', ok: 'visible' },
      notes: 'email body',
    });
    const out = lines.join('\n');
    for (const s of ['x1', 'x2', 'x3', 'x4', 'abc.def-ghi', 'ya29.A0AfH6SMB', 'email body']) expect(out).not.toContain(s);
    expect(out).toContain('visible');
    expect(redact({ Authorization: 'Bearer t' })).toEqual({ Authorization: '[redacted]' });
  });
});
