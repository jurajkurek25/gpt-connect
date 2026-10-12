import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,
  token_endpoint_auth_method TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  client_name TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_requests (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  state TEXT,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  browser_nonce_hash TEXT NOT NULL,
  google_state_hash TEXT UNIQUE,
  google_verifier_enc TEXT,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  family_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS access_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  family_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  family_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  rotated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS google_account (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  google_sub TEXT NOT NULL,
  refresh_token_enc TEXT NOT NULL,
  access_token_enc TEXT,
  access_token_expires_at INTEGER,
  scope TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency (
  source_hash TEXT PRIMARY KEY,
  tasklist_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  event TEXT NOT NULL,
  outcome TEXT NOT NULL,
  client_id TEXT,
  tasklist_id TEXT,
  task_id TEXT,
  source_hash TEXT,
  detail TEXT
);
`;

export interface ClientRow {
  client_id: string;
  client_secret_hash: string | null;
  token_endpoint_auth_method: string;
  redirect_uris: string;
  client_name: string | null;
  created_at: number;
}

export interface AuthRequestRow {
  id: string;
  client_id: string;
  redirect_uri: string;
  state: string | null;
  code_challenge: string;
  scope: string;
  resource: string;
  browser_nonce_hash: string;
  google_state_hash: string | null;
  google_verifier_enc: string | null;
  expires_at: number;
}

export interface AuthCodeRow {
  code_hash: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scope: string;
  resource: string;
  family_id: string;
  expires_at: number;
  used: number;
}

export interface TokenRow {
  token_hash: string;
  client_id: string;
  scope: string;
  resource: string;
  family_id: string;
  expires_at: number;
  rotated?: number;
}

export interface GoogleAccountRow {
  google_sub: string;
  refresh_token_enc: string;
  access_token_enc: string | null;
  access_token_expires_at: number | null;
  scope: string;
  updated_at: number;
}

export interface IdempotencyRow {
  source_hash: string;
  tasklist_id: string;
  task_id: string;
  created_at: number;
}

export interface AuditEntry {
  event: string;
  outcome: string;
  client_id?: string | null;
  tasklist_id?: string | null;
  task_id?: string | null;
  source_hash?: string | null;
  detail?: string | null;
}

type Row = Record<string, unknown>;

export class Store {
  readonly db: DatabaseSync;

  constructor(path: string) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    this.db.exec(SCHEMA);
    // Ciphertexts are useless without the key, but keep the file private anyway.
    if (path !== ':memory:') chmodSync(path, 0o600);
  }

  close(): void {
    this.db.close();
  }

  private get<T>(sql: string, ...params: (string | number | null)[]): T | undefined {
    return this.db.prepare(sql).get(...params) as T | undefined;
  }

  private run(sql: string, ...params: (string | number | null)[]): number {
    return Number(this.db.prepare(sql).run(...params).changes);
  }

  // ---- OAuth clients -------------------------------------------------------
  countClients(): number {
    return Number(this.get<Row>('SELECT COUNT(*) AS n FROM oauth_clients')?.n ?? 0);
  }
  insertClient(c: ClientRow): void {
    this.run(
      'INSERT INTO oauth_clients (client_id, client_secret_hash, token_endpoint_auth_method, redirect_uris, client_name, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      c.client_id, c.client_secret_hash, c.token_endpoint_auth_method, c.redirect_uris, c.client_name, c.created_at,
    );
  }
  /** Removes the oldest client that is older than `olderThan` and holds no live tokens. Returns true if one was removed. */
  evictStaleClient(olderThan: number): boolean {
    return (
      this.run(
        `DELETE FROM oauth_clients WHERE client_id = (
           SELECT c.client_id FROM oauth_clients c
           WHERE c.created_at < ?
             AND NOT EXISTS (SELECT 1 FROM refresh_tokens r WHERE r.client_id = c.client_id)
             AND NOT EXISTS (SELECT 1 FROM access_tokens a WHERE a.client_id = c.client_id)
           ORDER BY c.created_at ASC LIMIT 1)`,
        olderThan,
      ) === 1
    );
  }
  getClient(clientId: string): ClientRow | undefined {
    return this.get<ClientRow>('SELECT * FROM oauth_clients WHERE client_id = ?', clientId);
  }

  // ---- Authorization requests ---------------------------------------------
  insertAuthRequest(r: AuthRequestRow): void {
    this.run(
      `INSERT INTO auth_requests (id, client_id, redirect_uri, state, code_challenge, scope, resource, browser_nonce_hash, google_state_hash, google_verifier_enc, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      r.id, r.client_id, r.redirect_uri, r.state, r.code_challenge, r.scope, r.resource, r.browser_nonce_hash, r.google_state_hash, r.google_verifier_enc, r.expires_at,
    );
  }
  getAuthRequest(id: string): AuthRequestRow | undefined {
    return this.get<AuthRequestRow>('SELECT * FROM auth_requests WHERE id = ?', id);
  }
  setAuthRequestGoogleState(id: string, googleStateHash: string, verifierEnc: string): void {
    this.run('UPDATE auth_requests SET google_state_hash = ?, google_verifier_enc = ? WHERE id = ?', googleStateHash, verifierEnc, id);
  }
  /** Fetches and deletes in one step so a Google `state` can only be used once. */
  takeAuthRequestByGoogleState(googleStateHash: string): AuthRequestRow | undefined {
    const row = this.get<AuthRequestRow>('SELECT * FROM auth_requests WHERE google_state_hash = ?', googleStateHash);
    if (row) this.run('DELETE FROM auth_requests WHERE id = ?', row.id);
    return row;
  }
  deleteAuthRequest(id: string): void {
    this.run('DELETE FROM auth_requests WHERE id = ?', id);
  }

  // ---- Authorization codes ------------------------------------------------
  insertAuthCode(c: AuthCodeRow): void {
    this.run(
      'INSERT INTO auth_codes (code_hash, client_id, redirect_uri, code_challenge, scope, resource, family_id, expires_at, used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)',
      c.code_hash, c.client_id, c.redirect_uri, c.code_challenge, c.scope, c.resource, c.family_id, c.expires_at,
    );
  }
  getAuthCode(codeHash: string): AuthCodeRow | undefined {
    return this.get<AuthCodeRow>('SELECT * FROM auth_codes WHERE code_hash = ?', codeHash);
  }
  /** Returns true only for the first caller (atomic single-use). */
  markAuthCodeUsed(codeHash: string): boolean {
    return this.run('UPDATE auth_codes SET used = 1 WHERE code_hash = ? AND used = 0', codeHash) === 1;
  }

  // ---- Tokens --------------------------------------------------------------
  insertAccessToken(t: TokenRow): void {
    this.run(
      'INSERT INTO access_tokens (token_hash, client_id, scope, resource, family_id, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
      t.token_hash, t.client_id, t.scope, t.resource, t.family_id, t.expires_at,
    );
  }
  getAccessToken(hash: string): TokenRow | undefined {
    return this.get<TokenRow>('SELECT * FROM access_tokens WHERE token_hash = ?', hash);
  }
  insertRefreshToken(t: TokenRow): void {
    this.run(
      'INSERT INTO refresh_tokens (token_hash, client_id, scope, resource, family_id, expires_at, rotated) VALUES (?, ?, ?, ?, ?, ?, 0)',
      t.token_hash, t.client_id, t.scope, t.resource, t.family_id, t.expires_at,
    );
  }
  getRefreshToken(hash: string): TokenRow | undefined {
    return this.get<TokenRow>('SELECT * FROM refresh_tokens WHERE token_hash = ?', hash);
  }
  /** Returns true only for the first caller (atomic rotation). */
  markRefreshTokenRotated(hash: string): boolean {
    return this.run('UPDATE refresh_tokens SET rotated = 1 WHERE token_hash = ? AND rotated = 0', hash) === 1;
  }
  revokeFamily(familyId: string): void {
    this.run('DELETE FROM access_tokens WHERE family_id = ?', familyId);
    this.run('DELETE FROM refresh_tokens WHERE family_id = ?', familyId);
  }
  revokeAllTokens(): void {
    this.db.exec('DELETE FROM access_tokens; DELETE FROM refresh_tokens; DELETE FROM auth_codes; DELETE FROM auth_requests;');
  }
  purgeExpired(now: number): void {
    this.run('DELETE FROM access_tokens WHERE expires_at < ?', now);
    this.run('DELETE FROM refresh_tokens WHERE expires_at < ?', now);
    this.run('DELETE FROM auth_codes WHERE expires_at < ?', now - 86_400_000);
    this.run('DELETE FROM auth_requests WHERE expires_at < ?', now);
  }

  // ---- Google account (single owner) --------------------------------------
  getGoogleAccount(): GoogleAccountRow | undefined {
    return this.get<GoogleAccountRow>('SELECT * FROM google_account WHERE id = 1');
  }
  upsertGoogleAccount(a: GoogleAccountRow): void {
    this.run(
      `INSERT INTO google_account (id, google_sub, refresh_token_enc, access_token_enc, access_token_expires_at, scope, updated_at)
       VALUES (1, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET google_sub = excluded.google_sub, refresh_token_enc = excluded.refresh_token_enc,
         access_token_enc = excluded.access_token_enc, access_token_expires_at = excluded.access_token_expires_at,
         scope = excluded.scope, updated_at = excluded.updated_at`,
      a.google_sub, a.refresh_token_enc, a.access_token_enc, a.access_token_expires_at, a.scope, a.updated_at,
    );
  }
  updateGoogleAccessToken(accessTokenEnc: string, expiresAt: number, now: number): void {
    this.run('UPDATE google_account SET access_token_enc = ?, access_token_expires_at = ?, updated_at = ? WHERE id = 1', accessTokenEnc, expiresAt, now);
  }
  deleteGoogleAccount(): void {
    this.run('DELETE FROM google_account WHERE id = 1');
  }

  // ---- Idempotency ---------------------------------------------------------
  getIdempotency(sourceHash: string): IdempotencyRow | undefined {
    return this.get<IdempotencyRow>('SELECT * FROM idempotency WHERE source_hash = ?', sourceHash);
  }
  putIdempotency(r: IdempotencyRow): void {
    this.run(
      'INSERT INTO idempotency (source_hash, tasklist_id, task_id, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(source_hash) DO UPDATE SET tasklist_id = excluded.tasklist_id, task_id = excluded.task_id, created_at = excluded.created_at',
      r.source_hash, r.tasklist_id, r.task_id, r.created_at,
    );
  }
  deleteIdempotencyBySource(sourceHash: string): void {
    this.run('DELETE FROM idempotency WHERE source_hash = ?', sourceHash);
  }
  deleteIdempotencyByTask(taskId: string): void {
    this.run('DELETE FROM idempotency WHERE task_id = ?', taskId);
  }

  // ---- Audit ---------------------------------------------------------------
  audit(e: AuditEntry, now: number = Date.now()): void {
    this.run(
      'INSERT INTO audit_log (ts, event, outcome, client_id, tasklist_id, task_id, source_hash, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      now, e.event, e.outcome, e.client_id ?? null, e.tasklist_id ?? null, e.task_id ?? null, e.source_hash ?? null, e.detail ?? null,
    );
  }
  listAudit(limit = 100): (AuditEntry & { ts: number })[] {
    return this.db.prepare('SELECT ts, event, outcome, client_id, tasklist_id, task_id, source_hash, detail FROM audit_log ORDER BY id DESC LIMIT ?').all(limit) as unknown as (AuditEntry & { ts: number })[];
  }
}
