import type { AuthInfo, OAuthMetadata, OAuthTokenVerifier } from '@modelcontextprotocol/server';
import { OAuthError, OAuthErrorCode } from '@modelcontextprotocol/server';
import express, { type Request, type Response, Router } from 'express';
import { z } from 'zod';
import type { Config } from '../config.js';
import { GOOGLE_TASKS_SCOPE, MCP_SCOPE } from '../config.js';
import { decrypt, encrypt, randomToken, safeEqual, sha256Base64Url, sha256Hex } from '../crypto.js';
import type { ClientRow, Store } from '../db.js';
import type { GoogleCredentials } from '../google/credentials.js';
import type { GoogleOAuthClient } from '../google/oauth.js';
import type { Logger } from '../logger.js';
import { consentPage, errorPage } from './pages.js';

export const ACCESS_TOKEN_TTL_S = 3600;
export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 3600 * 1000;
const AUTH_REQUEST_TTL_MS = 10 * 60_000;
const AUTH_CODE_TTL_MS = 2 * 60_000;
const MAX_CLIENTS = 50;
const PKCE_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
const PURPOSE_GOOGLE_VERIFIER = 'google_pkce_verifier';

export interface OAuthDeps {
  config: Config;
  store: Store;
  googleOAuth: GoogleOAuthClient;
  credentials: GoogleCredentials;
  logger: Logger;
  now?: () => number;
}

export function authorizationServerMetadata(config: Config): OAuthMetadata {
  const base = config.publicBaseUrl;
  return {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    registration_endpoint: `${base}/oauth/register`,
    revocation_endpoint: `${base}/oauth/revoke`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    revocation_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    scopes_supported: [MCP_SCOPE],
    authorization_response_iss_parameter_supported: true,
  } as OAuthMetadata;
}

/** Maps an RFC 8707 `resource` value to this server's single protected resource, or null if it is foreign. */
function normalizeResource(config: Config, resource: string | undefined): string | null {
  if (resource === undefined || resource === '') return config.mcpResourceUrl;
  const accepted = new Set([config.mcpResourceUrl, `${config.mcpResourceUrl}/`, config.publicBaseUrl, `${config.publicBaseUrl}/`]);
  return accepted.has(resource) ? config.mcpResourceUrl : null;
}

function parseScope(scope: string | undefined): string | null {
  if (!scope || scope.trim() === '') return MCP_SCOPE;
  const parts = scope.split(' ').filter(Boolean);
  return parts.every((p) => p === MCP_SCOPE) ? MCP_SCOPE : null;
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function safeDecode(s: string): string | undefined {
  try {
    return decodeURIComponent(s);
  } catch {
    return undefined;
  }
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const value = safeDecode(part.slice(i + 1).trim());
    if (value !== undefined) out[part.slice(0, i).trim()] = value;
  }
  return out;
}

function noStore(res: Response): void {
  res.set('Cache-Control', 'no-store');
  res.set('Pragma', 'no-cache');
}

const RegistrationSchema = z.object({
  redirect_uris: z.array(z.string().max(2000)).min(1).max(5),
  client_name: z.string().max(200).optional(),
  token_endpoint_auth_method: z.enum(['none', 'client_secret_post', 'client_secret_basic']).optional(),
  grant_types: z.array(z.string()).optional(),
  response_types: z.array(z.string()).optional(),
  scope: z.string().max(200).optional(),
});

export function createOAuthRouter(deps: OAuthDeps): Router {
  const { config, store, googleOAuth, credentials, logger } = deps;
  const now = deps.now ?? Date.now;
  const router = Router();
  const secureCookies = config.publicBaseUrl.startsWith('https://');
  const cookieName = secureCookies ? '__Host-gtm_auth' : 'gtm_auth';
  const urlencoded = express.urlencoded({ extended: false, limit: '16kb', parameterLimit: 20 });
  const json = express.json({ limit: '16kb' });

  const setBrowserCookie = (res: Response, value: string) => {
    res.append('Set-Cookie', `${cookieName}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${AUTH_REQUEST_TTL_MS / 1000}${secureCookies ? '; Secure' : ''}`);
  };
  const clearBrowserCookie = (res: Response) => {
    res.append('Set-Cookie', `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureCookies ? '; Secure' : ''}`);
  };
  const browserMatches = (req: Request, nonceHash: string) => {
    const nonce = parseCookies(req.headers.cookie)[cookieName];
    return typeof nonce === 'string' && nonce.length > 0 && safeEqual(sha256Hex(nonce), nonceHash);
  };

  const redirectToClient = (res: Response, redirectUri: string, params: Record<string, string | null | undefined>) => {
    const url = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) if (v) url.searchParams.set(k, v);
    url.searchParams.set('iss', config.publicBaseUrl);
    noStore(res);
    res.redirect(303, url.toString());
  };

  const showError = (res: Response, status: number, message: string) => {
    noStore(res);
    res.status(status).type('html').send(errorPage(message));
  };

  // ---------------------------------------------------------------------------
  // Dynamic Client Registration (RFC 7591). Redirect URIs are restricted to an allowlist.
  router.post('/oauth/register', json, (req, res) => {
    noStore(res);
    const parsed = RegistrationSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_client_metadata', error_description: 'Invalid client metadata' });
      return;
    }
    const m = parsed.data;
    const badUri = m.redirect_uris.find((u) => !config.allowedRedirectUris.includes(u));
    if (badUri !== undefined) {
      // The URI is not secret; logging it lets the operator add the client's real redirect URI to ALLOWED_REDIRECT_URIS.
      logger.warn('DCR rejected: redirect URI not allowlisted', { redirect_uri: badUri.slice(0, 300) });
      store.audit({ event: 'client_register', outcome: 'rejected_redirect_uri' }, now());
      res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'redirect_uri is not allowed by this server' });
      return;
    }
    if (m.grant_types && !m.grant_types.every((g) => g === 'authorization_code' || g === 'refresh_token')) {
      res.status(400).json({ error: 'invalid_client_metadata', error_description: 'Unsupported grant_types' });
      return;
    }
    if (m.response_types && !m.response_types.every((r) => r === 'code')) {
      res.status(400).json({ error: 'invalid_client_metadata', error_description: 'Unsupported response_types' });
      return;
    }
    if (m.scope !== undefined && parseScope(m.scope) === null) {
      res.status(400).json({ error: 'invalid_client_metadata', error_description: 'Unsupported scope' });
      return;
    }
    if (store.countClients() >= MAX_CLIENTS && !store.evictStaleClient(now() - 3600_000)) {
      res.status(400).json({ error: 'invalid_client_metadata', error_description: 'Client registration limit reached' });
      return;
    }
    const method = m.token_endpoint_auth_method ?? 'client_secret_basic';
    const clientId = `mcp_${randomToken(16)}`;
    const clientSecret = method === 'none' ? undefined : randomToken(32);
    const issuedAt = Math.floor(now() / 1000);
    store.insertClient({
      client_id: clientId,
      client_secret_hash: clientSecret ? sha256Hex(clientSecret) : null,
      token_endpoint_auth_method: method,
      redirect_uris: JSON.stringify(m.redirect_uris),
      client_name: m.client_name ?? null,
      created_at: now(),
    });
    store.audit({ event: 'client_register', outcome: 'registered', client_id: clientId }, now());
    res.status(201).json({
      client_id: clientId,
      client_id_issued_at: issuedAt,
      ...(clientSecret ? { client_secret: clientSecret, client_secret_expires_at: 0 } : {}),
      client_name: m.client_name,
      redirect_uris: m.redirect_uris,
      token_endpoint_auth_method: method,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: MCP_SCOPE,
    });
  });

  // ---------------------------------------------------------------------------
  // Authorization endpoint: validate the request, then show the owner consent page.
  router.get('/oauth/authorize', (req, res) => {
    const q = req.query;
    const clientId = str(q.client_id);
    const client = clientId ? store.getClient(clientId) : undefined;
    if (!client) return showError(res, 400, 'Neznámy klient (client_id).');
    const registered = JSON.parse(client.redirect_uris) as string[];
    let redirectUri = str(q.redirect_uri);
    if (!redirectUri && registered.length === 1) redirectUri = registered[0];
    // Never redirect to an unregistered URI (open redirect protection).
    if (!redirectUri || !registered.includes(redirectUri)) return showError(res, 400, 'Neplatná redirect_uri.');

    const state = str(q.state);
    if (state && state.length > 2048) return showError(res, 400, 'Neplatný parameter state.');
    const fail = (error: string, description: string) => redirectToClient(res, redirectUri, { error, error_description: description, state });

    if (str(q.response_type) !== 'code') return fail('unsupported_response_type', 'Only response_type=code is supported');
    const challenge = str(q.code_challenge);
    if (!challenge || !PKCE_RE.test(challenge) || str(q.code_challenge_method) !== 'S256') {
      return fail('invalid_request', 'PKCE with code_challenge_method=S256 is required');
    }
    const scope = parseScope(str(q.scope));
    if (!scope) return fail('invalid_scope', 'Unsupported scope');
    const resource = normalizeResource(config, str(q.resource));
    if (!resource) return fail('invalid_target', 'Unknown resource');

    const id = randomToken(24);
    const browserNonce = randomToken(24);
    store.insertAuthRequest({
      id,
      client_id: client.client_id,
      redirect_uri: redirectUri,
      state: state ?? null,
      code_challenge: challenge,
      scope,
      resource,
      browser_nonce_hash: sha256Hex(browserNonce),
      google_state_hash: null,
      google_verifier_enc: null,
      expires_at: now() + AUTH_REQUEST_TTL_MS,
    });
    setBrowserCookie(res, browserNonce);
    noStore(res);
    res.type('html').send(consentPage({ requestId: id, clientName: client.client_name ?? client.client_id, redirectHost: new URL(redirectUri).host }));
  });

  // Consent submission: verify owner passphrase + browser binding, then continue to Google.
  router.post('/oauth/authorize', urlencoded, (req, res) => {
    const requestId = str(req.body?.request_id);
    const row = requestId ? store.getAuthRequest(requestId) : undefined;
    if (!row || row.expires_at < now()) return showError(res, 400, 'Žiadosť o autorizáciu vypršala. Spustite pripojenie znova.');
    if (!browserMatches(req, row.browser_nonce_hash)) return showError(res, 400, 'Žiadosť nepatrí tomuto prehliadaču.');

    if (str(req.body?.decision) !== 'approve') {
      store.deleteAuthRequest(row.id);
      store.audit({ event: 'authorize', outcome: 'denied_by_user', client_id: row.client_id }, now());
      clearBrowserCookie(res);
      return redirectToClient(res, row.redirect_uri, { error: 'access_denied', state: row.state });
    }

    const passphrase = str(req.body?.passphrase) ?? '';
    if (!safeEqual(passphrase, config.ownerPassphrase)) {
      store.audit({ event: 'authorize', outcome: 'bad_passphrase', client_id: row.client_id }, now());
      logger.warn('Consent rejected: wrong owner passphrase');
      const client = store.getClient(row.client_id);
      noStore(res);
      res.status(401).type('html').send(
        consentPage({ requestId: row.id, clientName: client?.client_name ?? row.client_id, redirectHost: new URL(row.redirect_uri).host, error: 'Nesprávna prístupová fráza.' }),
      );
      return;
    }

    const googleState = randomToken(32);
    const verifier = randomToken(48);
    store.setAuthRequestGoogleState(row.id, sha256Hex(googleState), encrypt(verifier, config.encryptionKey, PURPOSE_GOOGLE_VERIFIER));
    noStore(res);
    res.redirect(303, googleOAuth.buildAuthorizationUrl(googleState, sha256Base64Url(verifier)));
  });

  // Google redirects back here. Query string contains an authorization code: never log it.
  router.get('/oauth/google/callback', async (req, res) => {
    const googleState = str(req.query.state);
    const row = googleState ? store.takeAuthRequestByGoogleState(sha256Hex(googleState)) : undefined;
    if (!row || row.expires_at < now() || !row.google_verifier_enc) return showError(res, 400, 'Neplatný alebo expirovaný stav autorizácie.');
    if (!browserMatches(req, row.browser_nonce_hash)) return showError(res, 400, 'Žiadosť nepatrí tomuto prehliadaču.');
    clearBrowserCookie(res);

    if (str(req.query.error)) {
      store.audit({ event: 'authorize', outcome: 'google_denied', client_id: row.client_id }, now());
      return redirectToClient(res, row.redirect_uri, { error: 'access_denied', error_description: 'Google authorization was not granted', state: row.state });
    }
    const code = str(req.query.code);
    if (!code) return redirectToClient(res, row.redirect_uri, { error: 'invalid_request', state: row.state });

    let tokens;
    let sub: string;
    try {
      tokens = await googleOAuth.exchangeCode(code, decrypt(row.google_verifier_enc, config.encryptionKey, PURPOSE_GOOGLE_VERIFIER));
      sub = googleOAuth.subjectFromIdToken(tokens.id_token ?? '');
    } catch (err) {
      logger.warn('Google code exchange failed', { error: err instanceof Error ? err.message : 'unknown' });
      store.audit({ event: 'authorize', outcome: 'google_exchange_failed', client_id: row.client_id }, now());
      return redirectToClient(res, row.redirect_uri, { error: 'server_error', error_description: 'Google sign-in failed', state: row.state });
    }

    const revokeNew = () => googleOAuth.revoke(tokens.refresh_token ?? tokens.access_token);
    if (!tokens.scope.split(' ').includes(GOOGLE_TASKS_SCOPE)) {
      await revokeNew();
      store.audit({ event: 'authorize', outcome: 'tasks_scope_missing', client_id: row.client_id }, now());
      return redirectToClient(res, row.redirect_uri, { error: 'access_denied', error_description: 'Google Tasks permission was not granted', state: row.state });
    }
    const owner = credentials.ownerSubject();
    if (owner && owner !== sub) {
      await revokeNew();
      store.audit({ event: 'authorize', outcome: 'wrong_google_account', client_id: row.client_id }, now());
      logger.warn('Authorization rejected: Google account is not the bound owner');
      return redirectToClient(res, row.redirect_uri, { error: 'access_denied', error_description: 'This Google account is not authorized for this server', state: row.state });
    }
    try {
      credentials.save(sub, tokens);
    } catch (err) {
      logger.warn('Storing Google credentials failed', { error: err instanceof Error ? err.message : 'unknown' });
      return redirectToClient(res, row.redirect_uri, { error: 'server_error', error_description: 'Google did not return offline access', state: row.state });
    }

    const authCode = randomToken(32);
    store.insertAuthCode({
      code_hash: sha256Hex(authCode),
      client_id: row.client_id,
      redirect_uri: row.redirect_uri,
      code_challenge: row.code_challenge,
      scope: row.scope,
      resource: row.resource,
      family_id: randomToken(16),
      expires_at: now() + AUTH_CODE_TTL_MS,
      used: 0,
    });
    store.audit({ event: 'authorize', outcome: owner ? 'granted' : 'granted_owner_bound', client_id: row.client_id }, now());
    redirectToClient(res, row.redirect_uri, { code: authCode, state: row.state });
  });

  // ---------------------------------------------------------------------------
  const authenticateClient = (req: Request): ClientRow | null => {
    let clientId = str(req.body?.client_id);
    let secret = str(req.body?.client_secret);
    const header = req.headers.authorization;
    if (header?.startsWith('Basic ')) {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const i = decoded.indexOf(':');
      if (i > 0) {
        clientId = safeDecode(decoded.slice(0, i));
        secret = safeDecode(decoded.slice(i + 1));
      }
    }
    if (!clientId) return null;
    const client = store.getClient(clientId);
    if (!client) return null;
    if (client.token_endpoint_auth_method === 'none') return client;
    if (!secret || !client.client_secret_hash) return null;
    return safeEqual(sha256Hex(secret), client.client_secret_hash) ? client : null;
  };

  const issueTokens = (clientId: string, scope: string, resource: string, familyId: string) => {
    const accessToken = randomToken(32);
    const refreshToken = randomToken(32);
    const t = now();
    store.insertAccessToken({ token_hash: sha256Hex(accessToken), client_id: clientId, scope, resource, family_id: familyId, expires_at: t + ACCESS_TOKEN_TTL_S * 1000 });
    store.insertRefreshToken({ token_hash: sha256Hex(refreshToken), client_id: clientId, scope, resource, family_id: familyId, expires_at: t + REFRESH_TOKEN_TTL_MS });
    return { access_token: accessToken, token_type: 'Bearer', expires_in: ACCESS_TOKEN_TTL_S, refresh_token: refreshToken, scope };
  };

  const tokenError = (res: Response, status: number, error: string, description?: string) => {
    noStore(res);
    if (status === 401) res.set('WWW-Authenticate', 'Basic realm="oauth"');
    res.status(status).json({ error, ...(description ? { error_description: description } : {}) });
  };

  router.post('/oauth/token', urlencoded, (req, res) => {
    const client = authenticateClient(req);
    if (!client) return tokenError(res, 401, 'invalid_client');
    const grantType = str(req.body?.grant_type);

    if (grantType === 'authorization_code') {
      const code = str(req.body?.code);
      const verifier = str(req.body?.code_verifier);
      if (!code || !verifier) return tokenError(res, 400, 'invalid_request', 'code and code_verifier are required');
      const row = store.getAuthCode(sha256Hex(code));
      if (!row) return tokenError(res, 400, 'invalid_grant');
      if (!store.markAuthCodeUsed(row.code_hash)) {
        // Code replay: revoke everything issued from it (RFC 6749 §4.1.2).
        store.revokeFamily(row.family_id);
        store.audit({ event: 'token', outcome: 'code_replay', client_id: client.client_id }, now());
        return tokenError(res, 400, 'invalid_grant');
      }
      if (row.expires_at < now() || row.client_id !== client.client_id) return tokenError(res, 400, 'invalid_grant');
      const redirectUri = str(req.body?.redirect_uri);
      if (redirectUri !== undefined && redirectUri !== row.redirect_uri) return tokenError(res, 400, 'invalid_grant');
      if (!PKCE_RE.test(verifier) || !safeEqual(sha256Base64Url(verifier), row.code_challenge)) return tokenError(res, 400, 'invalid_grant', 'PKCE verification failed');
      const resource = normalizeResource(config, str(req.body?.resource));
      if (resource !== row.resource) return tokenError(res, 400, 'invalid_target');
      if (!credentials.isConnected()) return tokenError(res, 400, 'invalid_grant');
      store.audit({ event: 'token', outcome: 'issued', client_id: client.client_id }, now());
      noStore(res);
      res.json(issueTokens(client.client_id, row.scope, row.resource, row.family_id));
      return;
    }

    if (grantType === 'refresh_token') {
      const token = str(req.body?.refresh_token);
      if (!token) return tokenError(res, 400, 'invalid_request');
      const row = store.getRefreshToken(sha256Hex(token));
      if (!row || row.client_id !== client.client_id) return tokenError(res, 400, 'invalid_grant');
      if (row.rotated || !store.markRefreshTokenRotated(row.token_hash)) {
        // Refresh token reuse: assume theft and revoke the whole token family.
        store.revokeFamily(row.family_id);
        store.audit({ event: 'token', outcome: 'refresh_reuse_detected', client_id: client.client_id }, now());
        return tokenError(res, 400, 'invalid_grant');
      }
      if (row.expires_at < now()) return tokenError(res, 400, 'invalid_grant');
      const scope = str(req.body?.scope);
      if (scope !== undefined && parseScope(scope) !== row.scope) return tokenError(res, 400, 'invalid_scope');
      const resource = normalizeResource(config, str(req.body?.resource));
      if (resource !== row.resource) return tokenError(res, 400, 'invalid_target');
      if (!credentials.isConnected()) return tokenError(res, 400, 'invalid_grant');
      noStore(res);
      res.json(issueTokens(client.client_id, row.scope, row.resource, row.family_id));
      return;
    }

    tokenError(res, 400, 'unsupported_grant_type');
  });

  // Token revocation (RFC 7009). Always 200 so token validity is not disclosed.
  router.post('/oauth/revoke', urlencoded, (req, res) => {
    const client = authenticateClient(req);
    if (!client) return tokenError(res, 401, 'invalid_client');
    const token = str(req.body?.token);
    if (token) {
      const hash = sha256Hex(token);
      const row = store.getAccessToken(hash) ?? store.getRefreshToken(hash);
      if (row && row.client_id === client.client_id) {
        store.revokeFamily(row.family_id);
        store.audit({ event: 'revoke', outcome: 'revoked', client_id: client.client_id }, now());
      }
    }
    noStore(res);
    res.status(200).end();
  });

  return router;
}

/** Validates MCP bearer tokens issued by this server. Raw tokens are never stored or placed in AuthInfo. */
export function createTokenVerifier(store: Store, credentials: Pick<GoogleCredentials, 'isConnected'>, now: () => number = Date.now): OAuthTokenVerifier {
  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      const hash = sha256Hex(token);
      const row = store.getAccessToken(hash);
      if (!row || row.expires_at <= now()) throw new OAuthError(OAuthErrorCode.InvalidToken, 'Invalid or expired access token');
      if (!credentials.isConnected()) throw new OAuthError(OAuthErrorCode.InvalidToken, 'Google account disconnected');
      return {
        token: `sha256:${hash.slice(0, 16)}`,
        clientId: row.client_id,
        scopes: row.scope.split(' '),
        expiresAt: Math.floor(row.expires_at / 1000),
        resource: new URL(row.resource),
      };
    },
  };
}
