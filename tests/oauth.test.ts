import { randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { authorize, CHATGPT_REDIRECT, callTool, connect, type Harness, mcp, registerClient, startHarness, tokenRequest } from './helpers/harness.js';

let h: Harness;
beforeEach(async () => {
  h = await startHarness();
});
afterEach(async () => {
  await h.close();
});

describe('discovery metadata', () => {
  it('serves protected resource and authorization server metadata without wildcard CORS', async () => {
    const prm = await h.request('/.well-known/oauth-protected-resource/mcp');
    expect(prm.status).toBe(200);
    expect(prm.headers.get('access-control-allow-origin')).toBeNull();
    expect(await prm.json()).toMatchObject({ resource: `${h.baseUrl}/mcp`, authorization_servers: [h.baseUrl], scopes_supported: ['tasks'] });

    const as = (await (await h.request('/.well-known/oauth-authorization-server')).json()) as Record<string, unknown>;
    expect(as).toMatchObject({
      issuer: h.baseUrl,
      authorization_endpoint: `${h.baseUrl}/oauth/authorize`,
      token_endpoint: `${h.baseUrl}/oauth/token`,
      registration_endpoint: `${h.baseUrl}/oauth/register`,
      code_challenge_methods_supported: ['S256'],
    });
  });
});

describe('acceptance 7: unauthorized requests are rejected', () => {
  it('rejects /mcp without a token with a discoverable challenge', async () => {
    const r = await mcp(h, null, 'tools/list');
    expect(r.status).toBe(401);
    expect(r.headers.get('www-authenticate')).toContain(`resource_metadata="${h.baseUrl}/.well-known/oauth-protected-resource/mcp"`);
  });
  it('rejects unknown and forged tokens', async () => {
    expect((await mcp(h, 'not-a-real-token', 'tools/list')).status).toBe(401);
    expect((await callTool(h, randomBytes(32).toString('base64url'), 'list_task_lists', {})).status).toBe(401);
  });
  it('rejects expired access tokens', async () => {
    const c = await connect(h);
    expect((await mcp(h, c.accessToken, 'tools/list')).status).toBe(200);
    h.advance(3601_000);
    expect((await mcp(h, c.accessToken, 'tools/list')).status).toBe(401);
  });
  it('rejects requests with a foreign Host header (DNS rebinding)', async () => {
    const port = new URL(h.baseUrl).port;
    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest({ host: '127.0.0.1', port, path: '/healthz', headers: { host: 'evil.example' } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on('error', reject);
      req.end();
    });
    expect(status).toBe(403);
  });
});

describe('dynamic client registration', () => {
  it('only allows allowlisted redirect URIs', async () => {
    const res = await h.request('/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['https://attacker.example/cb'], token_endpoint_auth_method: 'none' }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_redirect_uri' });
  });
  it('issues a secret only for confidential clients', async () => {
    expect((await registerClient(h, 'none')).client_secret).toBeUndefined();
    expect((await registerClient(h, 'client_secret_post')).client_secret).toBeTruthy();
  });
});

describe('acceptance 1: OAuth login', () => {
  it('completes the full flow with PKCE, minimal Google scopes and owner binding', async () => {
    const client = await registerClient(h);
    const verifier = randomBytes(40).toString('base64url');
    const { googleUrl, final } = await authorize(h, client.client_id, { verifier, state: 'st-123' });

    // Google request: minimal scopes, PKCE, offline access, our callback.
    expect(googleUrl?.origin).toBe('https://accounts.google.com');
    expect(googleUrl?.searchParams.get('scope')).toBe('openid https://www.googleapis.com/auth/tasks');
    expect(googleUrl?.searchParams.get('scope')).not.toMatch(/gmail|drive|calendar/);
    expect(googleUrl?.searchParams.get('code_challenge_method')).toBe('S256');
    expect(googleUrl?.searchParams.get('access_type')).toBe('offline');
    expect(googleUrl?.searchParams.get('redirect_uri')).toBe(`${h.baseUrl}/oauth/google/callback`);

    // Back to the MCP client with code, original state and issuer.
    expect(`${final?.origin}${final?.pathname}`).toBe(CHATGPT_REDIRECT);
    expect(final?.searchParams.get('state')).toBe('st-123');
    expect(final?.searchParams.get('iss')).toBe(h.baseUrl);
    const code = final?.searchParams.get('code') as string;

    // Wrong PKCE verifier fails.
    const bad = await tokenRequest(h, { grant_type: 'authorization_code', code, code_verifier: randomBytes(40).toString('base64url'), client_id: client.client_id, redirect_uri: CHATGPT_REDIRECT });
    expect(bad.status).toBe(400);
    // The code was consumed by the failed attempt; replay is rejected.
    const replay = await tokenRequest(h, { grant_type: 'authorization_code', code, code_verifier: verifier, client_id: client.client_id, redirect_uri: CHATGPT_REDIRECT });
    expect(replay.body.error).toBe('invalid_grant');

    // Google credentials are stored encrypted, never in plaintext.
    const row = h.store.getGoogleAccount();
    expect(row?.google_sub).toBe('google-sub-owner-123');
    expect(row?.refresh_token_enc).not.toContain(h.google.refreshToken);
    const dump = JSON.stringify(h.store.db.prepare('SELECT * FROM google_account').all());
    expect(dump).not.toContain(h.google.refreshToken);
    expect(dump).not.toContain('ya29.');
  });

  it('rejects a wrong owner passphrase', async () => {
    const client = await registerClient(h);
    const { consent } = await authorize(h, client.client_id, { verifier: randomBytes(40).toString('base64url'), passphrase: 'wrong passphrase value!!' });
    expect(consent.status).toBe(401);
    expect(h.store.getGoogleAccount()).toBeUndefined();
  });

  it('rejects consent from a different browser (CSRF / session binding)', async () => {
    const client = await registerClient(h);
    const q = new URLSearchParams({
      response_type: 'code', client_id: client.client_id, redirect_uri: CHATGPT_REDIRECT,
      code_challenge: 'a'.repeat(43), code_challenge_method: 'S256', state: 's',
    });
    const page = await h.request(`/oauth/authorize?${q}`);
    const requestId = /name="request_id" value="([^"]+)"/.exec(await page.text())?.[1] as string;
    const res = await h.request('/oauth/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: 'gtm_auth=attacker' },
      body: new URLSearchParams({ request_id: requestId, passphrase: 'x', decision: 'approve' }).toString(),
    });
    expect(res.status).toBe(400);
  });

  it('never redirects to an unregistered redirect_uri and requires PKCE', async () => {
    const client = await registerClient(h);
    const base = { response_type: 'code', client_id: client.client_id, code_challenge_method: 'S256', code_challenge: 'a'.repeat(43) };
    const evil = await h.request(`/oauth/authorize?${new URLSearchParams({ ...base, redirect_uri: 'https://attacker.example/cb' })}`);
    expect(evil.status).toBe(400);
    expect(evil.headers.get('location')).toBeNull();

    const noPkce = await h.request(`/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: CHATGPT_REDIRECT })}`);
    expect(noPkce.status).toBe(303);
    expect(new URL(noPkce.headers.get('location') as string).searchParams.get('error')).toBe('invalid_request');

    const plain = await h.request(`/oauth/authorize?${new URLSearchParams({ ...base, redirect_uri: CHATGPT_REDIRECT, code_challenge_method: 'plain' })}`);
    expect(new URL(plain.headers.get('location') as string).searchParams.get('error')).toBe('invalid_request');

    const foreign = await h.request(`/oauth/authorize?${new URLSearchParams({ ...base, redirect_uri: CHATGPT_REDIRECT, resource: 'https://other.example/mcp' })}`);
    expect(new URL(foreign.headers.get('location') as string).searchParams.get('error')).toBe('invalid_target');
  });

  it('restricts access to the bound Google account', async () => {
    await connect(h);
    const client = await registerClient(h);
    const { final } = await authorize(h, client.client_id, { verifier: randomBytes(40).toString('base64url'), googleSub: 'someone-else-999' });
    expect(final?.searchParams.get('error')).toBe('access_denied');
    expect(final?.searchParams.get('code')).toBeNull();
    expect(h.store.getGoogleAccount()?.google_sub).toBe('google-sub-owner-123');
    expect(h.google.revokedTokens.length).toBe(1); // the foreign grant was revoked immediately
  });

  it('rejects the grant if the user unticks the Google Tasks permission', async () => {
    h.google.grantedScope = 'openid';
    const client = await registerClient(h);
    const { final } = await authorize(h, client.client_id, { verifier: randomBytes(40).toString('base64url') });
    expect(final?.searchParams.get('error')).toBe('access_denied');
    expect(h.store.getGoogleAccount()).toBeUndefined();
  });
});

describe('token refresh and revocation', () => {
  it('rotates refresh tokens and revokes the family on reuse', async () => {
    const c = await connect(h);
    const r1 = await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: c.refreshToken, client_id: c.clientId });
    expect(r1.status).toBe(200);
    expect(r1.body.refresh_token).not.toBe(c.refreshToken);
    expect((await mcp(h, r1.body.access_token as string, 'tools/list')).status).toBe(200);

    // Replaying the old refresh token is treated as theft: the whole family is revoked.
    const replay = await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: c.refreshToken, client_id: c.clientId });
    expect(replay.body.error).toBe('invalid_grant');
    expect((await mcp(h, r1.body.access_token as string, 'tools/list')).status).toBe(401);
    expect((await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: r1.body.refresh_token as string, client_id: c.clientId })).status).toBe(400);
  });

  it('supports RFC 7009 revocation', async () => {
    const c = await connect(h);
    const res = await h.request('/oauth/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: c.accessToken, client_id: c.clientId }).toString(),
    });
    expect(res.status).toBe(200);
    expect((await mcp(h, c.accessToken, 'tools/list')).status).toBe(401);
  });

  it('refreshes the Google access token transparently', async () => {
    const c = await connect(h);
    const before = h.google.accessTokenCounter;
    h.advance(59.5 * 60_000); // Google token (3599 s) is within the refresh skew; MCP token (3600 s) still valid
    const r = await callTool(h, c.accessToken, 'list_task_lists', {});
    expect(r.result?.isError).toBeFalsy();
    expect(h.google.accessTokenCounter).toBe(before + 1);
  });
});

describe('acceptance 9: disconnection', () => {
  it('revokes at Google, deletes credentials and invalidates all MCP tokens', async () => {
    const c = await connect(h);
    const result = await h.credentials.disconnect();
    expect(result).toEqual({ googleRevoked: true, hadAccount: true });
    expect(h.google.revokedTokens).toContain(h.google.refreshToken);
    expect(h.store.getGoogleAccount()).toBeUndefined();
    expect((await mcp(h, c.accessToken, 'tools/list')).status).toBe(401);
    expect((await tokenRequest(h, { grant_type: 'refresh_token', refresh_token: c.refreshToken, client_id: c.clientId })).status).toBe(400);
  });

  it('detects a grant revoked at Google and disconnects locally', async () => {
    const c = await connect(h);
    h.google.refreshRevoked = true;
    h.google.validAccessTokens.clear();
    const r = await callTool(h, c.accessToken, 'list_task_lists', {});
    expect(r.result?.isError).toBe(true);
    expect(r.text).toMatch(/not connected/i);
    expect(h.store.getGoogleAccount()).toBeUndefined();
    expect((await mcp(h, c.accessToken, 'tools/list')).status).toBe(401);
  });
});

describe('rate limiting', () => {
  it('limits consent submissions', async () => {
    let last = 0;
    for (let i = 0; i < 11; i++) {
      const r = await h.request('/oauth/authorize', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'request_id=x' });
      last = r.status;
    }
    expect(last).toBe(429);
  });
});

describe('robustness', () => {
  it('answers malformed bodies with 400 without logging their content', async () => {
    const res = await h.request('/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"redirect_uris": SECRET-IN-BODY' });
    expect(res.status).toBe(400);
    const basic = await h.request('/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${Buffer.from('%E0%A4%A:%zz').toString('base64')}` },
      body: 'grant_type=refresh_token&refresh_token=x',
    });
    expect(basic.status).toBe(401);
    expect(h.logs.join('\n')).not.toContain('SECRET-IN-BODY');
  });

  it('evicts stale unused clients when the registration cap is reached', async () => {
    for (let i = 0; i < 50; i++) h.store.insertClient({ client_id: `spam${i}`, client_secret_hash: null, token_endpoint_auth_method: 'none', redirect_uris: '[]', client_name: null, created_at: Date.now() });
    const blocked = await h.request('/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: [CHATGPT_REDIRECT], token_endpoint_auth_method: 'none' }) });
    expect(blocked.status).toBe(400);
    h.advance(2 * 3600_000);
    expect((await registerClient(h)).client_id).toMatch(/^mcp_/);
  });
});
