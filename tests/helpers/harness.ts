import { createHash, randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { createServer, type Server } from 'node:http';
import { vi } from 'vitest';
import { createApp } from '../../src/app.js';
import { type Config, loadConfig } from '../../src/config.js';
import { Store } from '../../src/db.js';
import type { GoogleCredentials } from '../../src/google/credentials.js';
import { createLogger } from '../../src/logger.js';
import { FakeGoogle } from './fakeGoogle.js';

export const OWNER_PASSPHRASE = 'correct horse battery staple 2026';
export const CHATGPT_REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';
const GOOGLE_CLIENT_ID = 'test-client-id.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = 'GOCSPX-test-google-client-secret';

async function freePort(): Promise<number> {
  const srv = createServer();
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const port = (srv.address() as AddressInfo).port;
  await new Promise<void>((r) => srv.close(() => r()));
  return port;
}

export interface Harness {
  baseUrl: string;
  config: Config;
  store: Store;
  google: FakeGoogle;
  credentials: GoogleCredentials;
  logs: string[];
  /** Every HTTP response body seen by tests (for leak assertions). */
  responses: string[];
  /** Moves the (fake) system clock forward. */
  advance(ms: number): void;
  /** Secrets that must never appear in logs or tool responses. */
  secrets: Set<string>;
  request(path: string, init?: RequestInit): Promise<Response>;
  close(): Promise<void>;
}

export async function startHarness(opts: { now?: string } = {}): Promise<Harness> {
  const port = await freePort();
  const baseUrl = `http://localhost:${port}`;
  // Fake only Date (not timers) so token expiry checks inside the MCP SDK see the same clock as our code.
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(new Date(opts.now ?? '2026-10-05T08:00:00Z'));
  const now = () => Date.now();
  const config = loadConfig({
    PUBLIC_BASE_URL: baseUrl,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    TOKEN_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    OWNER_PASSPHRASE,
    DATABASE_PATH: ':memory:',
    ALLOW_INSECURE_HTTP: 'true',
    TIMEZONE: 'Europe/Bratislava',
    TRUST_PROXY_HOPS: '0',
    LOG_LEVEL: 'debug',
  });
  const store = new Store(':memory:');
  const logs: string[] = [];
  const logger = createLogger('debug', (l) => logs.push(l));
  const google = new FakeGoogle({ clientId: GOOGLE_CLIENT_ID, now });
  const { app, credentials } = createApp({ config, store, logger, fetchFn: google.fetch as typeof fetch, now });
  const server: Server = await new Promise((resolve) => {
    const s = app.listen(port, '127.0.0.1', () => resolve(s));
  });
  const responses: string[] = [];
  const secrets = new Set<string>([OWNER_PASSPHRASE, GOOGLE_CLIENT_SECRET, google.refreshToken]);

  return {
    baseUrl,
    config,
    store,
    google,
    credentials,
    logs,
    responses,
    advance(ms) {
      vi.setSystemTime(new Date(Date.now() + ms));
    },
    secrets,
    async request(path, init) {
      const res = await fetch(`${baseUrl}${path}`, { redirect: 'manual', ...init });
      const text = await res.clone().text();
      responses.push(text);
      return res;
    },
    async close() {
      await new Promise<void>((r) => server.close(() => r()));
      store.close();
      vi.useRealTimers();
    },
  };
}

function b64urlSha256(s: string): string {
  return createHash('sha256').update(s).digest('base64url');
}

export interface ConnectedClient {
  clientId: string;
  clientSecret?: string;
  accessToken: string;
  refreshToken: string;
}

export async function registerClient(h: Harness, authMethod: 'none' | 'client_secret_post' = 'none') {
  const res = await h.request('/oauth/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'ChatGPT', redirect_uris: [CHATGPT_REDIRECT], token_endpoint_auth_method: authMethod }),
  });
  if (res.status !== 201) throw new Error(`register failed ${res.status}`);
  const body = (await res.json()) as { client_id: string; client_secret?: string };
  if (body.client_secret) h.secrets.add(body.client_secret);
  return body;
}

/** Runs the authorization flow up to the redirect back to the MCP client. Returns the final redirect URL. */
export async function authorize(h: Harness, clientId: string, opts: { verifier: string; state?: string; googleSub?: string; passphrase?: string }) {
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: CHATGPT_REDIRECT,
    code_challenge: b64urlSha256(opts.verifier),
    code_challenge_method: 'S256',
    state: opts.state ?? 'client-state-xyz',
    scope: 'tasks',
    resource: `${h.baseUrl}/mcp`,
  });
  const page = await h.request(`/oauth/authorize?${q}`);
  if (page.status !== 200) throw new Error(`authorize page ${page.status}`);
  const cookie = (page.headers.get('set-cookie') ?? '').split(';')[0] as string;
  const html = await page.text();
  const requestId = /name="request_id" value="([^"]+)"/.exec(html)?.[1] as string;

  const consent = await h.request('/oauth/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ request_id: requestId, passphrase: opts.passphrase ?? OWNER_PASSPHRASE, decision: 'approve' }).toString(),
  });
  if (consent.status !== 303) return { consent, cookie, requestId };
  const googleUrl = new URL(consent.headers.get('location') as string);

  // Simulate the user approving at Google: Google redirects back with a code.
  const googleCode = `gcode-${randomBytes(8).toString('hex')}`;
  h.secrets.add(googleCode);
  h.google.pendingCodes.set(googleCode, googleUrl.searchParams.get('code_challenge') as string);
  if (opts.googleSub) h.google.sub = opts.googleSub;
  const cb = await h.request(`/oauth/google/callback?${new URLSearchParams({ state: googleUrl.searchParams.get('state') as string, code: googleCode })}`, {
    headers: { cookie },
  });
  const final = new URL(cb.headers.get('location') as string);
  const code = final.searchParams.get('code');
  if (code) h.secrets.add(code);
  return { consent, cookie, requestId, googleUrl, callback: cb, final };
}

export async function tokenRequest(h: Harness, params: Record<string, string>) {
  const res = await h.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  const body = (await res.json()) as Record<string, string>;
  if (body.access_token) h.secrets.add(body.access_token);
  if (body.refresh_token) h.secrets.add(body.refresh_token);
  return { status: res.status, body };
}

export async function connect(h: Harness): Promise<ConnectedClient> {
  const client = await registerClient(h);
  const verifier = randomBytes(40).toString('base64url');
  const { final } = await authorize(h, client.client_id, { verifier });
  const code = final?.searchParams.get('code');
  if (!code) throw new Error(`no code: ${final?.href}`);
  const tok = await tokenRequest(h, { grant_type: 'authorization_code', code, code_verifier: verifier, client_id: client.client_id, redirect_uri: CHATGPT_REDIRECT, resource: `${h.baseUrl}/mcp` });
  if (tok.status !== 200) throw new Error(`token failed ${JSON.stringify(tok.body)}`);
  for (const t of h.google.validAccessTokens) h.secrets.add(t);
  return { clientId: client.client_id, accessToken: tok.body.access_token as string, refreshToken: tok.body.refresh_token as string };
}

let rpcId = 0;

/** Sends one JSON-RPC request to /mcp and returns the parsed JSON-RPC response (handles JSON and SSE framing). */
export async function mcp(h: Harness, accessToken: string | null, method: string, params: Record<string, unknown> = {}) {
  const res = await h.request('/mcp', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': '2025-06-18',
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }),
  });
  const text = await res.text();
  let message: Record<string, unknown> | undefined;
  if (res.headers.get('content-type')?.includes('text/event-stream')) {
    const data = text
      .split('\n')
      .filter((l) => l.startsWith('data: '))
      .map((l) => l.slice(6));
    message = data.length ? (JSON.parse(data[data.length - 1] as string) as Record<string, unknown>) : undefined;
  } else if (text) {
    message = JSON.parse(text) as Record<string, unknown>;
  }
  return { status: res.status, headers: res.headers, message };
}

export async function callTool(h: Harness, accessToken: string, name: string, args: Record<string, unknown>) {
  const r = await mcp(h, accessToken, 'tools/call', { name, arguments: args });
  const result = r.message?.result as { isError?: boolean; structuredContent?: Record<string, unknown>; content?: { text: string }[] } | undefined;
  return { ...r, result, data: result?.structuredContent as Record<string, any> | undefined, text: result?.content?.[0]?.text ?? '' };
}
