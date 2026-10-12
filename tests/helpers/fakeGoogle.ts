import type { GoogleTask } from '../../src/google/tasksClient.js';

function b64url(obj: object): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

export interface FakeGoogleOptions {
  clientId: string;
  sub?: string;
  now: () => number;
}

/**
 * In-memory stand-in for Google's OAuth and Tasks API endpoints, exposed as a `fetch` implementation.
 * No real Google account is ever contacted by the tests.
 */
export class FakeGoogle {
  sub: string;
  grantedScope = 'openid https://www.googleapis.com/auth/tasks';
  accessTokenCounter = 0;
  validAccessTokens = new Set<string>();
  refreshToken = 'google-refresh-token-SECRET-1//abcdefghijklmnop';
  refreshRevoked = false;
  revokedTokens: string[] = [];
  requests: { method: string; url: string; auth?: string; body?: string }[] = [];
  lists = [
    { id: 'list-school', title: 'Škola' },
    { id: 'list-personal', title: 'Osobné' },
  ];
  tasks = new Map<string, Map<string, GoogleTask>>([
    ['list-school', new Map()],
    ['list-personal', new Map()],
  ]);
  private idCounter = 0;
  pendingCodes = new Map<string, string>(); // google code -> code_challenge

  constructor(private readonly opts: FakeGoogleOptions) {
    this.sub = opts.sub ?? 'google-sub-owner-123';
  }

  issueAccessToken(): string {
    const t = `ya29.fake-google-access-${++this.accessTokenCounter}`;
    this.validAccessTokens.add(t);
    return t;
  }

  idToken(sub = this.sub): string {
    return `${b64url({ alg: 'RS256' })}.${b64url({ iss: 'https://accounts.google.com', aud: this.opts.clientId, sub, exp: Math.floor(this.opts.now() / 1000) + 3600 })}.sig`;
  }

  get taskCount(): number {
    let n = 0;
    for (const m of this.tasks.values()) n += m.size;
    return n;
  }

  fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    const method = (init?.method ?? 'GET').toUpperCase();
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === 'string' ? init.body : undefined;
    this.requests.push({ method, url: url.href, auth: headers.get('authorization') ?? undefined, body });

    const json = (status: number, obj: unknown) => new Response(obj === undefined ? null : JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } });

    if (url.origin === 'https://oauth2.googleapis.com' && url.pathname === '/token') {
      const p = new URLSearchParams(body);
      if (p.get('client_id') !== this.opts.clientId) return json(401, { error: 'invalid_client' });
      if (p.get('grant_type') === 'authorization_code') {
        if (!this.pendingCodes.has(p.get('code') ?? '')) return json(400, { error: 'invalid_grant' });
        this.pendingCodes.delete(p.get('code') ?? '');
        return json(200, { access_token: this.issueAccessToken(), expires_in: 3599, refresh_token: this.refreshToken, scope: this.grantedScope, token_type: 'Bearer', id_token: this.idToken() });
      }
      if (p.get('grant_type') === 'refresh_token') {
        if (this.refreshRevoked || p.get('refresh_token') !== this.refreshToken) return json(400, { error: 'invalid_grant' });
        return json(200, { access_token: this.issueAccessToken(), expires_in: 3599, scope: this.grantedScope, token_type: 'Bearer' });
      }
      return json(400, { error: 'unsupported_grant_type' });
    }
    if (url.origin === 'https://oauth2.googleapis.com' && url.pathname === '/revoke') {
      const token = new URLSearchParams(body).get('token') ?? '';
      this.revokedTokens.push(token);
      if (token === this.refreshToken) this.refreshRevoked = true;
      this.validAccessTokens.clear();
      return json(200, {});
    }

    if (url.origin !== 'https://tasks.googleapis.com') return json(404, { error: 'unknown host' });
    const auth = headers.get('authorization')?.replace(/^Bearer /, '') ?? '';
    if (!this.validAccessTokens.has(auth)) return json(401, { error: { status: 'UNAUTHENTICATED' } });

    const path = url.pathname.replace('/tasks/v1', '');
    if (path === '/users/@me/lists' && method === 'GET') return json(200, { items: this.lists });

    const m = /^\/lists\/([^/]+)\/tasks(?:\/([^/]+))?$/.exec(path);
    if (!m) return json(404, { error: { status: 'NOT_FOUND' } });
    const listId = decodeURIComponent(m[1] as string) === '@default' ? 'list-school' : decodeURIComponent(m[1] as string);
    const list = this.tasks.get(listId);
    if (!list) return json(404, { error: { status: 'NOT_FOUND', errors: [{ reason: 'notFound' }] } });
    const taskId = m[2] ? decodeURIComponent(m[2]) : undefined;

    if (!taskId && method === 'GET') {
      const showCompleted = url.searchParams.get('showCompleted') !== 'false';
      const max = Number(url.searchParams.get('maxResults') ?? 20);
      const start = Number(url.searchParams.get('pageToken') ?? 0);
      let items = [...list.values()].filter((t) => showCompleted || t.status !== 'completed');
      const dueMin = url.searchParams.get('dueMin');
      const dueMax = url.searchParams.get('dueMax');
      if (dueMin) items = items.filter((t) => t.due && t.due >= dueMin);
      if (dueMax) items = items.filter((t) => t.due && t.due <= dueMax);
      const page = items.slice(start, start + max);
      return json(200, { items: page, ...(start + max < items.length ? { nextPageToken: String(start + max) } : {}) });
    }
    if (!taskId && method === 'POST') {
      const input = JSON.parse(body ?? '{}') as GoogleTask;
      const id = `task${++this.idCounter}`;
      const task: GoogleTask = {
        id,
        title: input.title,
        notes: input.notes,
        status: 'needsAction',
        // Google keeps only the date part of `due`.
        due: input.due ? `${input.due.slice(0, 10)}T00:00:00.000Z` : undefined,
        updated: new Date(this.opts.now()).toISOString(),
        webViewLink: `https://tasks.google.com/task/${id}`,
      };
      list.set(id, task);
      return json(200, task);
    }
    const task = taskId ? list.get(taskId) : undefined;
    if (!task) return json(404, { error: { status: 'NOT_FOUND', errors: [{ reason: 'notFound' }] } });
    if (method === 'GET') return json(200, task);
    if (method === 'PATCH') {
      const patch = JSON.parse(body ?? '{}') as Record<string, unknown>;
      for (const [k, v] of Object.entries(patch)) {
        if (v === null) delete (task as unknown as Record<string, unknown>)[k];
        else (task as unknown as Record<string, unknown>)[k] = k === 'due' ? `${String(v).slice(0, 10)}T00:00:00.000Z` : v;
      }
      if (patch.status === 'completed') task.completed = new Date(this.opts.now()).toISOString();
      task.updated = new Date(this.opts.now()).toISOString();
      return json(200, task);
    }
    if (method === 'DELETE') {
      list.delete(task.id);
      return new Response(null, { status: 204 });
    }
    return json(405, {});
  };
}
