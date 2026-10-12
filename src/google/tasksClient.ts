import type { GoogleCredentials } from './credentials.js';
import type { FetchFn } from './oauth.js';

// Fixed API base URL. IDs are validated by the tool schemas and URL-encoded here (SSRF / path injection protection).
export const TASKS_API_BASE = 'https://tasks.googleapis.com/tasks/v1';

export interface GoogleTaskList {
  id: string;
  title: string;
  updated?: string;
}

export interface GoogleTask {
  id: string;
  title?: string;
  notes?: string;
  status?: 'needsAction' | 'completed';
  due?: string;
  completed?: string;
  updated?: string;
  deleted?: boolean;
  hidden?: boolean;
  parent?: string;
  webViewLink?: string;
}

export interface Page<T> {
  items: T[];
  nextPageToken?: string;
}

export interface ListTasksParams {
  showCompleted?: boolean;
  showHidden?: boolean;
  dueMin?: string;
  dueMax?: string;
  maxResults?: number;
  pageToken?: string;
}

export class GoogleApiError extends Error {
  constructor(
    readonly status: number,
    readonly reason: string,
  ) {
    super(`Google Tasks API error ${status}: ${reason}`);
    this.name = 'GoogleApiError';
  }
}

export interface TasksApi {
  listTaskLists(pageToken?: string, maxResults?: number): Promise<Page<GoogleTaskList>>;
  listTasks(tasklistId: string, params: ListTasksParams): Promise<Page<GoogleTask>>;
  getTask(tasklistId: string, taskId: string): Promise<GoogleTask>;
  insertTask(tasklistId: string, task: Partial<GoogleTask>): Promise<GoogleTask>;
  patchTask(tasklistId: string, taskId: string, patch: Partial<GoogleTask> & Record<string, unknown>): Promise<GoogleTask>;
  deleteTask(tasklistId: string, taskId: string): Promise<void>;
}

export class GoogleTasksClient implements TasksApi {
  constructor(
    private readonly credentials: Pick<GoogleCredentials, 'getAccessToken'>,
    private readonly fetchFn: FetchFn = fetch,
  ) {}

  async listTaskLists(pageToken?: string, maxResults = 100): Promise<Page<GoogleTaskList>> {
    const q = new URLSearchParams({ maxResults: String(maxResults) });
    if (pageToken) q.set('pageToken', pageToken);
    const body = (await this.request('GET', `/users/@me/lists?${q}`)) as { items?: GoogleTaskList[]; nextPageToken?: string };
    return { items: body.items ?? [], nextPageToken: body.nextPageToken };
  }

  async listTasks(tasklistId: string, p: ListTasksParams): Promise<Page<GoogleTask>> {
    const q = new URLSearchParams();
    q.set('maxResults', String(p.maxResults ?? 100));
    q.set('showCompleted', String(p.showCompleted ?? true));
    q.set('showHidden', String(p.showHidden ?? false));
    if (p.dueMin) q.set('dueMin', p.dueMin);
    if (p.dueMax) q.set('dueMax', p.dueMax);
    if (p.pageToken) q.set('pageToken', p.pageToken);
    const body = (await this.request('GET', `/lists/${enc(tasklistId)}/tasks?${q}`)) as { items?: GoogleTask[]; nextPageToken?: string };
    return { items: body.items ?? [], nextPageToken: body.nextPageToken };
  }

  async getTask(tasklistId: string, taskId: string): Promise<GoogleTask> {
    return (await this.request('GET', `/lists/${enc(tasklistId)}/tasks/${enc(taskId)}`)) as GoogleTask;
  }

  async insertTask(tasklistId: string, task: Partial<GoogleTask>): Promise<GoogleTask> {
    return (await this.request('POST', `/lists/${enc(tasklistId)}/tasks`, task)) as GoogleTask;
  }

  async patchTask(tasklistId: string, taskId: string, patch: Partial<GoogleTask> & Record<string, unknown>): Promise<GoogleTask> {
    return (await this.request('PATCH', `/lists/${enc(tasklistId)}/tasks/${enc(taskId)}`, patch)) as GoogleTask;
  }

  async deleteTask(tasklistId: string, taskId: string): Promise<void> {
    await this.request('DELETE', `/lists/${enc(tasklistId)}/tasks/${enc(taskId)}`);
  }

  private async request(method: string, path: string, body?: unknown, retried = false): Promise<unknown> {
    const token = await this.credentials.getAccessToken(retried);
    let res: Response;
    try {
      res = await this.fetchFn(`${TASKS_API_BASE}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          accept: 'application/json',
          ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        redirect: 'error',
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      throw new GoogleApiError(0, 'network_error');
    }
    if (res.status === 401 && !retried) {
      return this.request(method, path, body, true);
    }
    if (!res.ok) {
      let reason = `http_${res.status}`;
      try {
        const err = (await res.json()) as { error?: { status?: string; errors?: { reason?: string }[] } };
        reason = err.error?.errors?.[0]?.reason ?? err.error?.status ?? reason;
      } catch {
        // ignore
      }
      throw new GoogleApiError(res.status, reason);
    }
    if (res.status === 204) return undefined;
    const text = await res.text();
    return text ? JSON.parse(text) : undefined;
  }
}

function enc(id: string): string {
  return encodeURIComponent(id);
}
