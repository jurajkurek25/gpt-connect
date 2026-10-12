import { hmacHex, safeEqual } from '../crypto.js';
import type { Store } from '../db.js';
import type { GoogleTask, TasksApi } from '../google/tasksClient.js';
import { GoogleApiError } from '../google/tasksClient.js';
import { classifyUrgency, fromGoogleDue, todayIn, toGoogleDue } from './dates.js';
import {
  appendMarker,
  type Candidate,
  type DuplicateMatch,
  extractSourceHash,
  findDuplicates,
  sourceHash as hashSource,
  stripMarker,
} from './duplicates.js';

export interface TaskView {
  id: string;
  title: string;
  notes: string | null;
  due_date: string | null;
  status: 'needsAction' | 'completed';
  completed_at: string | null;
  updated: string | null;
  has_source_ref: boolean;
  urgency: 'urgent' | 'normal' | null;
  days_until_due: number | null;
  overdue: boolean;
  web_link: string | null;
}

export class UserError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UserError';
  }
}

const MAX_SCAN_PAGES = 20; // up to 2000 tasks scanned for duplicates
const DELETE_CONFIRMATION_TTL_MS = 5 * 60_000;

export interface ServiceDeps {
  api: TasksApi;
  store: Store;
  timezone: string;
  hmacKey: Buffer;
  now?: () => number;
}

/** Serializes operations per key so two identical create requests cannot race past the duplicate check. */
class KeyedMutex {
  private tails = new Map<string, Promise<unknown>>();
  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    const next = prev.catch(() => undefined).then(fn);
    this.tails.set(key, next);
    try {
      return await next;
    } finally {
      if (this.tails.get(key) === next) this.tails.delete(key);
    }
  }
}

export class TasksService {
  private readonly api: TasksApi;
  private readonly store: Store;
  private readonly timezone: string;
  private readonly hmacKey: Buffer;
  private readonly now: () => number;
  private readonly mutex = new KeyedMutex();

  constructor(deps: ServiceDeps) {
    this.api = deps.api;
    this.store = deps.store;
    this.timezone = deps.timezone;
    this.hmacKey = deps.hmacKey;
    this.now = deps.now ?? Date.now;
  }

  toView(t: GoogleTask, today = todayIn(this.timezone, this.now())): TaskView {
    const due = fromGoogleDue(t.due);
    const completed = t.status === 'completed';
    const notes = stripMarker(t.notes);
    return {
      id: t.id,
      title: t.title ?? '',
      notes: notes ? notes : null,
      due_date: due,
      status: completed ? 'completed' : 'needsAction',
      completed_at: t.completed ?? null,
      updated: t.updated ?? null,
      has_source_ref: extractSourceHash(t.notes) !== null,
      ...classifyUrgency(due, completed, today),
      web_link: t.webViewLink ?? null,
    };
  }

  async listTaskLists(pageToken?: string, maxResults?: number) {
    const page = await this.api.listTaskLists(pageToken, maxResults);
    return {
      task_lists: page.items.map((l) => ({ id: l.id, title: l.title, updated: l.updated ?? null })),
      next_page_token: page.nextPageToken ?? null,
    };
  }

  async listTasks(input: {
    tasklist_id: string;
    show_completed?: boolean;
    due_from?: string;
    due_to?: string;
    max_results?: number;
    page_token?: string;
  }) {
    if (input.due_from && input.due_to && input.due_from > input.due_to) throw new UserError('due_from must not be after due_to');
    const page = await this.api.listTasks(input.tasklist_id, {
      showCompleted: input.show_completed ?? false,
      showHidden: input.show_completed ?? false,
      dueMin: input.due_from ? `${input.due_from}T00:00:00.000Z` : undefined,
      dueMax: input.due_to ? `${input.due_to}T23:59:59.999Z` : undefined,
      maxResults: input.max_results ?? 50,
      pageToken: input.page_token,
    });
    const today = todayIn(this.timezone, this.now());
    return {
      tasklist_id: input.tasklist_id,
      today,
      tasks: page.items.filter((t) => !t.deleted).map((t) => this.toView(t, today)),
      next_page_token: page.nextPageToken ?? null,
    };
  }

  private async allCandidates(tasklistId: string): Promise<Candidate[]> {
    const out: Candidate[] = [];
    let pageToken: string | undefined;
    for (let i = 0; i < MAX_SCAN_PAGES; i++) {
      const page = await this.api.listTasks(tasklistId, { showCompleted: true, showHidden: true, maxResults: 100, pageToken });
      for (const t of page.items) {
        if (t.deleted) continue;
        out.push({ id: t.id, title: t.title ?? '', dueDate: fromGoogleDue(t.due), sourceHash: extractSourceHash(t.notes) });
      }
      if (!page.nextPageToken) break;
      pageToken = page.nextPageToken;
    }
    return out;
  }

  /** Looks up a task, returning null when Google reports it as missing or deleted. */
  private async getTaskOrNull(tasklistId: string, taskId: string): Promise<GoogleTask | null> {
    try {
      const t = await this.api.getTask(tasklistId, taskId);
      return t.deleted ? null : t;
    } catch (err) {
      if (err instanceof GoogleApiError && err.status === 404) return null;
      throw err;
    }
  }

  private async getTaskOrThrow(tasklistId: string, taskId: string): Promise<GoogleTask> {
    const t = await this.getTaskOrNull(tasklistId, taskId);
    if (!t) throw new UserError('Task not found. Use list_tasks to get an exact task ID.');
    return t;
  }

  async findDuplicateTasks(input: { tasklist_id: string; title?: string; due_date?: string; source_id?: string }) {
    if (!input.title && !input.source_id) throw new UserError('Provide title and/or source_id');
    const srcHash = input.source_id ? hashSource(input.source_id) : null;
    const candidates = await this.allCandidates(input.tasklist_id);
    const matches = findDuplicates({ title: input.title, dueDate: input.due_date ?? null, sourceHash: srcHash }, candidates);

    // A source recorded in the idempotency store counts even if its marker was removed from the notes.
    if (srcHash && !matches.some((m) => m.match_type === 'source_id')) {
      const row = this.store.getIdempotency(srcHash);
      if (row && row.tasklist_id === input.tasklist_id && candidates.some((c) => c.id === row.task_id)) {
        matches.unshift({ task_id: row.task_id, match_type: 'source_id', similarity: 1 });
      }
    }
    const byId = new Map(candidates.map((c) => [c.id, c]));
    return {
      tasklist_id: input.tasklist_id,
      matches: matches.slice(0, 20).map((m) => ({ ...m, title: byId.get(m.task_id)?.title ?? '', due_date: byId.get(m.task_id)?.dueDate ?? null })),
    };
  }

  async createTask(input: { tasklist_id: string; title: string; notes?: string; due_date?: string; source_id?: string }, clientId?: string) {
    const srcHash = input.source_id ? hashSource(input.source_id) : null;
    const lockKey = srcHash ? `src:${srcHash}` : `title:${input.tasklist_id}`;

    return this.mutex.run(lockKey, async () => {
      // 1. Deterministic idempotency: same source already turned into a task.
      if (srcHash) {
        const row = this.store.getIdempotency(srcHash);
        if (row) {
          const existing = await this.getTaskOrNull(row.tasklist_id, row.task_id);
          if (existing) {
            this.store.audit({ event: 'create_task', outcome: 'already_exists', client_id: clientId, tasklist_id: row.tasklist_id, task_id: row.task_id, source_hash: srcHash }, this.now());
            return { status: 'already_exists' as const, match_type: 'source_id' as const, created: false, task: this.toView(existing) };
          }
          this.store.deleteIdempotencyBySource(srcHash);
        }
      }

      // 2. Scan the list for markers and exact title+date duplicates.
      const candidates = await this.allCandidates(input.tasklist_id);
      const matches = findDuplicates({ title: input.title, dueDate: input.due_date ?? null, sourceHash: srcHash }, candidates);
      const blocking: DuplicateMatch | undefined = matches.find((m) => m.match_type === 'source_id' || m.match_type === 'exact_title_and_date');
      if (blocking) {
        const existing = await this.getTaskOrThrow(input.tasklist_id, blocking.task_id);
        if (srcHash && blocking.match_type === 'source_id') {
          this.store.putIdempotency({ source_hash: srcHash, tasklist_id: input.tasklist_id, task_id: existing.id, created_at: this.now() });
        }
        this.store.audit({ event: 'create_task', outcome: 'duplicate_blocked', client_id: clientId, tasklist_id: input.tasklist_id, task_id: existing.id, source_hash: srcHash, detail: blocking.match_type }, this.now());
        return {
          status: blocking.match_type === 'source_id' ? ('already_exists' as const) : ('duplicate_found' as const),
          match_type: blocking.match_type,
          created: false,
          task: this.toView(existing),
          message: 'No new task was created because an equivalent task already exists.',
        };
      }

      // 3. Create.
      const body: Partial<GoogleTask> = { title: input.title, status: 'needsAction' };
      const notes = srcHash ? appendMarker(input.notes, srcHash) : input.notes;
      if (notes) body.notes = notes;
      if (input.due_date) body.due = toGoogleDue(input.due_date);
      const created = await this.api.insertTask(input.tasklist_id, body);
      if (srcHash) this.store.putIdempotency({ source_hash: srcHash, tasklist_id: input.tasklist_id, task_id: created.id, created_at: this.now() });
      this.store.audit({ event: 'create_task', outcome: 'created', client_id: clientId, tasklist_id: input.tasklist_id, task_id: created.id, source_hash: srcHash }, this.now());
      const similar = matches.filter((m) => m.match_type === 'exact_title' || m.match_type === 'similar_title').slice(0, 5);
      return {
        status: 'created' as const,
        created: true,
        task: this.toView(created),
        ...(similar.length ? { similar_existing_task_ids: similar.map((m) => m.task_id) } : {}),
      };
    });
  }

  async updateTask(input: { tasklist_id: string; task_id: string; title?: string; notes?: string | null; due_date?: string | null }, clientId?: string) {
    const changed = (['title', 'notes', 'due_date'] as const).filter((k) => input[k] !== undefined);
    if (changed.length === 0) throw new UserError('Nothing to update: provide title, notes and/or due_date');
    const existing = await this.getTaskOrThrow(input.tasklist_id, input.task_id);

    // PATCH semantics: only explicitly provided fields are sent, everything else is preserved by Google.
    const patch: Record<string, unknown> = {};
    if (input.title !== undefined) patch.title = input.title;
    if (input.notes !== undefined) {
      const existingHash = extractSourceHash(existing.notes);
      const newNotes = input.notes ?? '';
      // Keep the source marker so de-duplication keeps working after the notes are edited.
      patch.notes = existingHash ? appendMarker(newNotes, existingHash) : newNotes;
    }
    if (input.due_date !== undefined) patch.due = input.due_date === null ? null : toGoogleDue(input.due_date);

    const updated = await this.api.patchTask(input.tasklist_id, input.task_id, patch);
    this.store.audit({ event: 'update_task', outcome: 'updated', client_id: clientId, tasklist_id: input.tasklist_id, task_id: input.task_id, detail: changed.join(',') }, this.now());
    return { status: 'updated' as const, changed_fields: changed, task: this.toView(updated) };
  }

  async completeTask(input: { tasklist_id: string; task_id: string }, clientId?: string) {
    const existing = await this.getTaskOrThrow(input.tasklist_id, input.task_id);
    if (existing.status === 'completed') {
      return { status: 'already_completed' as const, task: this.toView(existing) };
    }
    const updated = await this.api.patchTask(input.tasklist_id, input.task_id, { status: 'completed' });
    this.store.audit({ event: 'complete_task', outcome: 'completed', client_id: clientId, tasklist_id: input.tasklist_id, task_id: input.task_id }, this.now());
    return { status: 'completed' as const, task: this.toView(updated) };
  }

  private confirmationMac(tasklistId: string, taskId: string, expiresAt: number): string {
    return hmacHex(this.hmacKey, 'delete_confirmation', `${tasklistId}\n${taskId}\n${expiresAt}`);
  }

  /**
   * Two-step delete. Step 1 (no token) returns the task and a short-lived confirmation token bound to this exact task.
   * Step 2 deletes only with a valid token. The model must obtain explicit user approval between the steps.
   */
  async deleteTask(input: { tasklist_id: string; task_id: string; confirmation_token?: string }, clientId?: string) {
    const existing = await this.getTaskOrThrow(input.tasklist_id, input.task_id);
    if (!input.confirmation_token) {
      const expiresAt = this.now() + DELETE_CONFIRMATION_TTL_MS;
      const token = `${expiresAt}.${this.confirmationMac(input.tasklist_id, input.task_id, expiresAt)}`;
      this.store.audit({ event: 'delete_task', outcome: 'confirmation_requested', client_id: clientId, tasklist_id: input.tasklist_id, task_id: input.task_id }, this.now());
      return {
        status: 'confirmation_required' as const,
        deleted: false,
        task: this.toView(existing),
        confirmation_token: token,
        expires_in_seconds: DELETE_CONFIRMATION_TTL_MS / 1000,
        instructions:
          'Show this task to the user and ask for explicit approval to delete it permanently. Only if the user clearly approves, call delete_task again with the same IDs and this confirmation_token.',
      };
    }
    const [expStr, mac] = input.confirmation_token.split('.', 2);
    const expiresAt = Number(expStr);
    if (!mac || !Number.isSafeInteger(expiresAt) || expiresAt < this.now() || !safeEqual(mac, this.confirmationMac(input.tasklist_id, input.task_id, expiresAt))) {
      this.store.audit({ event: 'delete_task', outcome: 'invalid_confirmation', client_id: clientId, tasklist_id: input.tasklist_id, task_id: input.task_id }, this.now());
      throw new UserError('Invalid or expired confirmation_token. Call delete_task without a token to start over.');
    }
    await this.api.deleteTask(input.tasklist_id, input.task_id);
    this.store.deleteIdempotencyByTask(input.task_id);
    this.store.audit({ event: 'delete_task', outcome: 'deleted', client_id: clientId, tasklist_id: input.tasklist_id, task_id: input.task_id }, this.now());
    return { status: 'deleted' as const, deleted: true, task_id: input.task_id, title: existing.title ?? '' };
  }
}
