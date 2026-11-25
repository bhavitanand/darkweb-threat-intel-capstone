import { getToken } from './auth';
import type {
  Alert, AlertDetail, Analysis, ApiKeyRecord, ConnectorKind, EvalResult, FeedbackCounts, GraphData, IngestStatus, MeResponse,
  ParsedRule, RuleSpec, RuleVocabulary, Severity, Stats, WatchEntry, WorkspaceAlert, WorkspaceView,
} from './types';

// Dev: empty, so requests go to /api and Vite proxies them. Production: the deployed API origin.
export const BASE = ((import.meta.env.VITE_API_URL as string | undefined) ?? '').replace(/\/+$/, '');

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

/** The server's `detail` is a string for our own errors but a list of objects for a rejected request body (422).
 *  Showing the list as text gives "[object Object]", so turn either shape into a sentence. */
export function describeDetail(detail: unknown, status = 0): string {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    const first = detail.find((d) => d && typeof d === 'object') as { type?: string; loc?: unknown[]; msg?: string; ctx?: { max_length?: number } } | undefined;
    if (first?.type === 'string_too_long' && first.ctx?.max_length) {
      return `That is too long: the limit is ${first.ctx.max_length.toLocaleString()} characters. Paste a shorter part.`;
    }
    if (first?.msg) {
      const field = Array.isArray(first.loc) ? first.loc.filter((p) => p !== 'body').join(' ') : '';
      return `${field ? `${field}: ` : ''}${first.msg}.`.replace(/\.\.$/, '.');
    }
  }
  return status === 422 ? 'The server could not accept that input.' : '';
}

async function fetchOk(path: string, init?: RequestInit): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(BASE + path, init);
  } catch {
    throw new ApiError('Could not reach the DarkLens server. It may be starting up; try again in a moment.', 0);
  }
  if (!res.ok) {
    let detail = '';
    try {
      detail = describeDetail(((await res.json()) as { detail?: unknown }).detail, res.status);
    } catch {
      /* body was not JSON */
    }
    if (res.status === 429) {
      const wait = Number(res.headers.get('Retry-After'));
      throw new ApiError(
        `You are going a little fast. Please wait ${Number.isFinite(wait) && wait > 0 ? `${wait} seconds` : 'a moment'} and try again.`,
        429,
      );
    }
    if (res.status >= 500 && !detail) {
      // 502, 503 and 504 are what the free host returns while it wakes up or restarts.
      throw new ApiError('The DarkLens server is not answering properly right now. It may be waking up or restarting: wait a minute and try again.', res.status);
    }
    throw new ApiError(detail || `The server answered with an error (${res.status}).`, res.status);
  }
  return res;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  return (await (await fetchOk(path, init)).json()) as T;
}

export interface AlertQuery {
  severity?: string;
  category?: string;
  q?: string;
  /** "real" or "demo" */
  data?: string;
  limit?: number;
  offset?: number;
}

export interface AlertPage {
  rows: Alert[];
  /** How many alerts match the filters in total, not just on this page. */
  total: number;
}

/** The query string for /api/alerts: only the filters that are set. */
export function alertQueryString(p: AlertQuery): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(p)) {
    if (v !== undefined && v !== '' && v !== null) qs.set(k, String(v));
  }
  const s = qs.toString();
  return s ? `?${s}` : '';
}

/** A request that carries the signed-in session. A 401 means the session ended, so it is forgotten here. */
async function authed<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers = { ...(init.headers as Record<string, string> | undefined), ...(token ? { Authorization: `Bearer ${token}` } : {}) };
  try {
    return await request<T>(path, { ...init, headers });
  } catch (e) {
    if (e instanceof ApiError && e.status === 401 && token) {
      const { setToken } = await import('./auth');
      setToken(null);
    }
    throw e;
  }
}

const jsonInit = (method: string, body: unknown): RequestInit => ({
  method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
});

const post = <T>(path: string, body: unknown) =>
  request<T>(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

export const api = {
  stats: () => request<Stats>('/api/stats'),
  alerts: async (p: AlertQuery = {}): Promise<AlertPage> => {
    const res = await fetchOk(`/api/alerts${alertQueryString(p)}`);
    const rows = (await res.json()) as Alert[];
    const total = Number(res.headers.get('X-Total-Count'));
    return { rows, total: Number.isFinite(total) && total >= rows.length ? total : rows.length };
  },
  alert: (id: string) => request<AlertDetail>(`/api/alerts/${encodeURIComponent(id)}`),
  graph: () => request<GraphData>('/api/graph'),
  watchlist: () => request<WatchEntry[]>('/api/watchlist'),
  addWatch: (kind: WatchEntry['kind'], value: string) => post<WatchEntry[]>('/api/watchlist', { kind, value }),
  analyse: (text: string, title: string) => post<Analysis>('/api/analyse', { text, title }),
  evaluation: () => request<EvalResult>('/api/eval'),
  ingestStatus: () => request<IngestStatus>('/api/ingest/status'),
  feedback: (id: string, verdict: 'correct' | 'wrong', category = '') =>
    post<FeedbackCounts>(`/api/alerts/${encodeURIComponent(id)}/feedback`, { verdict, category }),
  requestLink: (email: string) => post<{ ok: boolean; message: string; dev_link?: string }>('/api/auth/request', { email }),
  verifyLink: (token: string) => post<{ token: string; email: string }>('/api/auth/verify', { token }),
  logout: () => authed<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),
  me: () => authed<MeResponse>('/api/me'),
  deleteAccount: () => authed<{ ok: boolean }>('/api/account', { method: 'DELETE' }),
  workspaceAlerts: () => authed<WorkspaceAlert[]>('/api/workspace/alerts?limit=100'),
  addEntry: (kind: WatchEntry['kind'], value: string) => authed<WorkspaceView>('/api/workspace/watch', jsonInit('POST', { kind, value })),
  removeEntry: (kind: string, value: string) =>
    authed<WorkspaceView>(`/api/workspace/watch?kind=${encodeURIComponent(kind)}&value=${encodeURIComponent(value)}`, { method: 'DELETE' }),
  saveSettings: (body: { digest?: string; webhook_url?: string; notify_min?: string }) =>
    authed<WorkspaceView>('/api/workspace/settings', jsonInit('PUT', body)),
  newKey: (label: string) => authed<ApiKeyRecord & { key: string; note: string }>('/api/workspace/keys', jsonInit('POST', { label })),
  revokeKey: (id: string) => authed<WorkspaceView>(`/api/workspace/keys/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  digestPreview: () => authed<{ count: number; subject: string; body: string }>('/api/workspace/digest/preview'),
  digestSend: () => authed<{ sent: boolean; count: number }>('/api/workspace/digest/send', { method: 'POST' }),
  webhookTest: () => authed<{ ok: boolean }>('/api/workspace/webhook/test', { method: 'POST' }),
  ruleVocabulary: () => request<RuleVocabulary>('/api/rules/vocabulary'),
  parseRule: (prompt: string) => post<ParsedRule>('/api/rules/parse', { prompt }),
  addRule: (prompt: string, spec: RuleSpec) => authed<WorkspaceView>('/api/workspace/rules', jsonInit('POST', { prompt, spec })),
  removeRule: (id: string) => authed<WorkspaceView>(`/api/workspace/rules/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  setConnector: (kind: ConnectorKind, url: string, min_severity: Severity) =>
    authed<WorkspaceView>(`/api/workspace/connectors/${kind}`, jsonInit('PUT', { url, min_severity })),
  setConnectorLevel: (kind: ConnectorKind, min_severity: Severity) =>
    authed<WorkspaceView>(`/api/workspace/connectors/${kind}`, jsonInit('PATCH', { min_severity })),
  removeConnector: (kind: ConnectorKind) => authed<WorkspaceView>(`/api/workspace/connectors/${kind}`, { method: 'DELETE' }),
  testConnector: (kind: ConnectorKind) => authed<{ ok: boolean }>(`/api/workspace/connectors/${kind}/test`, { method: 'POST' }),
  exportUrl: (file: 'alerts.csv' | 'stix.json') => `${BASE}/api/export/${file}`,
  evidenceUrl: (id: string) => `${BASE}/api/alerts/${encodeURIComponent(id)}/evidence`,
};
