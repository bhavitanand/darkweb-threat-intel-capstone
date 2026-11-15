import type { Alert, AlertDetail, Analysis, EvalResult, GraphData, Stats, WatchEntry } from './types';

// Dev: empty, so requests go to /api and Vite proxies them. Production: the deployed API origin.
export const BASE = ((import.meta.env.VITE_API_URL as string | undefined) ?? '').replace(/\/+$/, '');

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(BASE + path, init);
  } catch {
    throw new ApiError('Could not reach the DarkLens server. It may be starting up; try again in a moment.', 0);
  }
  if (!res.ok) {
    let detail = '';
    try {
      detail = ((await res.json()) as { detail?: string }).detail ?? '';
    } catch {
      /* body was not JSON */
    }
    throw new ApiError(detail || `The server answered with an error (${res.status}).`, res.status);
  }
  return (await res.json()) as T;
}

const post = <T>(path: string, body: unknown) =>
  request<T>(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

export const api = {
  stats: () => request<Stats>('/api/stats'),
  alerts: () => request<Alert[]>('/api/alerts'),
  alert: (id: string) => request<AlertDetail>(`/api/alerts/${encodeURIComponent(id)}`),
  graph: () => request<GraphData>('/api/graph'),
  watchlist: () => request<WatchEntry[]>('/api/watchlist'),
  addWatch: (kind: WatchEntry['kind'], value: string) => post<WatchEntry[]>('/api/watchlist', { kind, value }),
  analyse: (text: string, title: string) => post<Analysis>('/api/analyse', { text, title }),
  evaluation: () => request<EvalResult>('/api/eval'),
  evidenceUrl: (id: string) => `${BASE}/api/alerts/${encodeURIComponent(id)}/evidence`,
};
