import { useEffect, useSyncExternalStore } from 'react';
import { api } from './api';
import { useToken } from './auth';
import type { WorkspaceView } from './types';

/** The signed-in person's workspace, loaded once and shared by every page (Set alerts, Connectors, Workspace...),
 *  so a change made on one page shows on the others without another request. */
interface State {
  email: string;
  ws: WorkspaceView | null;
  error: string | null;
  loading: boolean;
}

let state: State = { email: '', ws: null, error: null, loading: false };
let loadedFor: string | null = null;
const listeners = new Set<() => void>();

function set(next: Partial<State>) {
  state = { ...state, ...next };
  listeners.forEach((l) => l());
}

export function setWorkspace(ws: WorkspaceView) {
  set({ ws });
}

export function reloadWorkspace(): Promise<void> {
  set({ loading: true, error: null });
  return api
    .me()
    .then((m) => set({ email: m.email, ws: m.workspace, loading: false }))
    .catch((e: unknown) => set({ error: e instanceof Error ? e.message : 'Could not load your workspace.', loading: false }));
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useSession(): State & { signedIn: boolean } {
  const token = useToken();
  const s = useSyncExternalStore(subscribe, () => state, () => state);
  useEffect(() => {
    if (!token) {
      loadedFor = null;
      if (state.ws) set({ email: '', ws: null, error: null });
      return;
    }
    if (loadedFor !== token) {
      loadedFor = token;
      void reloadWorkspace();
    }
  }, [token]);
  return { ...s, signedIn: Boolean(token) };
}
