import { useSyncExternalStore } from 'react';

const KEY = 'darklens.session';
const listeners = new Set<() => void>();

/** Storage can be blocked (private windows, strict settings), so every access is guarded and the app still works signed out. */
function read(): string | null {
  try {
    return window.localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

let memory: string | null = read();

export function getToken(): string | null {
  return memory;
}

export function setToken(token: string | null): void {
  memory = token;
  try {
    if (token) window.localStorage.setItem(KEY, token);
    else window.localStorage.removeItem(KEY);
  } catch {
    /* kept in memory for this tab only */
  }
  listeners.forEach((l) => l());
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  const onStorage = (e: StorageEvent) => {
    if (e.key === KEY) {
      memory = e.newValue;
      cb();
    }
  };
  window.addEventListener('storage', onStorage);
  return () => {
    listeners.delete(cb);
    window.removeEventListener('storage', onStorage);
  };
}

/** The current session token (null when signed out), kept in step across tabs. */
export function useToken(): string | null {
  return useSyncExternalStore(subscribe, getToken, () => null);
}
