import { useMemo, useSyncExternalStore } from 'react';

export type Route =
  | { name: 'overview' }
  | { name: 'start' }
  | { name: 'alerts' }
  | { name: 'alert'; id: string }
  | { name: 'graph' }
  | { name: 'watchlist' }
  | { name: 'analyse' }
  | { name: 'learn' };

/** Hash routing keeps this a pure static site: no rewrite rules needed on Vercel. */
export function parseRoute(hash: string): Route {
  const path = hash.replace(/^#\/?/, '').split('?')[0];
  const [head, ...rest] = path.split('/').filter(Boolean);
  switch (head) {
    case 'alerts':
      return rest.length ? { name: 'alert', id: decodeURIComponent(rest.join('/')) } : { name: 'alerts' };
    case 'start':
      return { name: 'start' };
    case 'graph':
      return { name: 'graph' };
    case 'watchlist':
      return { name: 'watchlist' };
    case 'analyse':
      return { name: 'analyse' };
    case 'learn':
      return { name: 'learn' };
    default:
      return { name: 'overview' };
  }
}

export function go(path: string) {
  window.location.hash = path.startsWith('/') ? path : `/${path}`;
}

export const alertPath = (id: string) => `/alerts/${encodeURIComponent(id)}`;

function subscribe(cb: () => void) {
  window.addEventListener('hashchange', cb);
  return () => window.removeEventListener('hashchange', cb);
}

export function useRoute(): Route {
  const hash = useSyncExternalStore(subscribe, () => window.location.hash, () => '');
  return useMemo(() => parseRoute(hash), [hash]);
}
