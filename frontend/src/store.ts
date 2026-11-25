import { useMemo, useSyncExternalStore } from 'react';

export type Route =
  | { name: 'overview' }
  | { name: 'home' }
  | { name: 'rules' }
  | { name: 'alerts' }
  | { name: 'alert'; id: string }
  | { name: 'graph' }
  | { name: 'connectors' }
  | { name: 'analyse' }
  | { name: 'signin'; token: string }
  | { name: 'workspace' };

/** A pasted or mangled link such as /#/alerts/%E0%A4%A is not valid percent-encoding. decodeURIComponent throws on it,
 *  and a throw while rendering blanks the whole page, so fall back to the text as typed (it will simply not be found). */
function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

/** Hash routing keeps this a static site. (index.html also turns a pasted /alerts into /#/alerts.) */
export function parseRoute(hash: string): Route {
  const [rawPath, query = ''] = hash.replace(/^#\/?/, '').split('?');
  const path = rawPath;
  const [head, ...rest] = path.split('/').filter(Boolean);
  switch (head) {
    case 'alerts':
      return rest.length ? { name: 'alert', id: safeDecode(rest.join('/')) } : { name: 'alerts' };
    case 'home':
      return { name: 'home' };
    case 'rules':
    case 'watchlist': // the old public watchlist page: watching now lives in "Set alerts"
      return { name: 'rules' };
    case 'graph':
      return { name: 'graph' };
    case 'connectors':
      return { name: 'connectors' };
    case 'analyse':
      return { name: 'analyse' };
    case 'signin':
      return { name: 'signin', token: safeDecode(new URLSearchParams(query).get('token') ?? '') };
    case 'workspace':
      return { name: 'workspace' };
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
