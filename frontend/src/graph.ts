import type { GraphLink, GraphNode } from './types';
import { layoutGraph } from './lib';
import type { Placed } from './lib';

export interface Cluster {
  id: number;
  nodes: Placed[];
  links: GraphLink[];
  items: number;
  /** The clues that tie the group together (non-alert nodes linked to two or more alerts). */
  shared: GraphNode[];
  maxScore: number;
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Turn the raw graph into what is worth looking at: groups of two or more alerts that share a clue.
 *
 *  The raw graph links every alert to every organisation, poster and indicator it mentions. Almost all of those clues
 *  belong to one alert only, so drawing them all gives a hairball that says nothing. Here a clue is kept only when it
 *  links two or more alerts, alerts with no shared clue are dropped, and each remaining group is laid out on its own
 *  and packed in rows, biggest and most serious first. */
export function buildClusters(nodes: GraphNode[], links: GraphLink[], width: number, keep?: (itemId: string) => boolean): { clusters: Cluster[]; height: number } {
  const isItem = (id: string) => id.startsWith('item:');
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const itemsOf = new Map<string, Set<string>>();
  for (const l of links) {
    const [item, clue] = isItem(l.source) ? [l.source, l.target] : isItem(l.target) ? [l.target, l.source] : [null, null];
    if (!item || !clue || isItem(clue)) continue;
    (itemsOf.get(clue) ?? itemsOf.set(clue, new Set()).get(clue)!).add(item);
  }
  const sharedClues = new Set([...itemsOf.entries()].filter(([, s]) => s.size >= 2).map(([c]) => c));
  const kept = links.filter((l) => sharedClues.has(l.source) || sharedClues.has(l.target));

  // connected components over the kept links
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    let r = x;
    while (parent.get(r) !== r) r = parent.get(r)!;
    let c = x;
    while (parent.get(c) !== r) { const n = parent.get(c)!; parent.set(c, r); c = n; }
    return r;
  };
  for (const l of kept) {
    for (const id of [l.source, l.target]) if (!parent.has(id)) parent.set(id, id);
    const a = find(l.source), b = find(l.target);
    if (a !== b) parent.set(a, b);
  }
  const groups = new Map<string, string[]>();
  for (const id of parent.keys()) (groups.get(find(id)) ?? groups.set(find(id), []).get(find(id))!).push(id);

  let comps = [...groups.values()]
    .map((ids) => ids.map((id) => byId.get(id)).filter((n): n is GraphNode => Boolean(n)))
    .filter((ns) => ns.filter((n) => n.kind === 'item').length >= 2);
  if (keep) comps = comps.filter((ns) => ns.some((n) => n.kind === 'item' && keep(n.id.replace(/^item:/, ''))));
  comps.sort((a, b) => Math.max(...b.map((n) => n.score ?? 0)) - Math.max(...a.map((n) => n.score ?? 0)) || b.length - a.length);

  const gap = 18;
  let x = gap, y = gap, rowH = 0;
  const clusters: Cluster[] = comps.map((ns, i) => {
    const ids = new Set(ns.map((n) => n.id));
    const ls = kept.filter((l) => ids.has(l.source) && ids.has(l.target));
    const side = Math.min(width - gap * 2, Math.max(200, Math.round(Math.sqrt(ns.length) * 92)));
    const w = side, h = Math.round(side * 0.72);
    if (x + w > width - gap && x > gap) { x = gap; y += rowH + gap; rowH = 0; }
    const placed = layoutGraph(ns, ls, w - 40, h - 50, 260).map((p) => ({ ...p, x: p.x + x + 20, y: p.y + y + 34 }));
    const c: Cluster = {
      id: i + 1, nodes: placed, links: ls, items: ns.filter((n) => n.kind === 'item').length,
      shared: ns.filter((n) => sharedClues.has(n.id)), maxScore: Math.max(...ns.map((n) => n.score ?? 0)), x, y, w, h,
    };
    x += w + gap;
    rowH = Math.max(rowH, h);
    return c;
  });
  return { clusters, height: clusters.length ? y + rowH + gap : 0 };
}
