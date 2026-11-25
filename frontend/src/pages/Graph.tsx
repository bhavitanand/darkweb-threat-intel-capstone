import { useEffect, useMemo, useRef, useState } from 'react';
import type { PointerEvent as RPointerEvent, WheelEvent as RWheelEvent } from 'react';
import { Maximize2, Minus, Plus } from 'lucide-react';
import { api } from '../api';
import { useToken } from '../auth';
import { useAsync } from '../hooks';
import { SEVERITY_META, SEVERITY_ORDER, TONE_HEX, categoryLabel, iocLabel, severityFromScore, severityMeta } from '../lib';
import { alertPath } from '../store';
import { buildClusters } from '../graph';
import type { Cluster } from '../graph';
import { Chip, Empty, ErrorBox, Loading, PageHead, Section, SeverityChip } from '../components/ui';
import SourceCredit from '../components/SourceCredit';

const W = 1000;
const CLUE_COLOR: Record<string, string> = {
  actor: '#1b1a17', org: '#756f63', btc: '#ffb020', eth: '#ffb020', xmr: '#ffb020', trx: '#ffb020',
  email: '#2c4a6e', domain: '#2c4a6e', ipv4: '#4f6b4a', sha256: '#c5b99f', md5: '#c5b99f', onion: '#6b3f7a', cve: '#b3261e',
};
const itemColor = (score?: number) => TONE_HEX[severityMeta(severityFromScore(score ?? 0)).tone];
const short = (s: string, n = 22) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

export default function Graph() {
  const signedIn = Boolean(useToken());
  const graph = useAsync(api.graph);
  const alerts = useAsync(() => api.alerts({ limit: 2000 }).then((p) => p.rows));
  const mine = useAsync(() => (signedIn ? api.workspaceAlerts() : Promise.resolve([])), [signedIn]);
  const [scope, setScope] = useState<'mine' | 'all'>(signedIn ? 'mine' : 'all');
  const [selected, setSelected] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [view, setView] = useState<{ x: number; y: number; k: number }>({ x: 0, y: 0, k: 1 });
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  const mineIds = useMemo(() => new Set((mine.data ?? []).map((a) => a.item_id)), [mine.data]);
  const useMine = signedIn && scope === 'mine';
  const { clusters, height } = useMemo(
    () => (graph.data ? buildClusters(graph.data.graph.nodes, graph.data.graph.links, W, useMine ? (id) => mineIds.has(id) : undefined) : { clusters: [], height: 0 }),
    [graph.data, useMine, mineIds],
  );
  const H = Math.max(height, 420);
  // Fit what is shown: a single small group should fill the frame, not sit in a corner.
  const fit = useMemo(() => {
    if (!clusters.length) return { x: 0, y: 0, k: 1 };
    const right = Math.max(...clusters.map((c) => c.x + c.w)) + 18;
    const bottom = Math.max(...clusters.map((c) => c.y + c.h)) + 18;
    const k = Math.min(2.2, W / right, H / bottom);
    return { k, x: (W - right * k) / 2, y: (H - bottom * k) / 2 };
  }, [clusters, H]);
  useEffect(() => setView(fit), [fit]);
  const titles = useMemo(() => new Map((alerts.data ?? []).map((a) => [a.item_id, a])), [alerts.data]);
  const nodeById = useMemo(() => new Map(clusters.flatMap((c) => c.nodes.map((n) => [n.id, { n, c }] as const))), [clusters]);
  const neighbours = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const c of clusters) for (const l of c.links) {
      (m.get(l.source) ?? m.set(l.source, new Set()).get(l.source)!).add(l.target);
      (m.get(l.target) ?? m.set(l.target, new Set()).get(l.target)!).add(l.source);
    }
    return m;
  }, [clusters]);

  const focus = hover ?? selected;
  const near = focus ? neighbours.get(focus) ?? new Set<string>() : new Set<string>();
  const sel = selected ? nodeById.get(selected) : undefined;
  const titleOf = (id: string) => titles.get(id.replace(/^item:/, ''))?.title;

  const zoomTo = (c: Cluster) => {
    const k = Math.min(2.4, Math.min(W / (c.w + 40), H / (c.h + 40)));
    setView({ k, x: -(c.x - 20) * k + (W - (c.w + 40) * k) / 2, y: -(c.y - 20) * k + (H - (c.h + 40) * k) / 2 });
  };
  const zoomBy = (f: number) => setView((v) => {
    const k = Math.min(4, Math.max(0.5, v.k * f));
    return { k, x: W / 2 - ((W / 2 - v.x) * k) / v.k, y: H / 2 - ((H / 2 - v.y) * k) / v.k };
  });
  const onWheel = (e: RWheelEvent<SVGSVGElement>) => {
    if (!e.ctrlKey && !e.metaKey) return; // a plain scroll keeps scrolling the page
    e.preventDefault();
    zoomBy(e.deltaY < 0 ? 1.15 : 1 / 1.15);
  };
  const toSvg = (dx: number, dy: number) => {
    const r = svgRef.current?.getBoundingClientRect();
    return r ? { dx: (dx * W) / r.width, dy: (dy * H) / r.height } : { dx, dy };
  };
  const onDown = (e: RPointerEvent<SVGSVGElement>) => {
    if ((e.target as Element).closest('.g-node')) return;
    drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
    (e.currentTarget as Element).setPointerCapture(e.pointerId);
  };
  const onMove = (e: RPointerEvent<SVGSVGElement>) => {
    if (!drag.current) return;
    const { dx, dy } = toSvg(e.clientX - drag.current.x, e.clientY - drag.current.y);
    setView((v) => ({ ...v, x: drag.current!.vx + dx, y: drag.current!.vy + dy }));
  };

  return (
    <>
      <PageHead
        title="Connections"
        sub="Alerts that share a clue: the same wallet, email, address, file or poster. Shared clues are a common sign of one operator behind several names or posts."
        actions={signedIn ? (
          <div className="pills" role="group" aria-label="Which connections">
            <button className="pill" aria-pressed={scope === 'mine'} onClick={() => { setScope('mine'); setSelected(null); }}>Around my alerts</button>
            <button className="pill" aria-pressed={scope === 'all'} onClick={() => { setScope('all'); setSelected(null); }}>Everything</button>
          </div>
        ) : undefined}
      />
      {graph.loading && !graph.data && <Loading what="the connections" slow={graph.slow} />}
      {graph.error && <ErrorBox message={graph.error} onRetry={graph.reload} />}
      {graph.data && (
        <div className="split">
          <div className="stack">
            {clusters.length === 0 ? (
              <Empty title={useMine ? 'None of your alerts share a clue with another' : 'No two alerts share a clue right now'}>
                {useMine ? 'That usually means each match is a separate event. Switch to Everything to see all connected groups.' : 'Connected groups appear here when two alerts mention the same wallet, address, file or poster.'}
              </Empty>
            ) : (
              <>
                <div className="graph-wrap">
                  <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} role="group" aria-label="Connection map. Tab moves between items; Enter selects one."
                    onWheel={onWheel} onPointerDown={onDown} onPointerMove={onMove} onPointerUp={() => { drag.current = null; }}
                    style={{ cursor: drag.current ? 'grabbing' : 'grab' }}>
                    <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
                      {clusters.map((c) => (
                        <g key={c.id}>
                          <rect className="g-cluster" x={c.x} y={c.y} width={c.w} height={c.h} rx="10" />
                          <text className="g-cluster-label" x={c.x + 12} y={c.y + 18}>Group {c.id} · {c.items} alerts · top {c.maxScore}</text>
                          {c.links.map((l, i) => {
                            const a = nodeById.get(l.source)?.n, b = nodeById.get(l.target)?.n;
                            if (!a || !b) return null;
                            const on = focus !== null && (l.source === focus || l.target === focus);
                            return <line key={i} className={`g-link${on ? ' on' : ''}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} />;
                          })}
                          {c.nodes.map((n) => {
                            const item = n.kind === 'item';
                            const r = item ? 7 + (n.score ?? 0) / 16 : 5.5;
                            const active = n.id === focus || near.has(n.id);
                            const dim = focus !== null && !active;
                            const label = item ? titleOf(n.id) ?? n.label : n.label.replace(/^[a-z0-9]+:/, '');
                            const showLabel = active || (!item && c.shared.some((s) => s.id === n.id) && !focus);
                            return (
                              <g key={n.id} className="g-node" tabIndex={0} role="button" aria-label={`${iocLabel(n.kind)}: ${label}`} opacity={dim ? 0.22 : 1}
                                onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)} onFocus={() => setHover(n.id)} onBlur={() => setHover(null)}
                                onClick={() => setSelected(n.id === selected ? null : n.id)}
                                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelected(n.id === selected ? null : n.id); } }}>
                                {item ? (
                                  <circle cx={n.x} cy={n.y} r={r} fill={itemColor(n.score)} stroke="#1b1a17" strokeWidth={n.id === selected ? 3 : 1.4} />
                                ) : (
                                  <rect x={n.x - r} y={n.y - r} width={r * 2} height={r * 2} rx="2" transform={`rotate(45 ${n.x} ${n.y})`}
                                    fill={CLUE_COLOR[n.kind] ?? '#756f63'} stroke="#1b1a17" strokeWidth={n.id === selected ? 3 : 1.2} />
                                )}
                                {showLabel && <text className="g-label" x={n.x + r + 5} y={n.y + 4}>{short(label, active ? 48 : 22)}</text>}
                              </g>
                            );
                          })}
                        </g>
                      ))}
                    </g>
                  </svg>
                  <div className="graph-tools">
                    <button className="btn btn-ghost" aria-label="Zoom in" onClick={() => zoomBy(1.25)}><Plus size={15} aria-hidden="true" /></button>
                    <button className="btn btn-ghost" aria-label="Zoom out" onClick={() => zoomBy(0.8)}><Minus size={15} aria-hidden="true" /></button>
                    <button className="btn btn-ghost" aria-label="Show everything" onClick={() => setView(fit)}><Maximize2 size={15} aria-hidden="true" /></button>
                  </div>
                </div>
                <div className="kinds" aria-label="Legend">
                  {SEVERITY_ORDER.map((s) => <span key={s} style={{ ['--c' as string]: TONE_HEX[SEVERITY_META[s].tone] }}>Alert, {SEVERITY_META[s].label.toLowerCase()}</span>)}
                  <span className="sq" style={{ ['--c' as string]: '#ffb020' }}>Wallet</span>
                  <span className="sq" style={{ ['--c' as string]: '#2c4a6e' }}>Domain or email</span>
                  <span className="sq" style={{ ['--c' as string]: '#1b1a17' }}>Poster</span>
                  <span className="sq" style={{ ['--c' as string]: '#c5b99f' }}>File</span>
                  <span className="muted">Drag to move. Ctrl + scroll or the buttons to zoom.</span>
                </div>
              </>
            )}
            <SourceCredit alerts={alerts.data ?? []} />
          </div>

          <div className="stack side-panel">
            {sel ? (
              <Section title={sel.n.kind === 'item' ? short(titleOf(sel.n.id) ?? sel.n.label, 70) : sel.n.label.replace(/^[a-z0-9]+:/, '')} hint={iocLabel(sel.n.kind)}
                aside={<button className="btn btn-ghost btn-sm" onClick={() => setSelected(null)}>Close</button>}>
                {sel.n.kind === 'item' ? (
                  <div className="stack">
                    <div className="row">
                      {titles.get(sel.n.id.replace(/^item:/, '')) && <SeverityChip severity={titles.get(sel.n.id.replace(/^item:/, ''))!.severity} />}
                      {sel.n.category && <Chip>{categoryLabel(sel.n.category)}</Chip>}
                    </div>
                    <p className="muted" style={{ fontSize: 13.5 }}>Shares {neighbours.get(sel.n.id)?.size ?? 0} clue{(neighbours.get(sel.n.id)?.size ?? 0) === 1 ? '' : 's'} with other alerts in group {sel.c.id}.</p>
                    <a className="btn" href={`#${alertPath(sel.n.id.replace(/^item:/, ''))}`}>Open the report</a>
                  </div>
                ) : (
                  <>
                    <p style={{ fontSize: 14 }}>Appears in {neighbours.get(sel.n.id)?.size ?? 0} alerts:</p>
                    <ul className="list-rows">
                      {[...(neighbours.get(sel.n.id) ?? [])].map((id) => (
                        <li key={id}><a href={`#${alertPath(id.replace(/^item:/, ''))}`} style={{ fontSize: 13.5 }}>{short(titleOf(id) ?? id, 60)}</a></li>
                      ))}
                    </ul>
                  </>
                )}
              </Section>
            ) : (
              <Section title={`${clusters.length} connected group${clusters.length === 1 ? '' : 's'}`} hint="Click a group to zoom in. Click a dot to see what it links.">
                <ul className="list-rows">
                  {clusters.slice(0, 12).map((c) => (
                    <li key={c.id}>
                      <button className="btn btn-ghost btn-sm" onClick={() => zoomTo(c)}>Group {c.id}</button>
                      <span className="grow" style={{ fontSize: 13 }}>
                        {c.items} alerts sharing {c.shared.slice(0, 2).map((s) => iocLabel(s.kind).toLowerCase()).join(' and ')}
                      </span>
                      <span className="mono muted">{c.maxScore}</span>
                    </li>
                  ))}
                </ul>
              </Section>
            )}
            <Section title="Possibly the same operator" hint="Different poster names that used the same wallet, email, address or file.">
              {graph.data.linked_actors.length ? (
                <ul className="list-rows">
                  {graph.data.linked_actors.map((l, i) => (
                    <li key={i} style={{ display: 'block' }}>
                      <strong>{l.actors.map((a) => a.replace(/^actor:/, '')).join(' and ')}</strong>
                      <div className="muted" style={{ fontSize: 13 }}>Both used the same {iocLabel(l.type).toLowerCase()}: <code className="mono">{l.shared.replace(/^[a-z0-9]+:/, '')}</code></div>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="muted" style={{ fontSize: 13.5 }}>No two posters share a clue in the current data.</p>
              )}
            </Section>
          </div>
        </div>
      )}
    </>
  );
}
