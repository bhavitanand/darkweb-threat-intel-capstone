import { useMemo, useState } from 'react';
import { api } from '../api';
import { useAsync } from '../hooks';
import { SEVERITY_META, SEVERITY_ORDER, TONE_HEX, categoryLabel, iocLabel, layoutGraph, severityFromScore, severityMeta } from '../lib';
import { alertPath, go } from '../store';
import { Empty, ErrorBox, Loading, PageHead, Section, SeverityChip } from '../components/ui';
import { Chip } from '../components/ui';
import SourceCredit from '../components/SourceCredit';

const W = 960;
const H = 560;
const KIND_COLOR: Record<string, string> = {
  item: '#101731', actor: '#cc3542', org: '#e0702b', btc: '#b9811a', eth: '#b9811a', xmr: '#b9811a', trx: '#b9811a',
  email: '#2f5bd8', domain: '#2f5bd8', ipv4: '#2e9e6b', sha256: '#6b7180', md5: '#6b7180', onion: '#6b3fa0', cve: '#a52632',
};

function nodeColor(kind: string, score?: number) {
  if (kind === 'item') return TONE_HEX[severityMeta(severityFromScore(score ?? 0)).tone];
  return KIND_COLOR[kind] ?? '#6b7180';
}

export default function Graph() {
  const graph = useAsync(api.graph);
  // Titles for the graph's nodes. The map shows at most 300 alerts, all among the highest-scoring 2,000.
  const alerts = useAsync(() => api.alerts({ limit: 2000 }).then((p) => p.rows));
  const [selected, setSelected] = useState<string | null>(null);

  const placed = useMemo(
    () => (graph.data ? layoutGraph(graph.data.graph.nodes, graph.data.graph.links, W, H) : []),
    [graph.data],
  );
  const byId = useMemo(() => new Map(placed.map((p) => [p.id, p])), [placed]);
  const titles = useMemo(() => new Map((alerts.data ?? []).map((a) => [a.item_id, a])), [alerts.data]);
  const neighbours = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const l of graph.data?.graph.links ?? []) {
      (m.get(l.source) ?? m.set(l.source, new Set()).get(l.source)!).add(l.target);
      (m.get(l.target) ?? m.set(l.target, new Set()).get(l.target)!).add(l.source);
    }
    return m;
  }, [graph.data]);

  const kinds = useMemo(() => {
    const c = new Map<string, number>();
    for (const n of placed) c.set(n.kind, (c.get(n.kind) ?? 0) + 1);
    return Array.from(c.entries()).sort((a, b) => b[1] - a[1]);
  }, [placed]);

  const sel = selected ? byId.get(selected) : undefined;
  const selNeighbours = selected ? neighbours.get(selected) ?? new Set<string>() : new Set<string>();

  return (
    <>
      <PageHead
        title="Connections"
        sub="Posts, the people who wrote them and the wallets, addresses and files they mention. Lines show shared clues, so you can spot one operator behind several names."
      />
      {graph.loading && !graph.data && <Loading what="the connections" slow={graph.slow} />}
      {graph.error && <ErrorBox message={graph.error} onRetry={graph.reload} />}
      {graph.data && (
        <div className="stack">
          {placed.length === 0 ? (
            <Empty title="Nothing to connect yet">Once alerts are loaded, the links between them appear here.</Empty>
          ) : (
            <div className="grid" style={{ gridTemplateColumns: 'minmax(0,1fr)' }}>
              <div>
                <div className="graph-wrap">
                  <svg viewBox={`0 0 ${W} ${H}`} role="group" aria-label="Connection map. Use Tab to move between items.">
                    {graph.data.graph.links.map((l, i) => {
                      const a = byId.get(l.source);
                      const b = byId.get(l.target);
                      if (!a || !b) return null;
                      const on = selected !== null && (l.source === selected || l.target === selected);
                      return <line key={i} className={`g-link${on ? ' on' : ''}`} x1={a.x} y1={a.y} x2={b.x} y2={b.y} />;
                    })}
                    {placed.map((n) => {
                      const r = n.kind === 'item' ? 7 + (n.score ?? 0) / 14 : 6;
                      const active = n.id === selected || selNeighbours.has(n.id);
                      const showLabel = n.kind === 'actor' || n.kind === 'org' || active;
                      return (
                        <g
                          key={n.id}
                          className="g-node"
                          tabIndex={0}
                          role="button"
                          aria-label={`${iocLabel(n.kind)}: ${n.label}`}
                          onClick={() => setSelected(n.id === selected ? null : n.id)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              setSelected(n.id === selected ? null : n.id);
                            }
                          }}
                          opacity={selected && !active ? 0.3 : 1}
                        >
                          <circle cx={n.x} cy={n.y} r={r} fill={nodeColor(n.kind, n.score)} stroke="#fff" strokeWidth={2} />
                          {showLabel && <text className="g-label" x={n.x + r + 4} y={n.y + 4}>{n.label}</text>}
                        </g>
                      );
                    })}
                  </svg>
                </div>
                <div className="kinds" aria-label="Legend">
                  {SEVERITY_ORDER.map((s) => (
                    <span key={s} style={{ ['--c' as string]: TONE_HEX[SEVERITY_META[s].tone] }}>Alert, {SEVERITY_META[s].label.toLowerCase()}</span>
                  ))}
                  {kinds.filter(([k]) => k !== 'item').map(([k, n]) => (
                    <span key={k} style={{ ['--c' as string]: nodeColor(k) }}>{iocLabel(k)} ({n})</span>
                  ))}
                </div>
              </div>

              {sel && (
                <Section title={sel.label} hint={iocLabel(sel.kind)}>
                  {sel.kind === 'item' ? (
                    <div className="row">
                      {titles.get(sel.id.replace(/^item:/, '')) && (
                        <SeverityChip severity={titles.get(sel.id.replace(/^item:/, ''))!.severity} />
                      )}
                      {sel.category && <Chip>{categoryLabel(sel.category)}</Chip>}
                      <button className="btn" onClick={() => go(alertPath(sel.id.replace(/^item:/, '')))}>Open this alert</button>
                    </div>
                  ) : (
                    <p>
                      Linked to {selNeighbours.size} alert{selNeighbours.size === 1 ? '' : 's'}. Click a highlighted dot to
                      look at it.
                    </p>
                  )}
                </Section>
              )}
            </div>
          )}

          <Section
            title="Possibly the same operator"
            hint="Different poster names that share a wallet, email, address or file. That is a common sign of one person using several accounts."
          >
            {graph.data.linked_actors.length ? (
              <ul className="alert-list">
                {graph.data.linked_actors.map((l, i) => (
                  <li key={i} className="camp">
                    <strong>{l.actors.map((a) => a.replace(/^actor:/, '')).join(' and ')}</strong>
                    <p className="muted">
                      Both used the same {iocLabel(l.type).toLowerCase()}: <code className="mono">{l.shared.replace(/^[a-z0-9]+:/, '')}</code>
                    </p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted">No two posters share a clue in the current data.</p>
            )}
          </Section>

          <SourceCredit alerts={alerts.data ?? []} />

          <Section
            title="Connected alerts"
            hint="Groups of alerts tied together by shared clues. Higher risk means the group contains or sits next to serious alerts."
          >
            {graph.data.campaigns.length ? (
              graph.data.campaigns.map((c, i) => (
                <div key={i} className="camp">
                  <div className="row">
                    <strong>{c.size} alerts</strong>
                    <Chip tone={c.risk >= 70 ? 'danger' : c.risk >= 40 ? 'caution' : 'safe'}>Group risk {c.risk}</Chip>
                    <span className="muted">Top score {c.max_score}</span>
                  </div>
                  {c.shared.length > 0 && <p className="muted">Shared: {c.shared.join(', ')}</p>}
                  <ul>
                    {c.items.map((id) => (
                      <li key={id}>
                        <a href={`#${alertPath(id)}`}>{titles.get(id)?.title ?? id}</a>
                      </li>
                    ))}
                  </ul>
                </div>
              ))
            ) : (
              <p className="muted">No alerts are linked through shared wallets, addresses or files.</p>
            )}
          </Section>
        </div>
      )}
    </>
  );
}
