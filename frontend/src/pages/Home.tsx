import { useMemo, useState } from 'react';
import { ArrowUpRight, BellPlus, RefreshCw } from 'lucide-react';
import { api } from '../api';
import { useAsync } from '../hooks';
import { categoryLabel, SEVERITY_META, SEVERITY_ORDER, timeAgo } from '../lib';
import { alertPath } from '../store';
import { useSession } from '../session';
import type { IngestStatus, WorkspaceAlert } from '../types';
import Gate from '../components/Gate';
import { Chip, Empty, ErrorBox, Loading, PageHead, ScoreRing, Section, SeverityChip, StatTile } from '../components/ui';

/** Why this item is in your feed, in words: the alert you wrote, or the watchlist entry it mentions. */
function because(a: WorkspaceAlert): string {
  if (a.rules?.length) {
    const words = a.rules[0].evidence.slice(0, 3).join(', ');
    return `You asked: “${a.rules[0].prompt}”${words ? ` (found: ${words})` : ''}`;
  }
  return `Mentions ${a.matched.slice(0, 3).join(', ') || 'something on your watchlist'}`;
}

export function PersonalRow({ a }: { a: WorkspaceAlert }) {
  return (
    <div className="alert-row">
      <ScoreRing score={a.score} severity={a.severity} size={54} />
      <div className="alert-main">
        <a className="alert-title stretch" href={`#${alertPath(a.item_id)}`} style={{ display: 'block', color: 'inherit', textDecoration: 'none' }}>
          {a.title || '(untitled)'}
        </a>
        <div className="alert-meta">
          <SeverityChip severity={a.severity} />
          <Chip>{categoryLabel(a.category)}</Chip>
          {a.demo && <Chip tone="info">Demo</Chip>}
          <span>{a.source}</span>
          <span>{timeAgo(a.seen_at)}</span>
        </div>
        <div className="alert-why">{because(a)}</div>
        {a.reasons[0] && <div className="muted" style={{ fontSize: 13, marginTop: 3 }}>{a.reasons[0].why}</div>}
      </div>
      <div className="alert-side">
        {a.url ? (
          <a className="src-link" href={a.url} target="_blank" rel="noreferrer noopener">Original report <ArrowUpRight size={14} aria-hidden="true" /></a>
        ) : (
          <span className="muted" style={{ fontSize: 12.5 }}>No public link</span>
        )}
      </div>
    </div>
  );
}

function Sources({ status }: { status: IngestStatus | null }) {
  // In demo mode nothing live was collected, so a list of sources with "0 items" would only confuse: describe them instead.
  const list = status?.last?.mode === 'live' ? status.last.sources : [];
  return (
    <Section title="Where we look" hint={status?.last ? `Last collected ${timeAgo(status.last.finished_at)}.` : 'Sources are collected on a schedule.'}>
      {list.length ? (
        <ul className="list-rows">
          {list.map((s) => (
            <li key={s.source} style={{ padding: '7px 0' }}>
              <span className={`dot ${s.status === 'ok' ? 'dot-ok' : s.status === 'error' ? 'dot-bad' : ''}`} aria-hidden="true" />
              <span className="grow" style={{ fontSize: 13.5 }}>{s.source}</span>
              <span className="muted mono" style={{ fontSize: 12 }}>{s.status === 'ok' ? `${s.items} items` : s.status === 'skipped' ? 'needs a key' : 'down'}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted" style={{ fontSize: 13.5 }}>
          Ransomware leak-site claims, abuse.ch malware and indicator feeds, CISA's exploited-flaw list, GitHub security
          advisories, OpenPhish, Have I Been Pwned breaches, and 17 security news outlets such as BleepingComputer, The Hacker
          News, Krebs on Security and The Record. Only demo data has been loaded on this server so far.
        </p>
      )}
    </Section>
  );
}

function Home() {
  const { ws } = useSession();
  const feed = useAsync(api.workspaceAlerts, [ws?.rules.length, ws?.entries.length]);
  const status = useAsync(api.ingestStatus);
  const [sev, setSev] = useState('');
  const [rule, setRule] = useState('');

  const rows = useMemo(() => (feed.data ?? [])
    .filter((a) => !sev || a.severity === sev)
    .filter((a) => !rule || (rule === 'watch' ? (a.watch_hits?.length ?? 0) > 0 : a.rules?.some((r) => r.id === rule))), [feed.data, sev, rule]);
  if (!ws) return null;
  const nothingSet = !ws.rules.length && !ws.entries.length;
  const count = (s: string) => (feed.data ?? []).filter((a) => a.severity === s).length;

  return (
    <>
      <PageHead
        title="My alerts"
        sub="Only what matches your alerts and watchlist, most serious first. Each one says why it is here and links to the original report."
        actions={
          <div className="row">
            <button className="btn btn-ghost" onClick={feed.reload}><RefreshCw size={15} aria-hidden="true" /> Refresh</button>
            <a className="btn" href="#/rules"><BellPlus size={15} aria-hidden="true" /> Set an alert</a>
          </div>
        }
      />
      {nothingSet ? (
        <div className="split">
          <div className="state state-empty" style={{ flexDirection: 'column', alignItems: 'center' }}>
            <strong>Nothing to show yet, because you haven't set any alerts</strong>
            <p className="muted">Write one sentence such as “ransomware attacks on hospitals” and matching items appear here.</p>
            <a className="btn btn-brand" href="#/rules"><BellPlus size={16} aria-hidden="true" /> Set your first alert</a>
          </div>
          <div className="side-panel"><Sources status={status.data} /></div>
        </div>
      ) : (
        <div className="split">
          <div className="stack">
            <div className="grid grid-4">
              <StatTile tone="danger" label="Critical" value={count('critical')} />
              <StatTile tone="orange" label="High" value={count('high')} />
              <StatTile tone="caution" label="Medium" value={count('medium')} />
              <StatTile tone="safe" label="Low" value={count('low')} />
            </div>
            <div className="filters" style={{ marginBottom: 0 }}>
              <div className="pills" role="group" aria-label="Filter by severity">
                <button className="pill" aria-pressed={sev === ''} onClick={() => setSev('')}>All</button>
                {SEVERITY_ORDER.map((s) => (
                  <button key={s} className="pill" aria-pressed={sev === s} onClick={() => setSev(sev === s ? '' : s)}>{SEVERITY_META[s].label}</button>
                ))}
              </div>
              <div className="field">
                <label htmlFor="by-rule">Matched by</label>
                <select id="by-rule" value={rule} onChange={(e) => setRule(e.target.value)}>
                  <option value="">Any of my alerts</option>
                  {ws.rules.map((r) => <option key={r.id} value={r.id}>“{r.prompt}”</option>)}
                  {ws.entries.length > 0 && <option value="watch">My exact matches</option>}
                </select>
              </div>
            </div>
            {feed.loading && !feed.data && <Loading what="your alerts" slow={feed.slow} />}
            {feed.error && <ErrorBox message={feed.error} onRetry={feed.reload} />}
            {feed.data && (rows.length ? (
              <ul className="alert-list">
                {rows.map((a) => <li key={a.item_id}><PersonalRow a={a} /></li>)}
              </ul>
            ) : (
              <Empty title={feed.data.length ? 'Nothing matches that filter' : 'Nothing matches your alerts right now'}>
                {feed.data.length ? 'Clear a filter to see the rest.' : 'That is good news. New items are checked every time the sources are collected.'}
              </Empty>
            ))}
          </div>
          <div className="stack side-panel">
            <Section title="You're watching for" aside={<a href="#/rules" style={{ fontSize: 13 }}>Edit</a>}>
              <ul className="list-rows">
                {ws.rules.map((r) => <li key={r.id} style={{ fontFamily: 'var(--serif)', fontStyle: 'italic' }}>“{r.prompt}”</li>)}
                {ws.entries.map((e) => <li key={`${e.kind}:${e.value}`} className="mono" style={{ fontSize: 12.5 }}>{e.value}</li>)}
              </ul>
            </Section>
            <Sources status={status.data} />
          </div>
        </div>
      )}
    </>
  );
}

export default function HomePage() {
  return (
    <Gate title="My alerts" why="Your own feed: only what matches the alerts you set.">
      <Home />
    </Gate>
  );
}
