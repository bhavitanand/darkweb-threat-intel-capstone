import { useEffect, useState } from 'react';
import { Download } from 'lucide-react';
import { api } from '../api';
import type { AlertPage } from '../api';
import { useAsync } from '../hooks';
import { CATEGORY_META, SEVERITY_META, SEVERITY_ORDER, categoryLabel } from '../lib';
import { AlertRow } from '../components/AlertRow';
import SourceCredit from '../components/SourceCredit';
import DataStatus from '../components/DataStatus';
import { useToken } from '../auth';
import { Empty, ErrorBox, Loading, PageHead } from '../components/ui';

const PAGE_SIZE = 100;

/** Wait for typing to pause before asking the server, so each keystroke is not a request. */
function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(t);
  }, [value, ms]);
  return v;
}

export default function Alerts() {
  const stats = useAsync(api.stats);
  const signedIn = Boolean(useToken());
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [q, setQ] = useState('');
  const [source, setSource] = useState('');
  const dq = useDebounced(q.trim());

  const [page, setPage] = useState<AlertPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [more, setMore] = useState(false);
  const [tick, setTick] = useState(0);
  const [slow, setSlow] = useState(false);

  // Filtering and paging happen on the server, so the count is the real total and a page costs the same however many
  // alerts exist. Any change of filter starts again from the first page.
  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(null);
    const timer = window.setTimeout(() => live && setSlow(true), 4000);
    api
      .alerts({ severity, category, q: dq, data: source, limit: PAGE_SIZE, offset: 0 })
      .then((p) => live && setPage(p))
      .catch((e: unknown) => live && setError(e instanceof Error ? e.message : 'Something went wrong.'))
      .finally(() => {
        window.clearTimeout(timer);
        if (live) {
          setLoading(false);
          setSlow(false);
        }
      });
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
  }, [severity, category, dq, source, tick]);

  async function showMore() {
    if (!page) return;
    setMore(true);
    try {
      const next = await api.alerts({ severity, category, q: dq, data: source, limit: PAGE_SIZE, offset: page.rows.length });
      setPage({ rows: [...page.rows, ...next.rows.filter((r) => !page.rows.some((x) => x.item_id === r.item_id))], total: next.total });
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Something went wrong.');
    } finally {
      setMore(false);
    }
  }

  const types = Object.keys(stats.data?.by_category ?? {}).sort((a, b) => categoryLabel(a).localeCompare(categoryLabel(b)));
  const filtered = Boolean(severity || category || dq || source);
  const left = page ? page.total - page.rows.length : 0;

  return (
    <>
      <PageHead
        title="Live feed"
        sub="Everything DarkLens has collected, from every source, most worrying first. This is not filtered to you: your own alerts are in My alerts."
        actions={
          <div className="row">
            <a className="btn btn-ghost" href={api.exportUrl('alerts.csv')} download><Download size={15} aria-hidden="true" /> Spreadsheet (CSV)</a>
            <a className="btn btn-ghost" href={api.exportUrl('stix.json')} download><Download size={15} aria-hidden="true" /> STIX 2.1</a>
          </div>
        }
      />
      {!signedIn && (
        <div className="state state-warn" style={{ marginBottom: 18 }}>
          <div>
            <strong>Want only what is about you?</strong>
            <p>Make a free workspace and write alerts like “ransomware attacks on hospitals”. <a href="#/workspace">Sign in</a></p>
          </div>
        </div>
      )}
      <div className="filters">
        <div className="pills" role="group" aria-label="Filter by severity">
          <button className="pill" aria-pressed={severity === ''} onClick={() => setSeverity('')}>All</button>
          {SEVERITY_ORDER.map((s) => (
            <button key={s} className="pill" aria-pressed={severity === s} onClick={() => setSeverity(severity === s ? '' : s)}>
              {SEVERITY_META[s].label}
            </button>
          ))}
        </div>
        <div className="field">
          <label htmlFor="cat">Type</label>
          <select id="cat" value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">All types</option>
            {types.map((c) => (
              <option key={c} value={c}>{CATEGORY_META[c]?.label ?? categoryLabel(c)}</option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="src">Data</label>
          <select id="src" value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="">Real and demo</option>
            <option value="real">Real feeds only</option>
            <option value="demo">Demo samples only</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="q">Search</label>
          <input id="q" type="search" placeholder="Company, poster, word..." value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>

      {loading && !page && <Loading what="alerts" slow={slow} />}
      {error && <ErrorBox message={error} onRetry={() => setTick((t) => t + 1)} />}
      {page && !error && (
        <>
          <p className="muted" aria-live="polite">
            Showing {page.rows.length.toLocaleString()} of {page.total.toLocaleString()}
            {filtered ? ' matching' : ''}
            {loading ? ' (updating...)' : ''}
          </p>
          {page.rows.length ? (
            <>
              <ul className="alert-list">
                {page.rows.map((a) => (
                  <li key={a.item_id}><AlertRow a={a} /></li>
                ))}
              </ul>
              {left > 0 && (
                <div className="row" style={{ justifyContent: 'center', marginTop: 16 }}>
                  <button className="btn btn-ghost" onClick={showMore} disabled={more}>
                    {more ? 'Loading...' : `Show ${Math.min(PAGE_SIZE, left).toLocaleString()} more (${left.toLocaleString()} left)`}
                  </button>
                </div>
              )}
              <SourceCredit alerts={page.rows} />
              <p className="muted" style={{ fontSize: 12.5 }}>
                Exports contain demo data and sources that allow sharing. Ransomware.live and news sites do not allow their text to
                be re-published, so those items are left out of downloads.
              </p>
            </>
          ) : (
            <Empty title="Nothing matches those filters">Clear a filter or try a different word.</Empty>
          )}
        </>
      )}
      {stats.data && <div style={{ marginTop: 22 }}><DataStatus real={stats.data.real_alerts} demo={stats.data.demo_alerts} /></div>}
    </>
  );
}
