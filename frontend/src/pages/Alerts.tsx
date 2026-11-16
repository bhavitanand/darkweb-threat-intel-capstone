import { useMemo, useState } from 'react';
import { Download } from 'lucide-react';
import { api } from '../api';
import { useAsync } from '../hooks';
import { CATEGORY_META, SEVERITY_META, SEVERITY_ORDER, categoryLabel, filterAlerts } from '../lib';
import { AlertRow } from '../components/AlertRow';
import SourceCredit from '../components/SourceCredit';
import { Empty, ErrorBox, Loading, PageHead } from '../components/ui';

const PAGE_SIZE = 100;

export default function Alerts() {
  const { data, error, loading, slow, reload } = useAsync(api.alerts);
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [q, setQ] = useState('');
  const [source, setSource] = useState('');
  const [limit, setLimit] = useState(PAGE_SIZE);

  const shown = useMemo(() => filterAlerts(data ?? [], { severity, category, q, data: source }), [data, severity, category, q, source]);
  // Changing a filter starts again from the first page.
  const onFilter = <T,>(set: (v: T) => void) => (v: T) => { set(v); setLimit(PAGE_SIZE); };
  const page = shown.slice(0, limit);
  const present = useMemo(() => Array.from(new Set((data ?? []).map((a) => a.category))), [data]);

  return (
    <>
      <PageHead
        title="Alerts"
        sub="Every post DarkLens has looked at, most worrying first. Open one to see exactly why it got its score."
        actions={
          <div className="row">
            <a className="btn btn-ghost" href={api.exportUrl('alerts.csv')} download><Download size={15} aria-hidden="true" /> Spreadsheet (CSV)</a>
            <a className="btn btn-ghost" href={api.exportUrl('stix.json')} download><Download size={15} aria-hidden="true" /> STIX 2.1</a>
          </div>
        }
      />
      <p className="muted">
        Exports contain demo data and sources that allow sharing. Ransomware.live does not allow its data to be re-published,
        so its claims are left out of downloads.
      </p>
      <div className="filters">
        <div className="pills" role="group" aria-label="Filter by severity">
          <button className="pill" aria-pressed={severity === ''} onClick={() => onFilter(setSeverity)('')}>All</button>
          {SEVERITY_ORDER.map((s) => (
            <button key={s} className="pill" aria-pressed={severity === s} onClick={() => onFilter(setSeverity)(severity === s ? '' : s)}>
              {SEVERITY_META[s].label}
            </button>
          ))}
        </div>
        <div className="field">
          <label htmlFor="cat">Type</label>
          <select id="cat" value={category} onChange={(e) => onFilter(setCategory)(e.target.value)}>
            <option value="">All types</option>
            {present.map((c) => (
              <option key={c} value={c}>{CATEGORY_META[c]?.label ?? categoryLabel(c)}</option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="src">Data</label>
          <select id="src" value={source} onChange={(e) => onFilter(setSource)(e.target.value)}>
            <option value="">Real and demo</option>
            <option value="real">Real feeds only</option>
            <option value="demo">Demo samples only</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="q">Search</label>
          <input id="q" type="search" placeholder="Company, poster, word..." value={q} onChange={(e) => onFilter(setQ)(e.target.value)} />
        </div>
      </div>

      {loading && !data && <Loading what="alerts" slow={slow} />}
      {error && <ErrorBox message={error} onRetry={reload} />}
      {data && (
        <>
          <p className="muted" aria-live="polite">
            Showing {page.length} of {shown.length}{shown.length !== data.length ? ` matching (${data.length} in total)` : ''}
          </p>
          {shown.length ? (
            <>
              <ul className="alert-list">
                {page.map((a) => (
                  <li key={a.item_id}><AlertRow a={a} /></li>
                ))}
              </ul>
              {shown.length > page.length && (
                <div className="row" style={{ justifyContent: 'center', marginTop: 16 }}>
                  <button className="btn btn-ghost" onClick={() => setLimit(limit + PAGE_SIZE)}>
                    Show {Math.min(PAGE_SIZE, shown.length - page.length)} more ({shown.length - page.length} left)
                  </button>
                </div>
              )}
              <SourceCredit alerts={page} />
            </>
          ) : (
            <Empty title="Nothing matches those filters">Clear a filter or try a different word.</Empty>
          )}
        </>
      )}
    </>
  );
}
