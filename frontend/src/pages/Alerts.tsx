import { useMemo, useState } from 'react';
import { api } from '../api';
import { useAsync } from '../hooks';
import { CATEGORY_META, SEVERITY_META, SEVERITY_ORDER, categoryLabel, filterAlerts } from '../lib';
import { AlertRow } from '../components/AlertRow';
import { Empty, ErrorBox, Loading, PageHead } from '../components/ui';

export default function Alerts() {
  const { data, error, loading, slow, reload } = useAsync(api.alerts);
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [q, setQ] = useState('');

  const shown = useMemo(() => filterAlerts(data ?? [], { severity, category, q }), [data, severity, category, q]);
  const present = useMemo(() => Array.from(new Set((data ?? []).map((a) => a.category))), [data]);

  return (
    <>
      <PageHead title="Alerts" sub="Every post DarkLens has looked at, most worrying first. Open one to see exactly why it got its score." />
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
            {present.map((c) => (
              <option key={c} value={c}>{CATEGORY_META[c]?.label ?? categoryLabel(c)}</option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="q">Search</label>
          <input id="q" type="search" placeholder="Company, poster, word..." value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>

      {loading && !data && <Loading what="alerts" slow={slow} />}
      {error && <ErrorBox message={error} onRetry={reload} />}
      {data && (
        <>
          <p className="muted" aria-live="polite">Showing {shown.length} of {data.length}</p>
          {shown.length ? (
            <ul className="alert-list">
              {shown.map((a) => (
                <li key={a.item_id}><AlertRow a={a} /></li>
              ))}
            </ul>
          ) : (
            <Empty title="Nothing matches those filters">Clear a filter or try a different word.</Empty>
          )}
        </>
      )}
    </>
  );
}
