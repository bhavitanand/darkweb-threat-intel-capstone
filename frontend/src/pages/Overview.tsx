import { ArrowRight, ScanSearch } from 'lucide-react';
import { api } from '../api';
import { useAsync } from '../hooks';
import { SEVERITY_META, SEVERITY_ORDER, TONE_HEX, categoryLabel } from '../lib';
import { AlertRow } from '../components/AlertRow';
import DataStatus from '../components/DataStatus';
import SourceCredit from '../components/SourceCredit';
import { Bar, ErrorBox, Loading, Section, StatTile } from '../components/ui';

const TONE_VAR = TONE_HEX;

export default function Overview() {
  const stats = useAsync(api.stats);
  // The five worst real alerts: ask for just enough, already sorted by the server, not the whole list.
  const alerts = useAsync(() => api.alerts({ data: 'real', limit: 5 }).then(async (p) => (p.rows.length ? p : api.alerts({ limit: 5 }))));

  return (
    <>
      <div className="landing">
        <h1>What the dark web is saying, and whether it is about you.</h1>
        <p>
          DarkLens reads leak sites, forums and ransomware claims, scores each post from 0 to 100, and tells you in plain
          words why. Add your own domains and emails and anything that mentions them jumps to the top.
        </p>
        <div className="row" style={{ marginTop: 18 }}>
          <a className="btn btn-brand" href="#/start">New here? Get started <ArrowRight size={16} aria-hidden="true" /></a>
          <a className="btn btn-ghost" href="#/alerts">See the alerts</a>
          <a className="btn btn-ghost" href="#/analyse"><ScanSearch size={16} aria-hidden="true" /> Check a post yourself</a>
        </div>
      </div>

      {stats.loading && !stats.data && <Loading what="the overview" slow={stats.slow} />}
      {stats.error && <ErrorBox message={stats.error} onRetry={stats.reload} />}

      {stats.data && (
        <div className="stack">
          <div className="grid grid-4">
            <StatTile
              tone="danger"
              label="Need attention"
              value={(stats.data.by_severity.critical ?? 0) + (stats.data.by_severity.high ?? 0)}
              hint="Critical or high"
            />
            <StatTile
              tone="info"
              label="Alerts raised"
              value={stats.data.alerts - (stats.data.by_category.ioc_feed ?? 0)}
              hint={
                stats.data.by_category.ioc_feed
                  ? `Posts and claims, plus ${stats.data.by_category.ioc_feed.toLocaleString()} lone feed indicators`
                  : 'All severities'
              }
            />
            <StatTile tone="caution" label="Posts read" value={stats.data.items} hint="Collected so far" />
            <StatTile
              tone="safe"
              label="Clues extracted"
              value={Object.values(stats.data.ioc_types).reduce((a, b) => a + b, 0)}
              hint="Wallets, links, hashes, IPs"
            />
          </div>

          <div className="grid grid-2">
            <Section title="How serious are they?" hint="Alerts grouped by how worried you should be.">
              <div className="stacked" role="img" aria-label="Alerts by severity">
                {SEVERITY_ORDER.map((s) => (
                  <div
                    key={s}
                    style={{ width: `${((stats.data!.by_severity[s] ?? 0) / Math.max(stats.data!.alerts, 1)) * 100}%`, background: TONE_VAR[SEVERITY_META[s].tone] }}
                  />
                ))}
              </div>
              <div className="legend">
                {SEVERITY_ORDER.map((s) => (
                  <span key={s} style={{ ['--c' as string]: TONE_VAR[SEVERITY_META[s].tone] }}>
                    {SEVERITY_META[s].label}: <strong>{stats.data!.by_severity[s] ?? 0}</strong>
                  </span>
                ))}
              </div>
            </Section>

            <Section title="What kind of threats?" hint="The type each alert was sorted into.">
              <ul className="cat-rows">
                {Object.entries(stats.data.by_category)
                  .sort((a, b) => b[1] - a[1])
                  .map(([cat, n]) => (
                    <li key={cat}>
                      <span>{categoryLabel(cat)}</span>
                      <Bar value={n} max={Math.max(...Object.values(stats.data!.by_category))} label={`${categoryLabel(cat)}: ${n}`} />
                      <span className="mono">{n}</span>
                    </li>
                  ))}
              </ul>
            </Section>
          </div>

          <DataStatus real={stats.data.real_alerts} demo={stats.data.demo_alerts} />

          <Section
            title="Most worrying right now"
            hint="The five highest-scoring alerts."
            aside={<a className="btn btn-ghost" href="#/alerts">View all</a>}
          >
            {alerts.loading && !alerts.data && <Loading what="alerts" slow={alerts.slow} />}
            {alerts.error && <ErrorBox message={alerts.error} onRetry={alerts.reload} />}
            {alerts.data && (
              <>
                <ul className="alert-list">
                  {alerts.data.rows.map((a) => (
                    <li key={a.item_id}><AlertRow a={a} /></li>
                  ))}
                </ul>
                <SourceCredit alerts={alerts.data.rows} />
              </>
            )}
          </Section>
          <p className="muted">{stats.data.attribution}</p>
        </div>
      )}
    </>
  );
}
