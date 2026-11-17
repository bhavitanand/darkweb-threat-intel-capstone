import { api } from '../api';
import { useAsync } from '../hooks';
import { timeAgo } from '../lib';
import { Chip, ErrorBox, Loading, Section } from './ui';

const SOURCE_NAMES: Record<string, string> = {
  'ransomware.live': 'Ransomware.live (ransomware victim claims, needs a free key)',
  threatfox: 'ThreatFox by abuse.ch (malicious indicators)',
  'cisa-kev': 'CISA Known Exploited Vulnerabilities (software flaws)',
  urlhaus: 'URLhaus by abuse.ch (malware download links)',
  haveibeenpwned: 'Have I Been Pwned (recent real data breaches)',
  'security-news': 'Security news feeds (headlines, linked to their source)',
  openphish: 'OpenPhish (live phishing pages)',
  feodo: 'Feodo Tracker by abuse.ch (botnet command servers)',
  forums: 'Forum posts',
};

function refreshText(minutes: number): string {
  if (minutes <= 0) return 'updated on request';
  return minutes % 60 === 0 ? `refreshed about every ${minutes / 60} hour${minutes === 60 ? '' : 's'}` : `refreshed about every ${minutes} minutes`;
}

export default function DataStatus({ real, demo }: { real: number; demo: number }) {
  const s = useAsync(api.ingestStatus);
  const last = s.data?.last;
  const live = s.data?.live_ready ?? false;

  return (
    <Section
      title="Where this data comes from"
      hint={
        live
          ? `Live feeds, ${refreshText(s.data?.auto_ingest_minutes ?? 0)}. Last update ${timeAgo(last?.finished_at)}.`
          : 'This site is showing demo data only. No live feed is switched on yet, because each needs a free key.'
      }
      aside={<Chip tone={live ? 'safe' : 'caution'}>{live ? 'Live' : 'Demo only'}</Chip>}
    >
      {s.loading && !s.data && <Loading what="data status" slow={s.slow} />}
      {s.error && <ErrorBox message={s.error} onRetry={s.reload} />}
      {last && (
        <ul className="src-list">
          {last.sources.map((src) => (
            <li key={src.source}>
              <span>{SOURCE_NAMES[src.source] ?? src.source}</span>
              <Chip tone={src.status === 'ok' ? 'safe' : src.status === 'error' ? 'danger' : 'muted'}>
                {src.status === 'ok' ? `${src.items} items` : src.status === 'skipped' ? 'Not switched on' : 'Problem'}
              </Chip>
              {src.note && <span className="muted src-note">{src.note}</span>}
            </li>
          ))}
        </ul>
      )}
      <p className="muted">
        {real} alert{real === 1 ? '' : 's'} from real feeds and {demo} from the built-in demo samples. Demo items are
        made up for demonstration and carry a Demo badge.
      </p>
    </Section>
  );
}
