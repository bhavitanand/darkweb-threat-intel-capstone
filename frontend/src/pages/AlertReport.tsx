import { ArrowLeft, ExternalLink, FileText } from 'lucide-react';
import { api } from '../api';
import { useAsync } from '../hooks';
import { timeAgo } from '../lib';
import { IocList, ProbBars, SignalList, Verdict } from '../components/parts';
import { ErrorBox, Loading, Section } from '../components/ui';

export default function AlertReport({ id }: { id: string }) {
  const { data: a, error, loading, slow, reload } = useAsync(() => api.alert(id), [id]);

  return (
    <>
      <a className="back" href="#/alerts"><ArrowLeft size={16} aria-hidden="true" /> All alerts</a>
      {loading && !a && <Loading what="the report" slow={slow} />}
      {error && <ErrorBox message={error} onRetry={reload} />}
      {a && (
        <div className="stack">
          <header>
            <h1>{a.title || '(untitled post)'}</h1>
            <p className="muted">
              From {a.source}
              {a.actor ? `, posted by ${a.actor}` : ''}
              {a.org ? `, about ${a.org}` : ''}
              {a.country ? ` (${a.country})` : ''}. Seen {timeAgo(a.seen_at)}.
            </p>
          </header>

          <Verdict score={a.score} severity={a.severity} category={a.category} confidence={a.confidence} />

          <Section title="Why it got this score" hint="Each warning sign the system found, from strongest to weakest. The final score combines them so several weak signs add up.">
            <SignalList signals={a.signals} />
          </Section>

          <div className="grid grid-2">
            <Section title="Clues found in the text" hint="Things an investigator could look up or block.">
              <IocList iocs={a.iocs} />
            </Section>
            <Section title="How attackers do this" hint="Matching techniques from the MITRE ATT&CK catalogue.">
              {a.mitre.length ? (
                <div className="tags">
                  {a.mitre.map((t) => (
                    <a key={t.id} className="tag" href={t.url} target="_blank" rel="noreferrer">
                      <span className="mono">{t.id}</span> {t.name} <ExternalLink size={13} aria-label="opens in a new tab" />
                    </a>
                  ))}
                </div>
              ) : (
                <p className="muted">No attack techniques apply to this type of post.</p>
              )}
            </Section>
          </div>

          <Section title="Details" hint="For analysts who want to check the work.">
            <div className="row">
              <a className="btn" href={api.evidenceUrl(a.item_id)} target="_blank" rel="noreferrer">
                <FileText size={16} aria-hidden="true" /> Open evidence pack
              </a>
              {a.url && (
                <a className="btn btn-ghost" href={a.url} target="_blank" rel="noreferrer noopener">
                  <ExternalLink size={16} aria-hidden="true" /> Original source
                </a>
              )}
            </div>
            {Object.keys(a.probs).length > 0 && (
              <details>
                <summary>How sure is the system about the type?</summary>
                <ProbBars probs={a.probs} />
              </details>
            )}
            <details>
              <summary>Full text of the post</summary>
              <div className="fulltext">{a.text}</div>
            </details>
          </Section>
        </div>
      )}
    </>
  );
}
