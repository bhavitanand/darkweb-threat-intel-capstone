import { ArrowLeft, ExternalLink, FileText } from 'lucide-react';
import { api } from '../api';
import { useAsync } from '../hooks';
import { hostOf, timeAgo } from '../lib';
import { IocList, ProbBars, SignalList, Verdict } from '../components/parts';
import FeedbackCard from '../components/FeedbackCard';
import SourceCredit from '../components/SourceCredit';
import { Chip, ErrorBox, Loading, Section } from '../components/ui';

export default function AlertReport({ id }: { id: string }) {
  const { data: a, error, loading, slow, reload } = useAsync(() => api.alert(id), [id]);

  return (
    <>
      <a className="back" href="#" onClick={(e) => { e.preventDefault(); if (window.history.length > 1) window.history.back(); else window.location.hash = '/alerts'; }}><ArrowLeft size={16} aria-hidden="true" /> Back</a>
      {loading && !a && <Loading what="the report" slow={slow} />}
      {error && /not found/i.test(error) ? (
        <div className="state" role="status">
          <div>
            <strong>We could not find that alert</strong>
            <p className="muted">
              The link may be mistyped, or the alert may have expired: old alerts are removed after a while. Go back to the list
              to see what is current.
            </p>
          </div>
        </div>
      ) : (
        error && <ErrorBox message={error} onRetry={reload} />
      )}
      {a && (
        <div className="stack">
          <header>
            <h1>{a.title || '(untitled post)'}</h1>
            {a.demo && (
              <p><Chip tone="info">Demo</Chip> <span className="muted">This is made-up sample data, not a real incident.</span></p>
            )}
            {a.url && (
              <p style={{ margin: '10px 0' }}>
                <a className="src-link" href={a.url} target="_blank" rel="noreferrer noopener">
                  Read the original report on {a.source === 'ransomware.live' ? 'Ransomware.live' : hostOf(a.url, a.source)} <ExternalLink size={14} aria-hidden="true" />
                </a>
              </p>
            )}
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

          <FeedbackCard key={a.item_id} id={a.item_id} category={a.category} counts={a.feedback} />

          <Section title="Details" hint="For analysts who want to check the work.">
            <div className="row">
              <a className="btn" href={api.evidenceUrl(a.item_id)} target="_blank" rel="noreferrer">
                <FileText size={16} aria-hidden="true" /> Open evidence pack
              </a>
              {a.url && (
                <a className="btn btn-ghost" href={a.url} target="_blank" rel="noreferrer noopener">
                  <ExternalLink size={16} aria-hidden="true" /> {a.source === 'ransomware.live' ? 'View on Ransomware.live' : 'Original source'}
                </a>
              )}
            </div>
            <SourceCredit alerts={[a]} />
            {Object.keys(a.probs).length > 0 && (
              <details>
                <summary>How sure is the system about the type?</summary>
                <ProbBars probs={a.probs} />
              </details>
            )}
            {a.restricted ? (
              <p className="muted">
                The original text is not shown here, because the source does not allow it to be re-published. Use the link above
                to read it on the source.
              </p>
            ) : (
              <details>
                <summary>Full text of the post</summary>
                <div className="fulltext">{a.text}</div>
              </details>
            )}
          </Section>
        </div>
      )}
    </>
  );
}
