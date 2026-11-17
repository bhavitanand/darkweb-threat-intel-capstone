import { useState } from 'react';
import type { FormEvent } from 'react';
import { ScanSearch } from 'lucide-react';
import { api } from '../api';
import type { Analysis } from '../types';
import { IocList, SignalList, Verdict } from '../components/parts';
import { ErrorBox, PageHead, Section } from '../components/ui';

/** The server refuses more than this (see AnalyseIn), so say so before sending rather than after. */
const MAX_CHARS = 20000;

// One click each. Two are threats, two are everyday news: the point is to see it flag the first and stay quiet on the rest.
const EXAMPLES = [
  {
    label: 'Access for sale',
    title: 'Access and exploit for sale',
    text: `Selling initial access to the VPN of a telecom provider. Zero-day exploit for CVE-2026-5555, working RCE, tested.
Price 2 XMR, escrow accepted. Contact via Session only.`,
  },
  {
    label: 'Data breach news',
    title: 'Uber notifies drivers of data breach',
    text: 'Uber notifies drivers of data breach affecting nearly 150,000 people. The ride-hailing company says attackers stole their data after breaching an AI infrastructure provider.',
  },
  {
    label: 'Patch news',
    title: 'Microsoft fixes security vulnerabilities',
    text: 'Microsoft fixes almost 1,100 security vulnerabilities in this months Patch Tuesday release, covering Windows and supported software.',
  },
  {
    label: 'Ordinary news',
    title: 'UK economy grows',
    text: 'UK economy grows at fastest rate for more than two years. The economy grew by 0.7% in the three months to September, according to official figures.',
  },
];

export default function Analyse() {
  const [title, setTitle] = useState('');
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Analysis | null>(null);

  async function run(e: FormEvent) {
    e.preventDefault();
    if (!text.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await api.analyse(text, title));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not analyse that.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHead
        title="Check a post"
        sub="Paste anything you found, such as a forum post, a chat message or a leak announcement, and get the same score and explanation the system gives its own alerts."
      />
      <form onSubmit={run} className="card section stack">
        <div>
          <label htmlFor="t">Title (optional)</label>
          <input id="t" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} />
        </div>
        <div>
          <label htmlFor="x">Text to check</label>
          <textarea id="x" value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste the text here" aria-describedby="x-help" />
          <p id="x-help" className="muted">
            Nothing you paste here is saved. Please do not paste real stolen data; a description is enough.{' '}
            <span style={text.length > MAX_CHARS ? { color: 'var(--danger)', fontWeight: 700 } : undefined}>
              {text.length.toLocaleString()} / {MAX_CHARS.toLocaleString()} characters{text.length > MAX_CHARS ? ': too long, shorten it to check it' : ''}.
            </span>{' '}
            Only the first 5,000 characters are classified.
          </p>
        </div>
        <div className="row">
          <button className="btn btn-brand" disabled={busy || !text.trim() || text.length > MAX_CHARS}>
            <ScanSearch size={16} aria-hidden="true" /> {busy ? 'Checking...' : 'Check it'}
          </button>
        </div>
        <div className="row" role="group" aria-label="Try an example">
          <span className="muted">Try an example:</span>
          {EXAMPLES.map((ex) => (
            <button
              key={ex.label}
              type="button"
              className="pill"
              onClick={() => { setText(ex.text); setTitle(ex.title); setResult(null); setError(null); }}
            >
              {ex.label}
            </button>
          ))}
        </div>
      </form>

      {error && <div style={{ marginTop: 16 }}><ErrorBox message={error} /></div>}

      {result && (
        <div className="stack" style={{ marginTop: 22 }} aria-live="polite">
          {result.truncated && (
            <p className="muted" role="note">This text is long, so only its first 5,000 characters were classified. Indicators and watchlist matches were still searched in all of it.</p>
          )}
          <Verdict score={result.score} severity={result.severity} category={result.category} confidence={result.confidence} />
          {result.exposures.length > 0 && (
            <div className="state state-error" role="alert">
              <div>
                <strong>Logins for your watched domains are in this text</strong>
                <p>{result.exposures.length} email and password pair{result.exposures.length === 1 ? '' : 's'} match a domain on your watchlist. Reset those passwords.</p>
              </div>
            </div>
          )}
          <Section title="Why it got this score"><SignalList signals={result.signals} /></Section>
          <Section title="Clues found in the text"><IocList iocs={result.iocs} /></Section>
        </div>
      )}
    </>
  );
}
