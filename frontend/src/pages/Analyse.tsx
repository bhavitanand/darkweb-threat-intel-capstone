import { useState } from 'react';
import type { FormEvent } from 'react';
import { ScanSearch } from 'lucide-react';
import { api } from '../api';
import type { Analysis } from '../types';
import { IocList, SignalList, Verdict } from '../components/parts';
import { ErrorBox, PageHead, Section } from '../components/ui';

const SAMPLE = `Selling initial access to the VPN of a telecom provider. Zero-day exploit for CVE-2026-5555, working RCE, tested.
Price 2 XMR, escrow accepted. Contact via Session only.`;

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
          <textarea id="x" value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste the text here" />
          <p className="muted">Nothing you paste here is saved. Please do not paste real stolen data; a description is enough.</p>
        </div>
        <div className="row">
          <button className="btn btn-brand" disabled={busy || !text.trim()}>
            <ScanSearch size={16} aria-hidden="true" /> {busy ? 'Checking...' : 'Check it'}
          </button>
          <button type="button" className="btn btn-ghost" onClick={() => { setText(SAMPLE); setTitle('Access and exploit for sale'); }}>
            Try an example
          </button>
        </div>
      </form>

      {error && <div style={{ marginTop: 16 }}><ErrorBox message={error} /></div>}

      {result && (
        <div className="stack" style={{ marginTop: 22 }} aria-live="polite">
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
