import { useState } from 'react';
import type { FormEvent } from 'react';
import { Globe, Mail, Plus } from 'lucide-react';
import { api } from '../api';
import { useAsync } from '../hooks';
import { cleanWatchValue } from '../lib';
import type { WatchEntry } from '../types';
import { Empty, ErrorBox, Loading, PageHead, Section } from '../components/ui';

export default function Watchlist() {
  const list = useAsync(api.watchlist);
  const [entries, setEntries] = useState<WatchEntry[] | null>(null);
  const [kind, setKind] = useState<WatchEntry['kind']>('domain');
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const shown = entries ?? list.data ?? [];

  async function submit(e: FormEvent) {
    e.preventDefault();
    setProblem(null);
    setNote(null);
    const clean = cleanWatchValue(kind, value);
    if (!clean) {
      setProblem(kind === 'domain' ? 'That does not look like a domain. Try something like example.com.' : 'That does not look like an email address.');
      return;
    }
    setBusy(true);
    try {
      setEntries(await api.addWatch(kind, clean));
      setValue('');
      setNote(`Now watching ${clean}. Every alert was re-checked against it.`);
    } catch (err) {
      setProblem(err instanceof Error ? err.message : 'Could not add it.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHead
        title="Your watchlist"
        sub="Tell DarkLens which domains and email addresses are yours. Any post that mentions them, or that contains leaked logins for them, jumps to the top."
      />
      <div className="state state-warn" role="note" style={{ marginBottom: 16 }}>
        <div>
          <strong>This watchlist is shared by everyone who uses this site.</strong>
          <p>
            There are no accounts yet, so anyone can see and add entries. Only add domains you are happy to be public, or run
            your own copy of DarkLens for private monitoring.
          </p>
        </div>
      </div>
      <div className="grid grid-2">
        <Section title="Add something to watch">
          <form onSubmit={submit} className="stack" noValidate>
            <div className="row" role="group" aria-label="What to watch">
              <button type="button" className="pill" aria-pressed={kind === 'domain'} onClick={() => setKind('domain')}>Website domain</button>
              <button type="button" className="pill" aria-pressed={kind === 'email'} onClick={() => setKind('email')}>Email address</button>
            </div>
            <div>
              <label htmlFor="wv">{kind === 'domain' ? 'Domain' : 'Email'}</label>
              <input
                id="wv"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={kind === 'domain' ? 'yourcompany.com' : 'you@yourcompany.com'}
                autoComplete="off"
                aria-describedby="wv-help"
              />
              <p id="wv-help" className="muted">Only the text is stored, and it is visible to other visitors.</p>
            </div>
            <button className="btn" disabled={busy || !value.trim()}>
              <Plus size={16} aria-hidden="true" /> {busy ? 'Adding and re-checking...' : 'Start watching'}
            </button>
            {problem && <p role="alert" style={{ color: 'var(--danger)' }}>{problem}</p>}
            {note && <p role="status" style={{ color: 'var(--safe)' }}>{note}</p>}
          </form>
        </Section>

        <Section title="Being watched">
          {list.loading && !list.data && <Loading what="your watchlist" slow={list.slow} />}
          {list.error && <ErrorBox message={list.error} onRetry={list.reload} />}
          {list.data && !shown.length && <Empty title="Nothing yet">Add your company domain to see what changes.</Empty>}
          {shown.length > 0 && (
            <ul className="ioc-values">
              {shown.map((w) => (
                <li key={`${w.kind}:${w.value}`} className="row">
                  {w.kind === 'domain' ? <Globe size={15} aria-label="domain" /> : <Mail size={15} aria-label="email" />}
                  <span>{w.value}</span>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>
    </>
  );
}
