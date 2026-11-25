import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { Plus, Sparkle, Trash2, X } from 'lucide-react';
import { api } from '../api';
import { cleanWatchValue } from '../lib';
import { setWorkspace, useSession } from '../session';
import type { RuleSpec, WatchEntry, WorkspaceView } from '../types';
import Gate from '../components/Gate';
import { RuleChips, RuleEditor } from '../components/RuleChips';
import { describeSpec, isEmptySpec as isEmpty } from '../rules';
import { Chip, Empty, PageHead, Section } from '../components/ui';

const EXAMPLES = [
  'any PHP to shell vulnerability in WordPress',
  'ransomware attacks on hospitals, critical only',
  'leaked logins for mycompany.com',
  'Fortinet or Ivanti bugs exploited in the wild',
  'phishing kits targeting banks',
  'anything about CVE-2024-4577',
];

const msg = (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback);

function Composer({ ws }: { ws: WorkspaceView }) {
  const [prompt, setPrompt] = useState('');
  const [spec, setSpec] = useState<RuleSpec | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const box = useRef<HTMLTextAreaElement>(null);

  // Understand as you type: wait for a pause, then ask the parser (it stores nothing).
  useEffect(() => {
    const p = prompt.trim();
    if (p.length < 3) {
      setSpec(null);
      return;
    }
    let live = true;
    const t = window.setTimeout(() => {
      api.parseRule(p).then((r) => {
        if (live) setSpec(r.spec);
      }).catch(() => undefined);
    }, 350);
    return () => {
      live = false;
      window.clearTimeout(t);
    };
  }, [prompt]);

  async function save(e: FormEvent) {
    e.preventDefault();
    if (!spec || isEmpty(spec)) return;
    setBusy(true);
    setNote(null);
    try {
      setWorkspace(await api.addRule(prompt.trim(), spec));
      setPrompt('');
      setNote({ ok: true, text: 'Alert saved. Matches appear in My alerts straight away.' });
      box.current?.focus();
    } catch (err) {
      setNote({ ok: false, text: msg(err, 'Could not save that alert.') });
    } finally {
      setBusy(false);
    }
  }

  const full = ws.rules.length >= ws.limits.rules;
  return (
    <form className="prompt-card" onSubmit={save} noValidate>
      <label htmlFor="prompt" className="eyebrow" style={{ fontWeight: 500 }}>Alert me for…</label>
      <div className="prompt-input">
        <textarea id="prompt" ref={box} value={prompt} maxLength={300} onChange={(e) => setPrompt(e.target.value)}
          placeholder="any PHP to shell vulnerability in WordPress"
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.currentTarget.form?.requestSubmit(); } }} />
      </div>
      <div className="prompt-examples" aria-label="Examples">
        {EXAMPLES.map((x) => <button type="button" key={x} onClick={() => setPrompt(x)}>{x}</button>)}
      </div>

      {spec && (
        <div className="understood" aria-live="polite">
          <div className="row" style={{ justifyContent: 'space-between' }}>
            <strong className="row" style={{ gap: 6 }}><Sparkle size={15} aria-hidden="true" /> What DarkLens understood</strong>
            <span className="muted" style={{ fontSize: 13 }}>Remove or add anything before saving.</span>
          </div>
          <RuleEditor spec={spec} onChange={setSpec} />
          <p style={{ marginTop: 14, fontFamily: 'var(--serif)', fontSize: 17 }}>
            {isEmpty(spec) ? 'Nothing to look for yet. Name a product, an attack, a CVE or a domain.' : describeSpec(spec)}
          </p>
        </div>
      )}
      <div className="row" style={{ marginTop: 14, justifyContent: 'space-between' }}>
        <span className="muted" style={{ fontSize: 13 }}>{ws.rules.length} of {ws.limits.rules} alerts used. Press Enter to save.</span>
        <button className="btn btn-brand" disabled={busy || full || !spec || isEmpty(spec)}>
          <Plus size={16} aria-hidden="true" /> {busy ? 'Saving…' : full ? 'Alert limit reached' : 'Save alert'}
        </button>
      </div>
      {note && <p role={note.ok ? 'status' : 'alert'} className={note.ok ? 'note-ok' : 'note-bad'}>{note.text}</p>}
    </form>
  );
}

function RuleList({ ws }: { ws: WorkspaceView }) {
  const [problem, setProblem] = useState<string | null>(null);
  if (!ws.rules.length) {
    return <Empty title="No alerts yet">Write your first one above. Try one of the examples to see how it works.</Empty>;
  }
  return (
    <div>
      {ws.rules.map((r) => (
        <div key={r.id} className="rule-card">
          <span className="rule-mark" aria-hidden="true">
            <svg width="16" height="16" viewBox="0 0 24 24"><path d="M2 12c3-5 7-7 10-7s7 2 10 7c-3 5-7 7-10 7S5 17 2 12Z" fill="none" stroke="#1b1a17" strokeWidth="2" /><circle cx="12" cy="12" r="3" fill="#1b1a17" /></svg>
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="quote">“{r.prompt}”</div>
            <RuleChips spec={r.spec} />
            <p className="muted" style={{ fontSize: 13, marginTop: 6 }}>{r.summary}</p>
          </div>
          <button className="btn btn-icon" aria-label={`Delete the alert "${r.prompt}"`}
            onClick={async () => { try { setWorkspace(await api.removeRule(r.id)); } catch (e) { setProblem(msg(e, 'Could not delete it.')); } }}>
            <Trash2 size={16} aria-hidden="true" />
          </button>
        </div>
      ))}
      {problem && <p role="alert" className="note-bad">{problem}</p>}
    </div>
  );
}

const KIND_LABEL: Record<WatchEntry['kind'], string> = { domain: 'Website domain', email: 'Email address', product: 'Software or vendor' };

/** Exact matches, the manual way: one domain, email or product per entry. */
function Watchlist({ ws }: { ws: WorkspaceView }) {
  const [kind, setKind] = useState<WatchEntry['kind']>('domain');
  const [value, setValue] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function add(e: FormEvent) {
    e.preventDefault();
    setProblem(null);
    const clean = cleanWatchValue(kind, value);
    if (!clean) {
      setProblem(kind === 'domain' ? 'That does not look like a domain. Try example.com.' : kind === 'email' ? 'That does not look like an email address.' : 'Use a product or vendor name of at least 3 letters.');
      return;
    }
    setBusy(true);
    try {
      setWorkspace(await api.addEntry(kind, clean));
      setValue('');
    } catch (err) {
      setProblem(msg(err, 'Could not add it.'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section title="Exact matches" hint={`The manual way: anything that mentions one of these is about you. Up to ${ws.limits.entries}.`}>
      <form onSubmit={add} noValidate>
        <div className="row" style={{ alignItems: 'flex-end' }}>
          <div className="pills" role="group" aria-label="What to watch">
            {(Object.keys(KIND_LABEL) as WatchEntry['kind'][]).map((k) => (
              <button key={k} type="button" className="pill" aria-pressed={kind === k} onClick={() => setKind(k)}>{KIND_LABEL[k]}</button>
            ))}
          </div>
          <div className="field">
            <label htmlFor="ws-value" className="sr-only">{KIND_LABEL[kind]}</label>
            <input id="ws-value" value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off"
              placeholder={kind === 'domain' ? 'yourcompany.com' : kind === 'email' ? 'you@yourcompany.com' : 'screenconnect'} />
          </div>
          <button className="btn" disabled={busy || !value.trim()}><Plus size={16} aria-hidden="true" /> Add</button>
        </div>
        {problem && <p role="alert" className="note-bad">{problem}</p>}
      </form>
      {ws.entries.length > 0 && (
        <ul className="list-rows" style={{ marginTop: 10 }}>
          {ws.entries.map((e) => (
            <li key={`${e.kind}:${e.value}`}>
              <Chip>{KIND_LABEL[e.kind]}</Chip> <span className="grow mono">{e.value}</span>
              <button className="btn btn-icon" aria-label={`Stop watching ${e.value}`}
                onClick={async () => { try { setWorkspace(await api.removeEntry(e.kind, e.value)); } catch (err) { setProblem(msg(err, 'Could not remove it.')); } }}>
                <X size={15} aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function Rules() {
  const { ws } = useSession();
  if (!ws) return null;
  return (
    <>
      <PageHead title="Set alerts" sub="Say what you want to hear about, in your own words. DarkLens shows you what it understood before anything is saved." />
      <div className="split">
        <div className="stack">
          <Composer ws={ws} />
          <Section title="Your alerts" hint="Every alert you have saved. Each one is checked against everything collected, old and new.">
            <RuleList ws={ws} />
          </Section>
        </div>
        <div className="stack side-panel">
          <Watchlist ws={ws} />
          <div className="card section">
            <h2 style={{ fontSize: 17 }}>How matching works</h2>
            <p className="muted" style={{ fontSize: 13.5 }}>
              Every part you keep must appear. "PHP to shell in WordPress" needs WordPress or PHP <em>and</em> a code-execution
              phrase, so ordinary WordPress news stays out. A CVE, domain or email is matched exactly.
            </p>
            <p className="muted" style={{ fontSize: 13.5 }}>
              Software you name also counts as "you run this": an attack on it scores higher in your feed than in the public one.
            </p>
            <p style={{ marginTop: 10 }}><a href="#/connectors">Send matches to Slack, Discord or Teams →</a></p>
          </div>
        </div>
      </div>
    </>
  );
}

export default function RulesPage() {
  return (
    <Gate title="Set alerts" why="Write what you want to hear about in one sentence, and DarkLens watches for it.">
      <Rules />
    </Gate>
  );
}
