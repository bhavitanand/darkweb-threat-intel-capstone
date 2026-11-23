import { useCallback, useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Bell, Copy, KeyRound, LogOut, Plus, Trash2, X } from 'lucide-react';
import { api } from '../api';
import { setToken, useToken } from '../auth';
import { categoryLabel, cleanWatchValue, timeAgo } from '../lib';
import type { WatchEntry, WorkspaceAlert, WorkspaceView } from '../types';
import { Chip, Empty, ErrorBox, Loading, PageHead, ScoreRing, Section, SeverityChip } from '../components/ui';
import { SignInForm } from './SignIn';

const KIND_LABEL: Record<WatchEntry['kind'], string> = { domain: 'Website domain', email: 'Email address', product: 'Software or vendor' };
const msg = (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback);

export default function Workspace() {
  const token = useToken();
  if (!token) {
    return (
      <>
        <PageHead title="Your workspace" sub="Sign in to keep a private watchlist, see only the alerts about it, and get a digest by email." />
        <SignInForm />
      </>
    );
  }
  return <Signed />;
}

function Signed() {
  const [email, setEmail] = useState('');
  const [ws, setWs] = useState<WorkspaceView | null>(null);
  const [alerts, setAlerts] = useState<WorkspaceAlert[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    api.me().then((m) => { setEmail(m.email); setWs(m.workspace); }).catch((e) => setError(msg(e, 'Could not load your workspace.')));
    api.workspaceAlerts().then(setAlerts).catch(() => setAlerts([]));
  }, []);
  useEffect(load, [load]);

  async function signOut() {
    try { await api.logout(); } catch { /* the session may already be gone */ }
    setToken(null);
  }

  if (error) return <ErrorBox message={error} onRetry={load} />;
  if (!ws) return <Loading what="your workspace" />;

  return (
    <>
      <PageHead
        title="Your workspace"
        sub={`Signed in as ${email}. Only you can see this watchlist; it never changes what anyone else sees.`}
        actions={<button className="btn btn-ghost" onClick={signOut}><LogOut size={15} aria-hidden="true" /> Sign out</button>}
      />
      <div className="stack">
        <Entries ws={ws} onChange={(w) => { setWs(w); api.workspaceAlerts().then(setAlerts).catch(() => undefined); }} />
        <MyAlerts alerts={alerts} hasEntries={ws.entries.length > 0} />
        <Notifications ws={ws} onChange={setWs} />
        <Keys ws={ws} onChange={setWs} />
        <Danger onDeleted={() => setToken(null)} />
      </div>
    </>
  );
}

function Entries({ ws, onChange }: { ws: WorkspaceView; onChange: (w: WorkspaceView) => void }) {
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
      onChange(await api.addEntry(kind, clean));
      setValue('');
    } catch (err) {
      setProblem(msg(err, 'Could not add it.'));
    } finally {
      setBusy(false);
    }
  }

  async function remove(entry: WatchEntry) {
    try { onChange(await api.removeEntry(entry.kind, entry.value)); } catch (err) { setProblem(msg(err, 'Could not remove it.')); }
  }

  return (
    <Section title="What you watch" hint={`Up to ${ws.limits.entries}. Domains, emails and software you run.`}>
      <form onSubmit={add} className="stack" noValidate>
        <div className="row" role="group" aria-label="What to watch">
          {(Object.keys(KIND_LABEL) as WatchEntry['kind'][]).map((k) => (
            <button key={k} type="button" className="pill" aria-pressed={kind === k} onClick={() => setKind(k)}>{KIND_LABEL[k]}</button>
          ))}
        </div>
        <div className="row">
          <div className="field">
            <label htmlFor="ws-value">{KIND_LABEL[kind]}</label>
            <input id="ws-value" value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off"
              placeholder={kind === 'domain' ? 'yourcompany.com' : kind === 'email' ? 'you@yourcompany.com' : 'screenconnect'} />
          </div>
          <button className="btn" disabled={busy || !value.trim()}><Plus size={16} aria-hidden="true" /> Add</button>
        </div>
        {problem && <p role="alert" style={{ color: 'var(--danger)' }}>{problem}</p>}
      </form>
      {ws.entries.length === 0 ? (
        <Empty title="Nothing yet">Add your company domain or the software you run to see what mentions it.</Empty>
      ) : (
        <ul className="ioc-values" style={{ marginTop: 12 }}>
          {ws.entries.map((e) => (
            <li key={`${e.kind}:${e.value}`} className="row">
              <Chip>{KIND_LABEL[e.kind]}</Chip> <span>{e.value}</span>
              <button className="btn btn-ghost" aria-label={`Stop watching ${e.value}`} onClick={() => remove(e)}><X size={14} aria-hidden="true" /></button>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function MyAlerts({ alerts, hasEntries }: { alerts: WorkspaceAlert[] | null; hasEntries: boolean }) {
  return (
    <Section title="About what you watch" hint="Stored items that mention your entries, scored against only your list.">
      {alerts === null && <Loading what="your alerts" />}
      {alerts && !alerts.length && (
        <Empty title={hasEntries ? 'Nothing mentions your list right now' : 'Add something to watch'}>
          {hasEntries ? 'That is good news. New items are checked every time the feeds refresh.' : 'Your alerts appear here.'}
        </Empty>
      )}
      {alerts && alerts.length > 0 && (
        <ul className="alert-list">
          {alerts.map((a) => (
            <li key={a.item_id}>
              <a className="alert-row" href={a.url || `#/alerts/${encodeURIComponent(a.item_id)}`} {...(a.url ? { target: '_blank', rel: 'noreferrer' } : {})}>
                <ScoreRing score={a.score} severity={a.severity} size={52} />
                <div className="alert-main">
                  <div className="alert-title">{a.title || '(untitled)'}</div>
                  <div className="alert-meta">
                    <SeverityChip severity={a.severity} />
                    <Chip>{categoryLabel(a.category)}</Chip>
                    <span>Matches: {a.matched.join(', ') || 'your list'}</span>
                    <span>{a.source}</span>
                    <span>{timeAgo(a.seen_at)}</span>
                  </div>
                  {a.reasons[0] && <div className="muted" style={{ fontSize: 13, marginTop: 4 }}>{a.reasons[0].why}</div>}
                </div>
              </a>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function Notifications({ ws, onChange }: { ws: WorkspaceView; onChange: (w: WorkspaceView) => void }) {
  const [url, setUrl] = useState(ws.webhook_url);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const say = (ok: boolean, text: string) => setNote({ ok, text });

  async function save(body: { digest?: string; webhook_url?: string; notify_min?: string }, done: string) {
    try { onChange(await api.saveSettings(body)); say(true, done); } catch (e) { say(false, msg(e, 'Could not save that.')); }
  }

  return (
    <Section title="Be told, not just shown" hint="A digest by email and an alert to Slack, Discord or Teams.">
      <div className="stack">
        <div className="row">
          <div className="field">
            <label htmlFor="digest">Email digest</label>
            <select id="digest" value={ws.digest} onChange={(e) => save({ digest: e.target.value }, 'Digest setting saved.')}>
              <option value="off">Off</option>
              <option value="daily">Daily, only when something is new</option>
              <option value="weekly">Weekly, only when something is new</option>
            </select>
          </div>
          <button className="btn btn-ghost" onClick={async () => { try { const p = await api.digestPreview(); setPreview(p.count ? p.body : 'Nothing new since the last digest.'); } catch (e) { say(false, msg(e, 'Could not build the preview.')); } }}>Preview</button>
          <button className="btn btn-ghost" disabled={!ws.email_ready} title={ws.email_ready ? '' : 'Email is not set up on this server'}
            onClick={async () => { try { const r = await api.digestSend(); say(true, r.sent ? `Sent ${r.count} item${r.count === 1 ? '' : 's'} to your email.` : 'Nothing new to send.'); } catch (e) { say(false, msg(e, 'Could not send.')); } }}>
            Send now
          </button>
        </div>
        {preview && <pre className="fulltext" aria-label="Digest preview">{preview}</pre>}

        <div className="row">
          <div className="field" style={{ minWidth: 260 }}>
            <label htmlFor="hook">Alert webhook (https)</label>
            <input id="hook" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.slack.com/services/..." autoComplete="off" />
          </div>
          <div className="field" style={{ minWidth: 150 }}>
            <label htmlFor="lvl">Alert me from</label>
            <select id="lvl" value={ws.notify_min} onChange={(e) => save({ notify_min: e.target.value }, 'Alert level saved.')}>
              <option value="low">Low and above</option>
              <option value="medium">Medium and above</option>
              <option value="high">High and above</option>
              <option value="critical">Critical only</option>
            </select>
          </div>
          <button className="btn" onClick={() => save({ webhook_url: url.trim() }, url.trim() ? 'Webhook saved.' : 'Webhook removed.')}><Bell size={15} aria-hidden="true" /> Save</button>
          <button className="btn btn-ghost" disabled={!ws.webhook_url}
            onClick={async () => { try { await api.webhookTest(); say(true, 'Test message sent.'); } catch (e) { say(false, msg(e, 'The test failed.')); } }}>Send a test</button>
        </div>
        {note && <p role={note.ok ? 'status' : 'alert'} style={{ color: note.ok ? 'var(--safe)' : 'var(--danger)' }}>{note.text}</p>}
      </div>
    </Section>
  );
}

function Keys({ ws, onChange }: { ws: WorkspaceView; onChange: (w: WorkspaceView) => void }) {
  const [label, setLabel] = useState('');
  const [fresh, setFresh] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  async function create(e: FormEvent) {
    e.preventDefault();
    setProblem(null);
    try {
      const k = await api.newKey(label);
      setFresh(k.key);
      setLabel('');
      onChange(await api.me().then((m) => m.workspace));
    } catch (err) {
      setProblem(msg(err, 'Could not create a key.'));
    }
  }

  return (
    <Section title="API keys" hint="For your own scripts. A key can only read the alerts about your watchlist.">
      <form onSubmit={create} className="row">
        <div className="field">
          <label htmlFor="key-label">Name</label>
          <input id="key-label" value={label} onChange={(e) => setLabel(e.target.value)} maxLength={60} placeholder="my script" />
        </div>
        <button className="btn" disabled={ws.api_keys.length >= ws.limits.api_keys}><KeyRound size={15} aria-hidden="true" /> Create key</button>
      </form>
      {problem && <p role="alert" style={{ color: 'var(--danger)' }}>{problem}</p>}
      {fresh && (
        <div className="state state-warn" role="status" style={{ marginTop: 12 }}>
          <div>
            <strong>Copy this key now. It is shown once and cannot be recovered.</strong>
            <p className="mono" style={{ wordBreak: 'break-all' }}>{fresh}</p>
            <button className="btn btn-ghost" onClick={() => navigator.clipboard?.writeText(fresh).catch(() => undefined)}><Copy size={14} aria-hidden="true" /> Copy</button>{' '}
            <button className="btn btn-ghost" onClick={() => setFresh(null)}>I have saved it</button>
          </div>
        </div>
      )}
      {ws.api_keys.length > 0 && (
        <ul className="ioc-values" style={{ marginTop: 12 }}>
          {ws.api_keys.map((k) => (
            <li key={k.id} className="row">
              <span>{k.label}</span>
              <span className="muted">created {timeAgo(k.created_at)}, {k.last_used ? `used ${timeAgo(k.last_used)}` : 'never used'}</span>
              <button className="btn btn-ghost" aria-label={`Revoke ${k.label}`} onClick={async () => onChange(await api.revokeKey(k.id))}><Trash2 size={14} aria-hidden="true" /> Revoke</button>
            </li>
          ))}
        </ul>
      )}
      <p className="muted" style={{ marginTop: 12 }}>Use it like this: <code>curl -H "X-API-Key: dlk_..." {'<server>'}/api/workspace/alerts</code></p>
    </Section>
  );
}

function Danger({ onDeleted }: { onDeleted: () => void }) {
  const [sure, setSure] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  return (
    <Section title="Delete my account" hint="Removes your workspace, watchlist, keys and sessions. It cannot be undone.">
      {!sure ? (
        <button className="btn btn-ghost" onClick={() => setSure(true)}><Trash2 size={15} aria-hidden="true" /> Delete my account</button>
      ) : (
        <div className="row">
          <strong>Delete everything?</strong>
          <button className="btn btn-brand" onClick={async () => { try { await api.deleteAccount(); onDeleted(); } catch (e) { setProblem(msg(e, 'Could not delete.')); } }}>Yes, delete</button>
          <button className="btn btn-ghost" onClick={() => setSure(false)}>Cancel</button>
        </div>
      )}
      {problem && <p role="alert" style={{ color: 'var(--danger)' }}>{problem}</p>}
    </Section>
  );
}
