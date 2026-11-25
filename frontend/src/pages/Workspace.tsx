import { useState } from 'react';
import type { FormEvent } from 'react';
import { Copy, KeyRound, LogOut, Trash2 } from 'lucide-react';
import { api, BASE } from '../api';
import { setToken } from '../auth';
import { timeAgo } from '../lib';
import { reloadWorkspace, useSession } from '../session';
import type { WorkspaceView } from '../types';
import Gate from '../components/Gate';
import { PageHead, Section, StatTile } from '../components/ui';

const msg = (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback);

async function signOut() {
  try { await api.logout(); } catch { /* the session may already be gone */ }
  setToken(null);
}

function Keys({ ws }: { ws: WorkspaceView }) {
  const [label, setLabel] = useState('');
  const [fresh, setFresh] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const server = BASE || window.location.origin;

  async function create(e: FormEvent) {
    e.preventDefault();
    setProblem(null);
    try {
      const k = await api.newKey(label);
      setFresh(k.key);
      setLabel('');
      await reloadWorkspace();
    } catch (err) {
      setProblem(msg(err, 'Could not create a key.'));
    }
  }

  return (
    <Section title="API keys" hint="For your own scripts and tools. A key can only read the alerts that match your workspace.">
      <form onSubmit={create} className="row" style={{ alignItems: 'flex-end' }}>
        <div className="field">
          <label htmlFor="key-label">Name the key</label>
          <input id="key-label" value={label} onChange={(e) => setLabel(e.target.value)} maxLength={60} placeholder="my SIEM script" />
        </div>
        <button className="btn" disabled={ws.api_keys.length >= ws.limits.api_keys}><KeyRound size={15} aria-hidden="true" /> Create key</button>
      </form>
      {problem && <p role="alert" className="note-bad">{problem}</p>}
      {fresh && (
        <div className="state state-warn" role="status" style={{ marginTop: 12 }}>
          <div>
            <strong>Copy this key now. It is shown once and cannot be recovered.</strong>
            <p className="mono" style={{ wordBreak: 'break-all' }}>{fresh}</p>
            <div className="row" style={{ marginTop: 8 }}>
              <button className="btn btn-ghost btn-sm" onClick={() => navigator.clipboard?.writeText(fresh).catch(() => undefined)}><Copy size={14} aria-hidden="true" /> Copy</button>
              <button className="btn btn-ghost btn-sm" onClick={() => setFresh(null)}>I have saved it</button>
            </div>
          </div>
        </div>
      )}
      {ws.api_keys.length > 0 && (
        <ul className="list-rows" style={{ marginTop: 12 }}>
          {ws.api_keys.map((k) => (
            <li key={k.id}>
              <KeyRound size={15} aria-hidden="true" />
              <span className="grow"><strong>{k.label}</strong> <span className="muted" style={{ fontSize: 13 }}>created {timeAgo(k.created_at)}, {k.last_used ? `used ${timeAgo(k.last_used)}` : 'never used'}</span></span>
              <button className="btn btn-ghost btn-sm" aria-label={`Revoke ${k.label}`} onClick={async () => { try { await api.revokeKey(k.id); await reloadWorkspace(); } catch (e) { setProblem(msg(e, 'Could not revoke it.')); } }}>
                <Trash2 size={14} aria-hidden="true" /> Revoke
              </button>
            </li>
          ))}
        </ul>
      )}
      <h3 style={{ marginTop: 20 }}>Use it from a script</h3>
      <pre className="code-block">
        <span className="c"># your alerts as JSON, worst first</span>{'\n'}
        curl -H <span className="k">"X-API-Key: dlk_..."</span> {server}/api/workspace/alerts{'\n\n'}
        <span className="c"># or in Python</span>{'\n'}
        import requests{'\n'}
        r = requests.get(<span className="k">"{server}/api/workspace/alerts"</span>,{'\n'}
        {'                 '}headers={'{'}<span className="k">"X-API-Key"</span>: <span className="k">"dlk_..."</span>{'}'}){'\n'}
        for a in r.json(): print(a[<span className="k">"severity"</span>], a[<span className="k">"title"</span>], a[<span className="k">"url"</span>])
      </pre>
    </Section>
  );
}

function Danger() {
  const [sure, setSure] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  return (
    <Section title="Delete my account" hint="Removes your workspace, alerts, watchlist, connectors, keys and sessions. It cannot be undone.">
      {!sure ? (
        <button className="btn btn-ghost" onClick={() => setSure(true)}><Trash2 size={15} aria-hidden="true" /> Delete my account</button>
      ) : (
        <div className="row">
          <strong>Delete everything?</strong>
          <button className="btn" style={{ background: 'var(--danger)', borderColor: 'var(--danger)' }}
            onClick={async () => { try { await api.deleteAccount(); setToken(null); } catch (e) { setProblem(msg(e, 'Could not delete.')); } }}>Yes, delete</button>
          <button className="btn btn-ghost" onClick={() => setSure(false)}>Cancel</button>
        </div>
      )}
      {problem && <p role="alert" className="note-bad">{problem}</p>}
    </Section>
  );
}

function Workspace() {
  const { ws, email } = useSession();
  if (!ws) return null;
  return (
    <>
      <PageHead
        title="Workspace"
        sub="Your account. Everything here is private to you and never changes what anyone else sees."
        actions={<button className="btn btn-ghost" onClick={signOut}><LogOut size={15} aria-hidden="true" /> Sign out</button>}
      />
      <div className="stack">
        <Section title="Profile">
          <div className="kv">
            <span>Signed in as</span><span>{email}</span>
            <span>Workspace</span><span>{ws.name}</span>
            <span>Sign-in</span><span>By emailed one-time link. Sessions last 30 days.</span>
          </div>
        </Section>
        <div className="grid grid-3">
          <a href="#/rules" style={{ textDecoration: 'none', color: 'inherit' }}><StatTile tone="amber" label="Alerts set" value={ws.rules.length} hint={`of ${ws.limits.rules}, plus ${ws.entries.length} exact matches`} /></a>
          <a href="#/connectors" style={{ textDecoration: 'none', color: 'inherit' }}><StatTile tone="safe" label="Connectors" value={ws.connectors.length + (ws.digest !== 'off' ? 1 : 0)} hint="Slack, Discord, Teams, email" /></a>
          <StatTile tone="info" label="API keys" value={ws.api_keys.length} hint={`of ${ws.limits.api_keys}`} />
        </div>
        <Keys ws={ws} />
        <Danger />
      </div>
    </>
  );
}

export default function WorkspacePage() {
  return (
    <Gate title="Your workspace" why="Sign in to keep private alerts, connect Slack, Discord or Teams, and create API keys.">
      <Workspace />
    </Gate>
  );
}
