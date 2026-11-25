import { useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { Hash, Mail, MessageSquare, PlugZap, Send, Unplug, Users } from 'lucide-react';
import { api } from '../api';
import { SEVERITY_META } from '../lib';
import { setWorkspace, useSession } from '../session';
import type { Connector, ConnectorKind, Severity, WorkspaceView } from '../types';
import Gate from '../components/Gate';
import { PageHead } from '../components/ui';

const msg = (e: unknown, fallback: string) => (e instanceof Error ? e.message : fallback);
const LEVELS: Severity[] = ['low', 'medium', 'high', 'critical'];

const KINDS: { kind: ConnectorKind; name: string; icon: ReactNode; placeholder: string; steps: string[] }[] = [
  {
    kind: 'slack', name: 'Slack', icon: <Hash size={20} aria-hidden="true" />, placeholder: 'https://hooks.slack.com/services/…',
    steps: ['In Slack, open Apps and add "Incoming WebHooks" (or create an app with incoming webhooks).', 'Pick the channel for alerts.', 'Copy the webhook URL and paste it here.'],
  },
  {
    kind: 'discord', name: 'Discord', icon: <MessageSquare size={20} aria-hidden="true" />, placeholder: 'https://discord.com/api/webhooks/…',
    steps: ['In your server, open the channel settings, then Integrations, then Webhooks.', 'Create a webhook and name it DarkLens.', 'Copy the webhook URL and paste it here.'],
  },
  {
    kind: 'teams', name: 'Microsoft Teams', icon: <Users size={20} aria-hidden="true" />, placeholder: 'https://….webhook.office.com/…',
    steps: ['In the channel, open Workflows and choose "Post to a channel when a webhook request is received".', 'Finish the steps and copy the address it gives you.', 'Paste it here.'],
  },
];

function Level({ value, onChange, id }: { value: Severity; onChange: (s: Severity) => void; id: string }) {
  return (
    <div className="field" style={{ minWidth: 160, flex: 'none' }}>
      <label htmlFor={id}>Send alerts from</label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value as Severity)}>
        {LEVELS.map((l) => <option key={l} value={l}>{SEVERITY_META[l].label}{l === 'critical' ? ' only' : ' and worse'}</option>)}
      </select>
    </div>
  );
}

function ChatCard({ spec, current }: { spec: (typeof KINDS)[number]; current?: Connector }) {
  const [url, setUrl] = useState('');
  const [level, setLevel] = useState<Severity>('high');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const say = (ok: boolean, text: string) => setNote({ ok, text });

  async function connect(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNote(null);
    try {
      setWorkspace(await api.setConnector(spec.kind, url.trim(), level));
      setUrl('');
      say(true, `Connected. New matches at ${SEVERITY_META[level].label} or worse will be posted, most serious first.`);
    } catch (err) {
      say(false, msg(err, 'Could not connect it.'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className={`conn${current ? ' on' : ''}`} aria-labelledby={`h-${spec.kind}`}>
      <div className="conn-head">
        <span className="conn-logo">{spec.icon}</span>
        <div style={{ flex: 1 }}>
          <h2 id={`h-${spec.kind}`}>{spec.name}</h2>
          <span className={`chip ${current ? 'chip-safe' : ''}`}>{current ? 'Connected' : 'Not connected'}</span>
        </div>
      </div>
      {current ? (
        <>
          <p className="mono muted" style={{ fontSize: 12, wordBreak: 'break-all', margin: 0 }}>{current.url}</p>
          <div className="row" style={{ alignItems: 'flex-end' }}>
            <Level id={`lvl-${spec.kind}`} value={current.min_severity}
              onChange={async (s) => { try { setWorkspace(await api.setConnectorLevel(spec.kind, s)); say(true, 'Level saved.'); } catch (err) { say(false, msg(err, 'Could not save.')); } }} />
            <button className="btn btn-ghost" onClick={async () => { try { await api.testConnector(spec.kind); say(true, 'Test message sent. Check the channel.'); } catch (err) { say(false, msg(err, 'The test failed.')); } }}>
              <Send size={15} aria-hidden="true" /> Send a test
            </button>
            <button className="btn btn-ghost" onClick={async () => { try { setWorkspace(await api.removeConnector(spec.kind)); say(true, 'Disconnected.'); } catch (err) { say(false, msg(err, 'Could not disconnect.')); } }}>
              <Unplug size={15} aria-hidden="true" /> Disconnect
            </button>
          </div>
        </>
      ) : (
        <form onSubmit={connect} className="stack" noValidate>
          <ol className="conn-steps">{spec.steps.map((s) => <li key={s}>{s}</li>)}</ol>
          <div>
            <label htmlFor={`url-${spec.kind}`}>Webhook address</label>
            <input id={`url-${spec.kind}`} value={url} onChange={(e) => setUrl(e.target.value)} placeholder={spec.placeholder} autoComplete="off" />
          </div>
          <div className="row" style={{ alignItems: 'flex-end' }}>
            <Level id={`new-lvl-${spec.kind}`} value={level} onChange={setLevel} />
            <button className="btn" disabled={busy || !url.trim()}><PlugZap size={15} aria-hidden="true" /> {busy ? 'Connecting…' : 'Connect'}</button>
          </div>
        </form>
      )}
      {note && <p role={note.ok ? 'status' : 'alert'} className={note.ok ? 'note-ok' : 'note-bad'} style={{ margin: 0 }}>{note.text}</p>}
    </section>
  );
}

function EmailCard({ ws }: { ws: WorkspaceView }) {
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const say = (ok: boolean, text: string) => setNote({ ok, text });
  return (
    <section className={`conn${ws.digest !== 'off' ? ' on' : ''}`} aria-labelledby="h-email">
      <div className="conn-head">
        <span className="conn-logo"><Mail size={20} aria-hidden="true" /></span>
        <div style={{ flex: 1 }}>
          <h2 id="h-email">Email digest</h2>
          <span className={`chip ${ws.digest !== 'off' ? 'chip-safe' : ''}`}>{ws.digest === 'off' ? 'Off' : ws.digest === 'daily' ? 'Daily' : 'Weekly'}</span>
        </div>
      </div>
      <p className="muted" style={{ margin: 0, fontSize: 13.5 }}>A summary of what is new about you, sent only when there is something new, most serious first.</p>
      <div className="row" style={{ alignItems: 'flex-end' }}>
        <div className="field" style={{ minWidth: 200 }}>
          <label htmlFor="digest">How often</label>
          <select id="digest" value={ws.digest}
            onChange={async (e) => { try { setWorkspace(await api.saveSettings({ digest: e.target.value })); say(true, 'Saved.'); } catch (err) { say(false, msg(err, 'Could not save that.')); } }}>
            <option value="off">Off</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
          </select>
        </div>
        <button className="btn btn-ghost" onClick={async () => { try { const p = await api.digestPreview(); setPreview(p.count ? p.body : 'Nothing new since the last digest.'); } catch (err) { say(false, msg(err, 'Could not build the preview.')); } }}>Preview</button>
        <button className="btn btn-ghost" disabled={!ws.email_ready} title={ws.email_ready ? '' : 'Email sending is not set up on this server yet'}
          onClick={async () => { try { const r = await api.digestSend(); say(true, r.sent ? `Sent ${r.count} item${r.count === 1 ? '' : 's'}.` : 'Nothing new to send.'); } catch (err) { say(false, msg(err, 'Could not send.')); } }}>
          Send now
        </button>
      </div>
      {!ws.email_ready && <p className="muted" style={{ margin: 0, fontSize: 12.5 }}>Email sending is not set up on this server yet, so digests are saved but not sent.</p>}
      {preview && <pre className="fulltext" aria-label="Digest preview">{preview}</pre>}
      {note && <p role={note.ok ? 'status' : 'alert'} className={note.ok ? 'note-ok' : 'note-bad'} style={{ margin: 0 }}>{note.text}</p>}
    </section>
  );
}

function Connectors() {
  const { ws } = useSession();
  if (!ws) return null;
  const on = (k: ConnectorKind) => ws.connectors.find((c) => c.kind === k);
  return (
    <>
      <PageHead title="Connectors" sub="Be told, not just shown. Matches for your alerts are posted where you already are, most serious first, each with a link to the original report." />
      <div className="conn-grid">
        {KINDS.map((k) => <ChatCard key={k.kind} spec={k} current={on(k.kind)} />)}
        <EmailCard ws={ws} />
      </div>
      <p className="muted" style={{ marginTop: 18, fontSize: 13 }}>
        Each alert is sent once per connector. At most 10 go out per collection run; the rest are summed up in one line.
        A webhook address lets anyone who has it post to your channel, so it is stored privately and only its ends are shown.
      </p>
    </>
  );
}

export default function ConnectorsPage() {
  return (
    <Gate title="Connectors" why="Send the alerts you care about to Slack, Discord, Teams or email.">
      <Connectors />
    </Gate>
  );
}
