import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Mail } from 'lucide-react';
import { api } from '../api';
import { setToken } from '../auth';
import { go } from '../store';
import { ErrorBox, Loading, PageHead } from '../components/ui';

/** Spending a sign-in link is one-time, and React may run an effect twice in development, so one request per link. */
const spending = new Map<string, Promise<{ token: string; email: string }>>();

export function SignInForm({ note }: { note?: string }) {
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [done, setDone] = useState<{ message: string; dev_link?: string } | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setProblem(null);
    setBusy(true);
    try {
      setDone(await api.requestLink(email.trim()));
    } catch (err) {
      setProblem(err instanceof Error ? err.message : 'Could not send the link.');
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="card section stack" role="status">
        <strong>Check your email</strong>
        <p>{done.message}</p>
        {done.dev_link && (
          <p className="muted">
            Email is not set up on this server, so for development here is your link:{' '}
            <a href={done.dev_link}>open it</a>.
          </p>
        )}
        <button type="button" className="btn btn-ghost" onClick={() => setDone(null)}>Use a different address</button>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="card section stack" noValidate>
      {note && <p className="muted">{note}</p>}
      <div>
        <label htmlFor="si-email">Your email address</label>
        <input id="si-email" type="email" inputMode="email" autoComplete="email" value={email} maxLength={254}
          onChange={(e) => setEmail(e.target.value)} placeholder="you@yourcompany.com" aria-describedby="si-help" />
        <p id="si-help" className="muted">No password. We email you a link that works once, for 15 minutes.</p>
      </div>
      <button className="btn btn-brand" disabled={busy || !email.trim()}>
        <Mail size={16} aria-hidden="true" /> {busy ? 'Sending...' : 'Email me a sign-in link'}
      </button>
      {problem && <p role="alert" style={{ color: 'var(--danger)' }}>{problem}</p>}
    </form>
  );
}

export default function SignIn({ token }: { token: string }) {
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    let live = true;
    let p = spending.get(token);
    if (!p) {
      p = api.verifyLink(token);
      spending.set(token, p);
    }
    p.then((r) => {
      if (!live) return;
      setToken(r.token);
      go('/workspace');
    }).catch((e: unknown) => live && setError(e instanceof Error ? e.message : 'That link did not work.'));
    return () => {
      live = false;
    };
  }, [token]);

  return (
    <>
      <PageHead title="Sign in" sub="Your own private watchlist, alerts about it, a digest by email, and keys for your own scripts." />
      {token && !error && <Loading what="your sign-in" />}
      {token && error && (
        <div className="stack">
          <ErrorBox message={error} />
          <SignInForm note="Ask for a fresh link below." />
        </div>
      )}
      {!token && <SignInForm />}
    </>
  );
}
