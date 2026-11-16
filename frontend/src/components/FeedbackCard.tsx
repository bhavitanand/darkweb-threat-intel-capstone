import { useState } from 'react';
import { Check, ThumbsDown } from 'lucide-react';
import { api } from '../api';
import { CATEGORY_META, categoryLabel } from '../lib';
import type { FeedbackCounts } from '../types';
import { Section } from './ui';

const KEY = (id: string) => `dl-feedback-${id}`;

function remembered(id: string): string | null {
  try {
    return window.localStorage.getItem(KEY(id));
  } catch {
    return null;
  }
}

function remember(id: string, v: string) {
  try {
    window.localStorage.setItem(KEY(id), v);
  } catch {
    /* private mode: the vote still counted on the server */
  }
}

export default function FeedbackCard({ id, category, counts }: { id: string; category: string; counts: FeedbackCounts }) {
  const [sent, setSent] = useState<string | null>(() => remembered(id));
  const [totals, setTotals] = useState(counts);
  const [fixing, setFixing] = useState(false);
  const [choice, setChoice] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send(verdict: 'correct' | 'wrong', cat = '') {
    setBusy(true);
    setError(null);
    try {
      setTotals(await api.feedback(id, verdict, cat));
      setSent(verdict);
      remember(id, verdict);
      setFixing(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not send that.');
    } finally {
      setBusy(false);
    }
  }

  const options = Object.keys(CATEGORY_META).filter((c) => c !== category);

  return (
    <Section title="Is this right?" hint="Your answer helps measure, and later improve, how well DarkLens sorts posts.">
      {sent ? (
        <p role="status">
          <Check size={16} aria-hidden="true" /> Thanks, that is recorded. Reviewers so far: {totals.correct} said it is
          right, {totals.wrong} said it is wrong.
        </p>
      ) : fixing ? (
        <div className="row">
          <div className="field">
            <label htmlFor="fb-cat">It should have been</label>
            <select id="fb-cat" value={choice} onChange={(e) => setChoice(e.target.value)}>
              <option value="">Choose a type</option>
              {options.map((c) => (
                <option key={c} value={c}>{categoryLabel(c)}</option>
              ))}
            </select>
          </div>
          <button className="btn" disabled={busy || !choice} onClick={() => send('wrong', choice)}>Send correction</button>
          <button className="btn btn-ghost" onClick={() => setFixing(false)}>Cancel</button>
        </div>
      ) : (
        <div className="row">
          <p style={{ margin: 0 }}>
            DarkLens sorted this as <strong>{categoryLabel(category)}</strong>.
          </p>
          <button className="btn btn-ghost" disabled={busy} onClick={() => send('correct')}>
            <Check size={16} aria-hidden="true" /> Yes, that is right
          </button>
          <button className="btn btn-ghost" disabled={busy} onClick={() => setFixing(true)}>
            <ThumbsDown size={16} aria-hidden="true" /> No, it is wrong
          </button>
        </div>
      )}
      {error && <p role="alert" style={{ color: 'var(--danger)' }}>{error}</p>}
    </Section>
  );
}
