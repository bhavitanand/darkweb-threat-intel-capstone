import { useEffect, useState } from 'react';
import { ArrowDown, ArrowRight, Check } from 'lucide-react';
import { api } from '../api';
import { useAsync } from '../hooks';
import { categoryLabel, splitRule, timeAgo } from '../lib';
import type { Alert, ParsedRule } from '../types';
import Pipeline from '../components/Pipeline';
import Specks from '../components/Specks';
import { RuleChips } from '../components/RuleChips';
import { ScoreRing, SeverityChip } from '../components/ui';
import { SignInForm } from './SignIn';

const EXAMPLES = [
  'alert me for any PHP to shell vulnerability in WordPress',
  'ransomware attacks on hospitals, critical only',
  'leaked logins for granite-bank.example',
  'tell me when Fortinet VPN bugs are exploited in the wild',
];

const parseCache = new Map<string, ParsedRule>();

/** A typewriter that cycles through example prompts, and what DarkLens understood from each (asked from the real
 *  parser, so the demo is honest). */
function AskDemo() {
  const [n, setN] = useState(0);
  const [typed, setTyped] = useState('');
  const [parsed, setParsed] = useState<ParsedRule | null>(null);
  const text = EXAMPLES[n % EXAMPLES.length];

  useEffect(() => {
    setParsed(null);
    setTyped('');
    let i = 0;
    const t = window.setInterval(() => {
      i += 1;
      setTyped(text.slice(0, i));
      if (i >= text.length) window.clearInterval(t);
    }, 38);
    return () => window.clearInterval(t);
  }, [text]);

  useEffect(() => {
    if (typed !== text) return;
    let live = true;
    const known = parseCache.get(text);
    if (known) setParsed(known);
    else api.parseRule(text).then((p) => { parseCache.set(text, p); if (live) setParsed(p); }).catch(() => undefined);
    const next = window.setTimeout(() => live && setN((x) => x + 1), 4200);
    return () => {
      live = false;
      window.clearTimeout(next);
    };
  }, [typed, text]);

  return (
    <div className="ask-demo">
      <div className="ask-box" aria-live="off">
        <div className="eyebrow" style={{ marginBottom: 8 }}>You type</div>
        {typed}<span className="caret" aria-hidden="true" />
      </div>
      <div className="ask-parsed">
        <div className="eyebrow">DarkLens understands</div>
        {parsed ? (
          <>
            <RuleChips spec={parsed.spec} />
            <p className="muted" style={{ margin: 0 }}>{parsed.summary}</p>
          </>
        ) : (
          <p className="muted" style={{ margin: 0 }}>Reading…</p>
        )}
      </div>
    </div>
  );
}

function Clipping({ a }: { a: Alert | null }) {
  const why = a ? [...a.signals].sort((x, y) => y.score - x.score).slice(0, 3) : [];
  return (
    <figure className="clip" style={{ margin: 0 }} aria-label="An example alert">
      <div className="clip-head">
        <span className="eyebrow">{a ? (a.demo ? 'Example alert' : 'Top alert right now') : 'Example alert'}</span>
        {a && <SeverityChip severity={a.severity} />}
      </div>
      {a ? (
        <>
          <div className="row" style={{ alignItems: 'flex-start', flexWrap: 'nowrap', gap: 14 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <h3>{a.title}</h3>
              <p>{categoryLabel(a.category)} · {a.org ? `about ${a.org}` : a.source} · {timeAgo(a.seen_at)}</p>
            </div>
            <ScoreRing score={a.score} severity={a.severity} size={62} />
          </div>
          <ul className="clip-why">
            {why.map((s, i) => (
              <li key={i}><span>{splitRule(s.name).title}</span><span className="mono muted">+{s.score}</span></li>
            ))}
          </ul>
        </>
      ) : (
        <>
          <h3>Someone is selling 40,000 logins for granite-bank.example</h3>
          <p>Stolen logins · about Granite Bank · 2 hours ago</p>
          <ul className="clip-why">
            <li><span>Credentials for your domain</span><span className="mono muted">+95</span></li>
            <li><span>Database offered for sale</span><span className="mono muted">+60</span></li>
          </ul>
        </>
      )}
    </figure>
  );
}

export default function Landing() {
  const stats = useAsync(api.stats);
  const top = useAsync(() => api.alerts({ data: 'real', limit: 1 }).then(async (p) => (p.rows[0] ?? (await api.alerts({ limit: 1 })).rows[0] ?? null)));
  const attention = stats.data ? (stats.data.by_severity.critical ?? 0) + (stats.data.by_severity.high ?? 0) : null;
  const today = new Date().toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });

  return (
    <div className="lp">
      <div className="lp-dateline eyebrow">
        <span>Field report</span>
        <span>{today}</span>
        {stats.data && <span>{stats.data.items.toLocaleString()} items read</span>}
        {attention !== null && <span>{attention.toLocaleString()} need attention</span>}
      </div>

      <section className="lp-hero">
        <Specks />
        <div>
          <h1>Know when the dark web is talking about <span className="hl">you</span>.</h1>
          <p className="lede">
            DarkLens reads ransomware leak sites, malware feeds, exploited-flaw lists and security news, scores every item
            from 0 to 100, and explains why in plain words. Tell it what you care about in one sentence, and it tells you when
            it shows up.
          </p>
          <div className="lp-cta">
            <a className="btn btn-brand" href="#join" onClick={(e) => { e.preventDefault(); document.getElementById('join')?.scrollIntoView({ behavior: 'smooth' }); }}>
              Create your workspace <ArrowDown size={16} aria-hidden="true" />
            </a>
            <a className="btn btn-ghost" href="#/alerts">See the live feed <ArrowRight size={16} aria-hidden="true" /></a>
          </div>
        </div>
        <Clipping a={top.data ?? null} />
      </section>

      <section className="lp-section">
        <span className="eyebrow">What it is</span>
        <h2>A threat-intelligence desk for people who don't have one.</h2>
        <div className="lp-cols">
          <div>
            <div className="num">01</div>
            <h3>It reads where attackers talk</h3>
            <p>Leak-site claims, malicious links and files, flaws attackers are using right now, breach notices and security
              news, collected every 30 minutes.</p>
          </div>
          <div>
            <div className="num">02</div>
            <h3>It explains every score</h3>
            <p>Each warning sign adds to the score with a one-line reason, like "countdown to publish stolen data". No black
              box: you see why.</p>
          </div>
          <div>
            <div className="num">03</div>
            <h3>It tells you what is about you</h3>
            <p>Your own alert rules decide what reaches you, in the website, in Slack, Discord or Teams, or as an email
              digest. Each alert links to the original report.</p>
          </div>
        </div>
      </section>

      <section className="lp-section">
        <span className="eyebrow">How it works</span>
        <h2>From a leak site to your phone, in one picture.</h2>
        <div className="pipe-wrap"><Pipeline /></div>
        <div className="pipe-caption">
          <span>Each amber dot is an item moving through the system.</span>
          <span>Scores: 0-39 Low · 40-64 Medium · 65-84 High · 85-100 Critical</span>
        </div>
      </section>

      <section className="lp-section">
        <span className="eyebrow">No forms, no filters</span>
        <h2>Just say what you want to hear about.</h2>
        <AskDemo />
      </section>

      <section className="lp-section" id="join">
        <div className="lp-join">
          <div>
            <span className="eyebrow">Get started</span>
            <h2>Make your workspace. It takes one email.</h2>
            <p className="lede">No password. We email you a sign-in link that works once. Your rules and watchlist are private.</p>
            <ul className="list-rows" style={{ marginTop: 18 }}>
              {[
                'Alerts written as sentences, with editable chips',
                'A feed of only what matches you, worst first, with links to the original reports',
                'Slack, Discord and Teams connectors, and an email digest',
                'A map of connected clues: shared wallets, addresses and files',
                'Read-only API keys for your own scripts',
              ].map((t) => (
                <li key={t}><Check size={16} aria-hidden="true" /> <span className="grow">{t}</span></li>
              ))}
            </ul>
          </div>
          <SignInForm />
        </div>
      </section>
      {stats.data && <p className="muted" style={{ fontSize: 12.5 }}>{stats.data.attribution}</p>}
    </div>
  );
}
