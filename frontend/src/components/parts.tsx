import type { Iocs, Signal } from '../types';
import { categoryBlurb, categoryLabel, iocLabel, pct, severityMeta, splitRule } from '../lib';
import { Bar, Chip, ScoreRing } from './ui';

export function SignalList({ signals }: { signals: Signal[] }) {
  if (!signals.length) {
    return <p className="muted">Nothing suspicious was found, so there is nothing adding to the score.</p>;
  }
  const sorted = [...signals].sort((a, b) => b.score - a.score);
  return (
    <ul className="signals">
      {sorted.map((s, i) => (
        <li key={`${s.name}-${i}`}>
          <div className="signal-top">
            <strong>
              {splitRule(s.name).title}
              {splitRule(s.name).code && <span className="mono muted rule-code"> {splitRule(s.name).code}</span>}
            </strong>
            <span className="mono muted">{s.score}/100</span>
          </div>
          <Bar value={s.score} tone={s.score >= 85 ? 'danger' : s.score >= 65 ? 'orange' : s.score >= 40 ? 'caution' : 'safe'} label={`${s.name}: ${s.score} out of 100`} />
          <p>{s.why}</p>
          {s.evidence && (
            <p className="muted">
              Seen: <code className="mono">{s.evidence}</code>
            </p>
          )}
        </li>
      ))}
    </ul>
  );
}

export function IocList({ iocs }: { iocs: Iocs }) {
  const groups = Object.entries(iocs).filter(([, v]) => v && v.length);
  if (!groups.length) return <p className="muted">No wallets, addresses, links or file fingerprints were found in the text.</p>;
  return (
    <div className="ioc-groups">
      {groups.map(([kind, values]) => (
        <div key={kind}>
          <h3>
            {iocLabel(kind)} <span className="muted">({values.length})</span>
          </h3>
          <ul className="ioc-values">
            {values.map((v) => (
              <li key={v} className="mono">{v}</li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

export function ProbBars({ probs }: { probs: Record<string, number> }) {
  const rows = Object.entries(probs).sort((a, b) => b[1] - a[1]);
  return (
    <ul className="probs">
      {rows.map(([k, v]) => (
        <li key={k}>
          <span>{categoryLabel(k)}</span>
          <Bar value={v} max={1} tone="info" label={`${categoryLabel(k)} ${pct(v)}`} />
          <span className="mono muted">{pct(v)}</span>
        </li>
      ))}
    </ul>
  );
}

export function Verdict({
  score, severity, category, confidence,
}: { score: number; severity: string; category: string; confidence: number }) {
  const m = severityMeta(severity);
  return (
    <div className={`hero hero-${m.tone}`}>
      <ScoreRing score={score} severity={severity} size={96} />
      <div className="hero-body">
        <div className="hero-chips">
          <Chip tone={m.tone}>{m.label}</Chip>
          <Chip>{categoryLabel(category)}</Chip>
          <Chip tone="info">{category === 'ioc_feed' ? `Feed confidence ${pct(confidence)}` : `${pct(confidence)} sure of the type`}</Chip>
        </div>
        <h2>{m.verdict}</h2>
        <p>{m.advice}</p>
        {categoryBlurb(category) && <p className="muted">{categoryLabel(category)}: {categoryBlurb(category)}</p>}
      </div>
    </div>
  );
}
