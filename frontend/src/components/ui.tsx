import type { ReactNode } from 'react';
import { AlertTriangle, Loader2 } from 'lucide-react';
import type { Tone } from '../lib';
import { severityMeta } from '../lib';

export function Chip({ tone = 'muted', children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`chip chip-${tone}`}>{children}</span>;
}

export function SeverityChip({ severity }: { severity: string }) {
  const m = severityMeta(severity);
  return <Chip tone={m.tone}>{m.label}</Chip>;
}

export function ScoreRing({ score, severity, size = 64 }: { score: number; severity: string; size?: number }) {
  const tone = severityMeta(severity).tone;
  const r = 15.9155;
  const dash = Math.max(0, Math.min(100, score));
  return (
    <div className={`ring ring-${tone}`} style={{ width: size, height: size }} role="img" aria-label={`Risk score ${score} out of 100`}>
      <svg viewBox="0 0 36 36" aria-hidden="true">
        <circle cx="18" cy="18" r={r} className="ring-track" />
        <circle cx="18" cy="18" r={r} className="ring-fill" strokeDasharray={`${dash} ${100 - dash}`} transform="rotate(-90 18 18)" />
      </svg>
      <span className="ring-num" style={{ fontSize: size * 0.34 }}>{score}</span>
    </div>
  );
}

export function StatTile({ label, value, hint, tone = 'info' }: { label: string; value: ReactNode; hint?: string; tone?: Tone }) {
  return (
    <div className={`tile tile-${tone}`}>
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {hint && <div className="tile-hint">{hint}</div>}
    </div>
  );
}

export function Section({ title, hint, children, aside }: { title: string; hint?: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="card section">
      <header className="section-head">
        <div>
          <h2>{title}</h2>
          {hint && <p className="muted">{hint}</p>}
        </div>
        {aside}
      </header>
      {children}
    </section>
  );
}

export function Bar({ value, max = 100, tone = 'info', label }: { value: number; max?: number; tone?: Tone; label?: string }) {
  const w = max > 0 ? Math.max(0, Math.min(100, (value / max) * 100)) : 0;
  return (
    <div className="bar" role="img" aria-label={label}>
      <div className={`bar-fill bar-${tone}`} style={{ width: `${w}%` }} />
    </div>
  );
}

export function Loading({ slow, what = 'data' }: { slow?: boolean; what?: string }) {
  return (
    <div className="state" role="status">
      <Loader2 className="spin" size={22} aria-hidden="true" />
      <div>
        <strong>Loading {what}...</strong>
        {slow && (
          <p className="muted">
            The free server goes to sleep when nobody is using it and takes up to a minute to wake. Hang on, it will appear on its own.
          </p>
        )}
      </div>
    </div>
  );
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="state state-error" role="alert">
      <AlertTriangle size={22} aria-hidden="true" />
      <div>
        <strong>That did not work</strong>
        <p>{message}</p>
        {onRetry && (
          <button className="btn btn-ghost" onClick={onRetry}>
            Try again
          </button>
        )}
      </div>
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="state state-empty">
      <div>
        <strong>{title}</strong>
        {children && <p className="muted">{children}</p>}
      </div>
    </div>
  );
}

export function PageHead({ title, sub, actions }: { title: string; sub?: string; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <p className="lede">{sub}</p>}
      </div>
      {actions}
    </div>
  );
}
