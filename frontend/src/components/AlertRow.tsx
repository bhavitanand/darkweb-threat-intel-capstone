import { ArrowUpRight, ChevronRight } from 'lucide-react';
import type { Alert } from '../types';
import { alertPath } from '../store';
import { categoryLabel, timeAgo } from '../lib';
import { Chip, ScoreRing, SeverityChip } from './ui';

/** One alert in a list. The whole row opens the DarkLens report; the "Original" link opens the source's own page. */
export function AlertRow({ a }: { a: Alert }) {
  return (
    <div className="alert-row">
      <ScoreRing score={a.score} severity={a.severity} size={52} />
      <div className="alert-main">
        <a className="alert-title stretch" href={`#${alertPath(a.item_id)}`} style={{ display: 'block', color: 'inherit', textDecoration: 'none' }}>
          {a.title || '(untitled post)'}
        </a>
        <div className="alert-meta">
          <SeverityChip severity={a.severity} />
          <Chip>{categoryLabel(a.category)}</Chip>
          {a.demo && <Chip tone="info">Demo</Chip>}
          <span>{a.org ? `About ${a.org}` : a.actor ? `By ${a.actor}` : a.source}</span>
          <span>{timeAgo(a.seen_at)}</span>
        </div>
      </div>
      <div className="alert-side">
        {a.url ? (
          <a className="src-link" href={a.url} target="_blank" rel="noreferrer noopener" aria-label={`Original report: ${a.title}`}>
            Original <ArrowUpRight size={14} aria-hidden="true" />
          </a>
        ) : (
          <ChevronRight size={18} aria-hidden="true" className="muted" />
        )}
      </div>
    </div>
  );
}
