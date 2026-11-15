import { ChevronRight } from 'lucide-react';
import type { Alert } from '../types';
import { alertPath } from '../store';
import { categoryLabel, timeAgo } from '../lib';
import { Chip, ScoreRing, SeverityChip } from './ui';

export function AlertRow({ a }: { a: Alert }) {
  return (
    <a className="alert-row" href={`#${alertPath(a.item_id)}`}>
      <ScoreRing score={a.score} severity={a.severity} size={52} />
      <div className="alert-main">
        <div className="alert-title">{a.title || '(untitled post)'}</div>
        <div className="alert-meta">
          <SeverityChip severity={a.severity} />
          <Chip>{categoryLabel(a.category)}</Chip>
          <span>{a.org ? `About ${a.org}` : a.actor ? `By ${a.actor}` : a.source}</span>
          <span>{timeAgo(a.seen_at)}</span>
        </div>
      </div>
      <ChevronRight size={18} aria-hidden="true" className="muted" />
    </a>
  );
}
