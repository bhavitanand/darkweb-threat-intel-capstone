import { describe, expect, it } from 'vitest';
import {
  categoryLabel, cleanWatchValue, filterAlerts, iocLabel, layoutGraph, mostWorrying, needsRansomwareLiveCredit, severityFromScore, severityMeta, splitRule, timeAgo,
} from './lib';
import type { Alert, GraphLink, GraphNode } from './types';

const mk = (over: Partial<Alert>): Alert => ({
  item_id: 'a', score: 10, severity: 'low', category: 'benign', confidence: 0.9, signals: [], probs: {},
  source: 's', kind: 'post', title: 't', text: '', url: null, seen_at: null, actor: null, org: null,
  country: null, iocs: {}, demo: false, restricted: false, ...over,
});

describe('labels', () => {
  it('uses plain names for known categories and prettifies unknown ones', () => {
    expect(categoryLabel('credential_dump')).toBe('Stolen logins');
    expect(categoryLabel('new_thing')).toBe('New thing');
    expect(categoryLabel('ioc_feed')).toBe('Known bad indicator');
    expect(categoryLabel('uncertain')).toBe('Not sure');
  });
  it('falls back to low for an unknown severity', () => {
    expect(severityMeta('weird').label).toBe('Low');
    expect(severityMeta('critical').tone).toBe('danger');
  });
  it('names indicator types in plain words', () => {
    expect(iocLabel('btc')).toBe('Bitcoin address');
    expect(iocLabel('zzz')).toBe('zzz');
  });
});

describe('splitRule', () => {
  it('separates a rule code from its title and leaves other names alone', () => {
    expect(splitRule('DL-EXP-001 Zero-day or exploit for sale')).toEqual({ code: 'DL-EXP-001', title: 'Zero-day or exploit for sale' });
    expect(splitRule('Classifier')).toEqual({ code: '', title: 'Classifier' });
  });
});

describe('severityFromScore', () => {
  it('matches the backend thresholds at every edge', () => {
    expect(severityFromScore(0)).toBe('low');
    expect(severityFromScore(39)).toBe('low');
    expect(severityFromScore(40)).toBe('medium');
    expect(severityFromScore(64)).toBe('medium');
    expect(severityFromScore(65)).toBe('high');
    expect(severityFromScore(84)).toBe('high');
    expect(severityFromScore(85)).toBe('critical');
    expect(severityFromScore(100)).toBe('critical');
  });
});

describe('timeAgo', () => {
  const now = Date.parse('2026-11-16T12:00:00Z');
  it('handles missing and bad dates', () => {
    expect(timeAgo(null, now)).toBe('date unknown');
    expect(timeAgo('nope', now)).toBe('date unknown');
  });
  it('speaks in minutes, hours and days', () => {
    expect(timeAgo('2026-11-16T11:59:50Z', now)).toBe('just now');
    expect(timeAgo('2026-11-16T11:30:00Z', now)).toBe('30 min ago');
    expect(timeAgo('2026-11-16T11:00:00Z', now)).toBe('1 hour ago');
    expect(timeAgo('2026-11-14T12:00:00Z', now)).toBe('2 days ago');
  });
});

describe('filterAlerts', () => {
  const list = [
    mk({ item_id: '1', score: 20, severity: 'low', title: 'Cat photos' }),
    mk({ item_id: '2', score: 90, severity: 'critical', category: 'ransomware_leak', title: 'Acme leak', org: 'Acme' }),
    mk({ item_id: '3', score: 60, severity: 'medium', category: 'credential_dump', title: 'Combo list' }),
  ];
  it('sorts by score, highest first', () => {
    expect(filterAlerts(list, { severity: '', category: '', q: '' }).map((a) => a.item_id)).toEqual(['2', '3', '1']);
  });
  it('filters by severity, category and text', () => {
    expect(filterAlerts(list, { severity: 'medium', category: '', q: '' })).toHaveLength(1);
    expect(filterAlerts(list, { severity: '', category: 'ransomware_leak', q: '' })[0].item_id).toBe('2');
    expect(filterAlerts(list, { severity: '', category: '', q: ' ACME ' })[0].item_id).toBe('2');
    expect(filterAlerts(list, { severity: 'low', category: 'ransomware_leak', q: '' })).toHaveLength(0);
  });
});

describe('filterAlerts by data source', () => {
  const list = [mk({ item_id: 'd', demo: true, score: 50 }), mk({ item_id: 'r', demo: false, score: 40 })];
  it('separates real feeds from the demo samples', () => {
    const f = { severity: '', category: '', q: '' };
    expect(filterAlerts(list, { ...f, data: 'real' }).map((a) => a.item_id)).toEqual(['r']);
    expect(filterAlerts(list, { ...f, data: 'demo' }).map((a) => a.item_id)).toEqual(['d']);
    expect(filterAlerts(list, { ...f, data: '' })).toHaveLength(2);
    expect(filterAlerts(list, f)).toHaveLength(2);
  });
});

describe('needsRansomwareLiveCredit', () => {
  it('is true only when a Ransomware.live item is on the page', () => {
    expect(needsRansomwareLiveCredit([mk({ source: 'ransomware.live' }), mk({ source: 'forum' })])).toBe(true);
    expect(needsRansomwareLiveCredit([mk({ source: 'threatfox' })])).toBe(false);
    expect(needsRansomwareLiveCredit([])).toBe(false);
  });
});

describe('mostWorrying', () => {
  const demoHigh = mk({ item_id: 'd', demo: true, score: 95 });
  const realLow = mk({ item_id: 'r1', demo: false, score: 30 });
  const realHigh = mk({ item_id: 'r2', demo: false, score: 70 });
  it('puts real alerts ahead of higher-scoring demo ones', () => {
    expect(mostWorrying([demoHigh, realLow, realHigh]).map((a) => a.item_id)).toEqual(['r2', 'r1']);
  });
  it('falls back to demo alerts when nothing is real, and caps the list', () => {
    expect(mostWorrying([demoHigh]).map((a) => a.item_id)).toEqual(['d']);
    expect(mostWorrying(Array.from({ length: 9 }, (_, i) => mk({ item_id: String(i), score: i })))).toHaveLength(5);
    expect(mostWorrying([])).toEqual([]);
  });
});

describe('cleanWatchValue', () => {
  it('accepts domains and strips scheme and path', () => {
    expect(cleanWatchValue('domain', 'https://Example.com/login')).toBe('example.com');
    expect(cleanWatchValue('domain', 'sub.example.co.uk')).toBe('sub.example.co.uk');
  });
  it('rejects things that are not domains or emails', () => {
    expect(cleanWatchValue('domain', 'not a domain')).toBeNull();
    expect(cleanWatchValue('domain', 'localhost')).toBeNull();
    expect(cleanWatchValue('email', 'a@b')).toBeNull();
    expect(cleanWatchValue('email', ' Me@Example.com ')).toBe('me@example.com');
  });
});

describe('layoutGraph', () => {
  const nodes: GraphNode[] = ['a', 'b', 'c', 'd'].map((id) => ({ id, kind: 'actor', label: id }));
  const links: GraphLink[] = [
    { source: 'a', target: 'b', rel: 'x' },
    { source: 'b', target: 'c', rel: 'x' },
    { source: 'c', target: 'zzz', rel: 'x' }, // dangling link is ignored
  ];
  it('keeps every node inside the canvas and is deterministic', () => {
    const one = layoutGraph(nodes, links, 600, 400);
    const two = layoutGraph(nodes, links, 600, 400);
    expect(one).toEqual(two);
    for (const p of one) {
      expect(p.x).toBeGreaterThanOrEqual(24);
      expect(p.x).toBeLessThanOrEqual(576);
      expect(p.y).toBeGreaterThanOrEqual(24);
      expect(p.y).toBeLessThanOrEqual(376);
      expect(Number.isFinite(p.x + p.y)).toBe(true);
    }
  });
  it('pulls linked nodes closer than an unlinked one', () => {
    const p = Object.fromEntries(layoutGraph(nodes, links, 600, 400).map((n) => [n.id, n]));
    const dist = (a: string, b: string) => Math.hypot(p[a].x - p[b].x, p[a].y - p[b].y);
    expect(dist('a', 'b')).toBeLessThan(dist('a', 'd') + 200);
  });
  it('stays fast and valid on a large graph', () => {
    const many: GraphNode[] = Array.from({ length: 1500 }, (_, i) => ({ id: `n${i}`, kind: 'item' as const, label: `n${i}`, score: i % 100 }));
    const lnk: GraphLink[] = many.slice(1).map((n, i) => ({ source: n.id, target: `n${Math.floor(i / 3)}`, rel: 'x' }));
    const start = Date.now();
    const placed = layoutGraph(many, lnk, 960, 560);
    expect(Date.now() - start).toBeLessThan(5000);
    expect(placed).toHaveLength(1500);
    expect(placed.every((p) => Number.isFinite(p.x) && Number.isFinite(p.y))).toBe(true);
  });
  it('handles an empty graph', () => {
    expect(layoutGraph([], [], 600, 400)).toEqual([]);
  });
});
