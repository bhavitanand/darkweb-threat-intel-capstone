import { describe, expect, it } from 'vitest';
import { alertQueryString } from './api';
import { categoryBlurb, categoryLabel, cleanWatchValue, filterAlerts, iocLabel, layoutGraph, mostWorrying, pct, severityFromScore, severityMeta, splitRule, timeAgo } from './lib';
import { alertPath, parseRoute } from './store';
import type { Alert, GraphLink, GraphNode } from './types';

const alert = (o: Partial<Alert>): Alert => ({
  item_id: 'x', score: 10, severity: 'low', category: 'benign', title: 't', text: '', source: 's', url: null, seen_at: null,
  actor: null, org: null, country: null, demo: false, confidence: 0.5, signals: [], probs: {}, iocs: {}, restricted: false, ...o,
} as unknown as Alert);

describe('parseRoute with hostile links', () => {
  it.each(['', '#', '#/', '##/', '#//', '#///alerts', '#/ALERTS', '#/alerts?x=1', '#/alerts/', '#/nope', '#/' + 'a'.repeat(5000), '#/\u0000', '#/💀'])(
    'never throws for %s',
    (h) => {
      expect(() => parseRoute(h)).not.toThrow();
      expect(parseRoute(h).name).toBeTruthy();
    },
  );
  it('does not crash on invalid percent-encoding in an alert link', () => {
    for (const bad of ['%E0%A4%A', '%', '%%', '%zz', '%C0%AF', '%F0%9F%92']) {
      const r = parseRoute(`#/alerts/${bad}`);
      expect(r.name).toBe('alert');
    }
  });
  it('round-trips ids with slashes, spaces and unicode', () => {
    for (const id of ['abc123', 'a/b', 'a b', 'ünï💀', 'a?b#c', '%41']) {
      const r = parseRoute(`#${alertPath(id)}`);
      expect(r).toEqual({ name: 'alert', id });
    }
  });
  it('a trailing slash is the list, extra segments are part of the id', () => {
    expect(parseRoute('#/alerts/').name).toBe('alerts');
    expect(parseRoute('#/alerts/a/b')).toEqual({ name: 'alert', id: 'a/b' });
  });
});

describe('timeAgo with odd dates', () => {
  const now = Date.parse('2026-11-17T12:00:00Z');
  it('handles missing, invalid and absurd values', () => {
    for (const v of [null, undefined, '', 'garbage', 'NaN', '2026-13-45', 'undefined']) expect(timeAgo(v, now)).toBe('date unknown');
    expect(() => timeAgo('9999-12-31', now)).not.toThrow();
    expect(() => timeAgo('0001-01-01', now)).not.toThrow();
  });
  it('a date in the future is "just now", never negative', () => {
    expect(timeAgo('2027-01-01T00:00:00Z', now)).toBe('just now');
  });
  it('uses singular and plural', () => {
    expect(timeAgo('2026-11-17T11:00:00Z', now)).toBe('1 hour ago');
    expect(timeAgo('2026-11-17T09:00:00Z', now)).toBe('3 hours ago');
    expect(timeAgo('2026-11-16T12:00:00Z', now)).toBe('1 day ago');
  });
});

describe('filtering and ranking odd alerts', () => {
  it('does not fail on missing optional fields or an empty list', () => {
    expect(filterAlerts([], { severity: '', category: '', q: 'x' })).toEqual([]);
    const a = alert({ actor: null, org: null, title: undefined as unknown as string, text: undefined as unknown as string });
    expect(() => filterAlerts([a], { severity: '', category: '', q: 'abc' })).not.toThrow();
  });
  it('search is case-insensitive, trimmed, and treats regex characters literally', () => {
    const rows = [alert({ item_id: '1', title: 'Fortinet (VPN) [0day] a+b' }), alert({ item_id: '2', title: 'other' })];
    for (const q of ['  FORTINET ', '(vpn)', '[0day]', 'a+b', '.*', '\\']) {
      const got = filterAlerts(rows, { severity: '', category: '', q }).map((r) => r.item_id);
      expect(got).not.toContain('2');
    }
  });
  it('mostWorrying copes with fewer alerts than asked and with ties', () => {
    expect(mostWorrying([], 5)).toEqual([]);
    expect(mostWorrying([alert({ item_id: '1' })], 5)).toHaveLength(1);
    expect(mostWorrying([alert({ item_id: '1', demo: true }), alert({ item_id: '2', demo: false })], 5).map((a) => a.item_id)).toEqual(['2']);
  });
});

describe('small helpers', () => {
  it('severity thresholds match the backend at every boundary', () => {
    expect([0, 39, 40, 64, 65, 84, 85, 100].map(severityFromScore)).toEqual(['low', 'low', 'medium', 'medium', 'high', 'high', 'critical', 'critical']);
    expect(severityFromScore(-5)).toBe('low');
    expect(severityFromScore(Number.NaN)).toBe('low');
  });
  it('unknown categories, severities and rule names fall back instead of throwing', () => {
    expect(categoryLabel('weird_new_type')).toBeTruthy();
    expect(categoryBlurb('weird_new_type')).toBeDefined();
    expect(severityMeta('nonsense').label).toBeTruthy();
    expect(iocLabel('mystery')).toBe('mystery');
    expect(splitRule('')).toEqual({ code: '', title: '' });
    expect(splitRule('DL-EXP-001 Zero-day or exploit')).toEqual({ code: 'DL-EXP-001', title: 'Zero-day or exploit' });
    expect(splitRule('DL-EXP-001')).toEqual({ code: '', title: 'DL-EXP-001' });
  });
  it('pct rounds and never prints NaN for ordinary numbers', () => {
    expect(pct(0)).toBe('0%');
    expect(pct(1)).toBe('100%');
    expect(pct(0.8366, 1)).toBe('83.7%');
  });
});

describe('cleanWatchValue edge cases', () => {
  it.each([
    ['domain', 'Example.COM', 'example.com'], ['domain', ' https://example.com/path?x=1 ', 'example.com'], ['domain', 'a.b.c.example.co.uk', 'a.b.c.example.co.uk'],
    ['domain', 'example.com.', null], ['domain', 'exa mple.com', null], ['domain', '-bad.com', null], ['domain', 'bad-.com', null], ['domain', 'a'.repeat(64) + '.com', null], ['domain', 'münchen.de', null], ['domain', '1.2.3.4', null],
    ['domain', '', null], ['domain', '   ', null], ['domain', 'localhost', null], ['domain', 'example.com:8080', null],
    ['email', 'A@B.CO', 'a@b.co'], ['email', 'a b@c.com', null], ['email', 'a@@b.com', null], ['email', '@b.com', null], ['email', 'a@b', null], ['email', '', null],
    ['product', 'c++', 'c++'], ['product', '.net', null], ['product', 'log4j', 'log4j'], ['product', 'a  b', 'a b'], ['product', 'ab', null], ['product', 'x'.repeat(61), null],
    ['product', '-bad', null], ['product', '💀💀💀', null], ['product', "a'; --", null], ['product', 'node.js', 'node.js'], ['product', '7-zip', '7-zip'],
  ] as const)('%s %j -> %j', (kind, raw, want) => {
    expect(cleanWatchValue(kind, raw)).toBe(want);
  });
});

describe('alertQueryString', () => {
  it('encodes hostile values and omits unset ones', () => {
    const q = alertQueryString({ q: '%&=?# \u0000💀', severity: undefined, limit: 5, offset: 0 });
    expect(q).toContain('limit=5');
    expect(q).toContain('offset=0');
    expect(q).not.toContain('severity');
    expect(new URLSearchParams(q.slice(1)).get('q')).toBe('%&=?# \u0000💀');
  });
});

describe('layoutGraph edge cases', () => {
  const node = (id: string): GraphNode => ({ id, kind: 'actor', label: id });
  const finite = (pts: { x: number; y: number }[]) => pts.every((p) => Number.isFinite(p.x) && Number.isFinite(p.y));
  it('empty, single node and no links', () => {
    expect(layoutGraph([], [], 800, 600)).toEqual([]);
    const one = layoutGraph([node('a')], [], 800, 600);
    expect(one).toHaveLength(1);
    expect(finite(one)).toBe(true);
  });
  it('duplicate ids, self loops, links to missing nodes and repeated links', () => {
    const links: GraphLink[] = [{ source: 'a', target: 'a' }, { source: 'a', target: 'ghost' }, { source: 'a', target: 'b' }, { source: 'a', target: 'b' }] as GraphLink[];
    const pts = layoutGraph([node('a'), node('a'), node('b')], links, 800, 600);
    expect(pts).toHaveLength(3);
    expect(finite(pts)).toBe(true);
  });
  it('degenerate canvas sizes do not produce NaN', () => {
    for (const [w, h] of [[0, 0], [1, 1], [10, 0], [0, 10]]) expect(finite(layoutGraph([node('a'), node('b'), node('c')], [{ source: 'a', target: 'b' } as GraphLink], w, h))).toBe(true);
  });
  it('is deterministic and stays fast for a big graph', () => {
    const nodes = Array.from({ length: 1500 }, (_, i) => node(`n${i}`));
    const links = Array.from({ length: 1500 }, (_, i) => ({ source: `n${i}`, target: `n${(i * 7 + 1) % 1500}` }) as GraphLink);
    const t = performance.now();
    const a = layoutGraph(nodes, links, 900, 600);
    const took = performance.now() - t;
    expect(took).toBeLessThan(5000);
    expect(layoutGraph(nodes.slice(0, 30), links.slice(0, 30), 900, 600)).toEqual(layoutGraph(nodes.slice(0, 30), links.slice(0, 30), 900, 600));
    expect(finite(a)).toBe(true);
  });
});

import { describeDetail } from './api';

describe('describeDetail turns every server error shape into a sentence', () => {
  it('passes a plain string through', () => {
    expect(describeDetail('That does not look like a valid domain.', 400)).toBe('That does not look like a valid domain.');
  });
  it('explains a too-long body instead of printing [object Object]', () => {
    const d = [{ type: 'string_too_long', loc: ['body', 'text'], msg: 'String should have at most 20000 characters', ctx: { max_length: 20000 } }];
    expect(describeDetail(d, 422)).toContain('20,000 characters');
  });
  it('uses the message and field for other validation errors', () => {
    const out = describeDetail([{ type: 'missing', loc: ['body', 'text'], msg: 'Field required' }], 422);
    expect(out).toContain('text') ;
    expect(out).toContain('Field required');
  });
  it('never returns an object string, whatever it is given', () => {
    for (const v of [undefined, null, 5, {}, [], [null], [1, 2], [{}], { a: 1 }]) {
      expect(describeDetail(v, 422)).not.toContain('[object');
    }
    expect(describeDetail(undefined, 500)).toBe('');
  });
});
