import { describe, expect, it } from 'vitest';
import { buildClusters } from './graph';
import { describeSpec, isEmptySpec } from './rules';
import { hostOf } from './lib';
import type { GraphLink, GraphNode, RuleSpec } from './types';

const item = (id: string, score = 50): GraphNode => ({ id: `item:${id}`, kind: 'item', label: id, score });
const clue = (id: string, kind: GraphNode['kind'] = 'btc'): GraphNode => ({ id, kind, label: id });
const link = (a: string, b: string): GraphLink => ({ source: `item:${a}`, target: b, rel: 'mentions' });

describe('buildClusters', () => {
  it('keeps only alerts that share a clue, and drops clues that belong to one alert', () => {
    const nodes = [item('a', 90), item('b'), item('c'), clue('btc:1'), clue('org:x', 'org'), clue('org:y', 'org')];
    const links = [link('a', 'btc:1'), link('b', 'btc:1'), link('a', 'org:x'), link('c', 'org:y')];
    const { clusters } = buildClusters(nodes, links, 1000);
    expect(clusters).toHaveLength(1);
    const ids = clusters[0].nodes.map((n) => n.id).sort();
    expect(ids).toEqual(['btc:1', 'item:a', 'item:b']);
    expect(clusters[0].items).toBe(2);
    expect(clusters[0].shared.map((s) => s.id)).toEqual(['btc:1']);
  });

  it('can be narrowed to groups around chosen alerts, and puts the most serious group first', () => {
    const nodes = [item('a', 30), item('b', 30), item('c', 95), item('d', 20), clue('btc:1'), clue('btc:2')];
    const links = [link('a', 'btc:1'), link('b', 'btc:1'), link('c', 'btc:2'), link('d', 'btc:2')];
    const all = buildClusters(nodes, links, 1000).clusters;
    expect(all.map((c) => c.maxScore)).toEqual([95, 30]);
    const mine = buildClusters(nodes, links, 1000, (id) => id === 'a').clusters;
    expect(mine).toHaveLength(1);
    expect(mine[0].nodes.some((n) => n.id === 'item:a')).toBe(true);
  });

  it('places every group inside the width and returns an empty map for no data', () => {
    const nodes = Array.from({ length: 40 }, (_, i) => item(String(i))).concat(Array.from({ length: 20 }, (_, i) => clue(`btc:${i}`)));
    const links = Array.from({ length: 40 }, (_, i) => link(String(i), `btc:${Math.floor(i / 2)}`));
    const { clusters, height } = buildClusters(nodes, links, 800);
    expect(clusters).toHaveLength(20);
    for (const c of clusters) expect(c.x + c.w).toBeLessThanOrEqual(800);
    expect(height).toBeGreaterThan(0);
    expect(buildClusters([], [], 800)).toEqual({ clusters: [], height: 0 });
  });
});

const spec = (s: Partial<RuleSpec>): RuleSpec => ({
  products: [], keywords: [], attacks: [], categories: [], cves: [], domains: [], emails: [], min_severity: 'medium', ...s,
});

describe('describeSpec', () => {
  it('says the rule in one sentence, like the server', () => {
    expect(describeSpec(spec({ products: ['wordpress', 'php'], attacks: ['rce'] })))
      .toBe('Alert on remote code execution about wordpress or php, rated Medium or worse.');
    expect(describeSpec(spec({ categories: ['credential_dump'], domains: ['acme.com'], min_severity: 'critical' })))
      .toBe('Alert on leaked logins or data that also mentions acme.com, rated Critical.');
    expect(describeSpec(spec({ cves: ['CVE-2024-4577'], min_severity: 'low' }))).toBe('Alert on anything that mentions CVE-2024-4577, of any severity.');
  });

  it('knows when there is nothing to look for', () => {
    expect(isEmptySpec(spec({}))).toBe(true);
    expect(isEmptySpec(spec({ keywords: ['bank'] }))).toBe(false);
  });
});

describe('hostOf', () => {
  it('names the site of an original report', () => {
    expect(hostOf('https://www.bleepingcomputer.com/news/x')).toBe('bleepingcomputer.com');
    expect(hostOf('not a url', 'rss')).toBe('rss');
  });
});
