import { describe, expect, it } from 'vitest';
import { alertPath, parseRoute } from './store';

describe('parseRoute', () => {
  it('defaults to the overview', () => {
    expect(parseRoute('')).toEqual({ name: 'overview' });
    expect(parseRoute('#/')).toEqual({ name: 'overview' });
    expect(parseRoute('#/nonsense')).toEqual({ name: 'overview' });
  });
  it('knows each page', () => {
    expect(parseRoute('#/alerts')).toEqual({ name: 'alerts' });
    expect(parseRoute('#/graph')).toEqual({ name: 'graph' });
    expect(parseRoute('#/home')).toEqual({ name: 'home' });
    expect(parseRoute('#/rules')).toEqual({ name: 'rules' });
    expect(parseRoute('#/connectors')).toEqual({ name: 'connectors' });
    expect(parseRoute('#/analyse')).toEqual({ name: 'analyse' });
    // pages removed in 0.4 send old links somewhere useful instead of breaking
    expect(parseRoute('#/watchlist')).toEqual({ name: 'rules' });
    expect(parseRoute('#/learn')).toEqual({ name: 'overview' });
    expect(parseRoute('#/start')).toEqual({ name: 'overview' });
  });
  it('round-trips an alert id, including odd characters', () => {
    expect(parseRoute('#' + alertPath('abc123'))).toEqual({ name: 'alert', id: 'abc123' });
    expect(parseRoute('#' + alertPath('a b/c'))).toEqual({ name: 'alert', id: 'a b/c' });
  });
});
