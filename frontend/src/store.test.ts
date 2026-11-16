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
    expect(parseRoute('#/watchlist')).toEqual({ name: 'watchlist' });
    expect(parseRoute('#/analyse')).toEqual({ name: 'analyse' });
    expect(parseRoute('#/learn')).toEqual({ name: 'learn' });
    expect(parseRoute('#/start')).toEqual({ name: 'start' });
  });
  it('round-trips an alert id, including odd characters', () => {
    expect(parseRoute('#' + alertPath('abc123'))).toEqual({ name: 'alert', id: 'abc123' });
    expect(parseRoute('#' + alertPath('a b/c'))).toEqual({ name: 'alert', id: 'a b/c' });
  });
});
