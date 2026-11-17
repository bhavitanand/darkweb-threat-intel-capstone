import { describe, expect, it } from 'vitest';
import { alertQueryString } from './api';

describe('alertQueryString', () => {
  it('is empty when nothing is set', () => {
    expect(alertQueryString({})).toBe('');
    expect(alertQueryString({ severity: '', q: '', data: undefined })).toBe('');
  });
  it('keeps only the filters that are set, and encodes them', () => {
    expect(alertQueryString({ severity: 'high', q: 'a b&c', limit: 100, offset: 0 })).toBe('?severity=high&q=a+b%26c&limit=100&offset=0');
  });
});
