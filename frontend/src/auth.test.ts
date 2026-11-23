import { afterEach, describe, expect, it, vi } from 'vitest';
import { getToken, setToken } from './auth';
import { parseRoute } from './store';
import { api } from './api';

afterEach(() => {
  setToken(null);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('sign-in routes', () => {
  it('reads the token from the link', () => {
    expect(parseRoute('#/signin?token=abc123')).toEqual({ name: 'signin', token: 'abc123' });
  });
  it('treats a missing or broken token as empty without throwing', () => {
    expect(parseRoute('#/signin')).toEqual({ name: 'signin', token: '' });
    expect(parseRoute('#/signin?token=%E0%A4%A')).toMatchObject({ name: 'signin' });
  });
  it('still routes the workspace', () => {
    expect(parseRoute('#/workspace')).toEqual({ name: 'workspace' });
    expect(parseRoute('#/workspace?x=1')).toEqual({ name: 'workspace' });
  });
});

describe('session storage', () => {
  it('keeps the token and forgets it', () => {
    setToken('t1');
    expect(getToken()).toBe('t1');
    setToken(null);
    expect(getToken()).toBeNull();
  });
  it('still works when storage is blocked', () => {
    const blocked = { getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); }, removeItem: () => { throw new Error('blocked'); } };
    vi.stubGlobal('window', { ...globalThis.window, localStorage: blocked, addEventListener: () => undefined, removeEventListener: () => undefined });
    expect(() => setToken('t2')).not.toThrow();
    expect(getToken()).toBe('t2');
  });
});

describe('authenticated calls', () => {
  it('sends the session as a bearer header', async () => {
    setToken('t3');
    const f = vi.fn().mockResolvedValue(new Response(JSON.stringify({ email: 'a@b.co' }), { status: 200 }));
    vi.stubGlobal('fetch', f);
    await api.me();
    const init = f.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer t3');
  });
  it('forgets the session after a 401', async () => {
    setToken('t4');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: 'Sign in again.' }), { status: 401 })));
    await expect(api.me()).rejects.toThrow('Sign in again.');
    expect(getToken()).toBeNull();
  });
  it('sends no header when signed out', async () => {
    const f = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', f);
    await api.me();
    expect((f.mock.calls[0][1] as RequestInit).headers as Record<string, string>).not.toHaveProperty('Authorization');
  });
});
