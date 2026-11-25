import { useEffect, useState } from 'react';
import { BellRing, Inbox, Network, Plug, Radio, ScanSearch } from 'lucide-react';
import { BASE } from './api';
import { RANSOMWARE_LIVE_URL, REPO_URL } from './lib';
import { useRoute } from './store';
import type { Route } from './store';
import { useSession } from './session';
import Loader from './components/Loader';
import Landing from './pages/Landing';
import Home from './pages/Home';
import Rules from './pages/Rules';
import Alerts from './pages/Alerts';
import AlertReport from './pages/AlertReport';
import Graph from './pages/Graph';
import Connectors from './pages/Connectors';
import Analyse from './pages/Analyse';
import SignIn from './pages/SignIn';
import Workspace from './pages/Workspace';

const DEFAULT_TITLE = document.title;

/** Signed in, the menu is the product. Signed out, it is the public feed, the post checker and a way in. */
const NAV_IN = [
  { name: 'home', href: '#/home', label: 'My alerts', Icon: Inbox },
  { name: 'rules', href: '#/rules', label: 'Set alerts', Icon: BellRing },
  { name: 'graph', href: '#/graph', label: 'Connections', Icon: Network },
  { name: 'alerts', href: '#/alerts', label: 'Live feed', Icon: Radio },
  { name: 'connectors', href: '#/connectors', label: 'Connectors', Icon: Plug },
  { name: 'analyse', href: '#/analyse', label: 'Check a post', Icon: ScanSearch },
] as const;
const NAV_OUT = [
  { name: 'alerts', href: '#/alerts', label: 'Live feed', Icon: Radio },
  { name: 'graph', href: '#/graph', label: 'Connections', Icon: Network },
  { name: 'analyse', href: '#/analyse', label: 'Check a post', Icon: ScanSearch },
] as const;
const TITLES: Record<string, string> = {
  home: 'My alerts', rules: 'Set alerts', graph: 'Connections', alerts: 'Live feed', connectors: 'Connectors', analyse: 'Check a post',
  workspace: 'Workspace', alert: 'Alert report', signin: 'Sign in',
};

function Status() {
  const [ok, setOk] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    // Check now, every 30 seconds, and when the tab comes back into view: a server that goes down (or wakes up)
    // while the page is open must not leave a stale "online" badge. A check that hangs counts as not reachable.
    const check = () => {
      const ctl = new AbortController();
      const timer = window.setTimeout(() => ctl.abort(), 10000);
      fetch(`${BASE}/api/health`, { signal: ctl.signal })
        .then((r) => live && setOk(r.ok))
        .catch(() => live && setOk(false))
        .finally(() => window.clearTimeout(timer));
    };
    check();
    const every = window.setInterval(check, 30000);
    const onVisible = () => document.visibilityState === 'visible' && check();
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      live = false;
      window.clearInterval(every);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, []);
  const text = ok === null ? 'Connecting' : ok ? 'Live' : 'Server not reachable';
  return (
    <span className="status" role="status" title={ok ? 'The DarkLens server is online' : undefined}>
      <span className={`dot ${ok === null ? '' : ok ? 'dot-ok' : 'dot-bad'}`} aria-hidden="true" />
      <span className="label">{text}</span>
    </span>
  );
}

function page(route: Route, signedIn: boolean) {
  switch (route.name) {
    case 'home': return <Home />;
    case 'rules': return <Rules />;
    case 'alerts': return <Alerts />;
    case 'alert': return <AlertReport id={route.id} />;
    case 'graph': return <Graph />;
    case 'connectors': return <Connectors />;
    case 'analyse': return <Analyse />;
    case 'signin': return <SignIn token={route.token} />;
    case 'workspace': return <Workspace />;
    default: return signedIn ? <Home /> : <Landing />;
  }
}

export default function App() {
  const route = useRoute();
  const { signedIn, email } = useSession();
  const current = route.name === 'alert' ? 'alerts' : route.name === 'signin' ? 'workspace' : route.name === 'overview' && signedIn ? 'home' : route.name;
  const nav = signedIn ? NAV_IN : NAV_OUT;

  useEffect(() => {
    if (!route.name.startsWith('alert')) window.scrollTo(0, 0);
    const label = TITLES[current];
    document.title = !label ? DEFAULT_TITLE : `${label} | DarkLens`;
    // On a phone the menu scrolls sideways: keep the current page's tab in view.
    document.querySelector<HTMLElement>('.nav a[aria-current="page"]')?.scrollIntoView({ inline: 'center', block: 'nearest' });
  }, [route, current]);

  return (
    <>
      <Loader />
      <a className="skip" href="#main" onClick={(e) => { e.preventDefault(); document.getElementById('main')?.focus(); }}>Skip to content</a>
      <header className="topbar">
        <div className="topbar-inner">
          <a className="brand" href="#/" aria-label="DarkLens home">
            <img src="/logo.svg" alt="" />
            <span>DarkLens</span>
          </a>
          <nav className="nav" aria-label="Main">
            {nav.map(({ name, href, label, Icon }) => (
              <a key={name} href={href} aria-current={current === name ? 'page' : undefined}>
                <Icon size={16} aria-hidden="true" /> {label}
              </a>
            ))}
          </nav>
          <div className="top-actions">
            <Status />
            {signedIn ? (
              <a className="avatar" href="#/workspace" aria-label="Your workspace" title={email || 'Your workspace'} aria-current={current === 'workspace' ? 'page' : undefined}>
                {(email || '?').slice(0, 1).toUpperCase()}
              </a>
            ) : (
              <a className="btn btn-sm" href="#/workspace">Sign in</a>
            )}
          </div>
        </div>
      </header>
      <main id="main" tabIndex={-1} className="page">
        {page(route, signedIn)}
      </main>
      <footer className="footer">
        DarkLens is a Samsung Innovation Campus capstone project. Alerts marked Demo are made up. It reads text only and
        never stores real stolen data. Live ransomware claims: source{' '}
        <a href={RANSOMWARE_LIVE_URL} target="_blank" rel="noreferrer">Ransomware.live</a> (non-commercial use). Data breaches:{' '}
        <a href="https://haveibeenpwned.com" target="_blank" rel="noreferrer">Have I Been Pwned</a> (CC BY 4.0). Phishing:{' '}
        <a href="https://openphish.com" target="_blank" rel="noreferrer">OpenPhish</a>. Botnets, malware links and indicators:{' '}
        <a href="https://abuse.ch" target="_blank" rel="noreferrer">abuse.ch</a>. News headlines link to their sources.{' '}
        <a href={REPO_URL} target="_blank" rel="noreferrer">Source and documentation on GitHub</a>.
      </footer>
    </>
  );
}
