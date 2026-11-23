import { useEffect, useState } from 'react';
import { BookOpen, Briefcase, Compass, Eye, LayoutDashboard, Network, ScanSearch, ShieldAlert } from 'lucide-react';
import { BASE } from './api';
import { RANSOMWARE_LIVE_URL, REPO_URL } from './lib';
import { useRoute } from './store';
import type { Route } from './store';
import Overview from './pages/Overview';
import Alerts from './pages/Alerts';
import AlertReport from './pages/AlertReport';
import Graph from './pages/Graph';
import Watchlist from './pages/Watchlist';
import Analyse from './pages/Analyse';
import Learn from './pages/Learn';
import Start from './pages/Start';
import SignIn from './pages/SignIn';
import Workspace from './pages/Workspace';

const DEFAULT_TITLE = document.title;

const NAV = [
  { name: 'overview', href: '#/', label: 'Overview', Icon: LayoutDashboard },
  { name: 'start', href: '#/start', label: 'Get started', Icon: Compass },
  { name: 'alerts', href: '#/alerts', label: 'Alerts', Icon: ShieldAlert },
  { name: 'graph', href: '#/graph', label: 'Connections', Icon: Network },
  { name: 'watchlist', href: '#/watchlist', label: 'Watchlist', Icon: Eye },
  { name: 'analyse', href: '#/analyse', label: 'Check a post', Icon: ScanSearch },
  { name: 'workspace', href: '#/workspace', label: 'Workspace', Icon: Briefcase },
  { name: 'learn', href: '#/learn', label: 'How it works', Icon: BookOpen },
] as const;

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
  const text = ok === null ? 'Connecting' : ok ? 'Server online' : 'Server not reachable';
  return (
    <span className="status" role="status">
      <span className={`dot ${ok === null ? '' : ok ? 'dot-ok' : 'dot-bad'}`} aria-hidden="true" />
      <span className="label">{text}</span>
    </span>
  );
}

function page(route: Route) {
  switch (route.name) {
    case 'start': return <Start />;
    case 'alerts': return <Alerts />;
    case 'alert': return <AlertReport id={route.id} />;
    case 'graph': return <Graph />;
    case 'watchlist': return <Watchlist />;
    case 'analyse': return <Analyse />;
    case 'learn': return <Learn />;
    case 'signin': return <SignIn token={route.token} />;
    case 'workspace': return <Workspace />;
    default: return <Overview />;
  }
}

export default function App() {
  const route = useRoute();
  const current = route.name === 'alert' ? 'alerts' : route.name === 'signin' ? 'workspace' : route.name;

  useEffect(() => {
    window.scrollTo(0, 0);
    // A title per page: it names the browser tab and history entries, and makes shared links readable.
    const label = NAV.find((n) => n.name === current)?.label;
    document.title = route.name === 'overview' || !label ? DEFAULT_TITLE : `${route.name === 'alert' ? 'Alert report' : label} | DarkLens`;
    // On a phone the menu scrolls sideways: keep the current page's tab in view.
    document.querySelector<HTMLElement>('.nav a[aria-current="page"]')?.scrollIntoView({ inline: 'center', block: 'nearest' });
  }, [route, current]);

  return (
    <>
      <a className="skip" href="#main" onClick={(e) => { e.preventDefault(); document.getElementById('main')?.focus(); }}>Skip to content</a>
      <header className="topbar">
        <div className="topbar-inner">
          <a className="brand" href="#/" aria-label="DarkLens home">
            <img src="/logo.svg" alt="" />
            <span>DarkLens</span>
          </a>
          <nav className="nav" aria-label="Main">
            {NAV.map(({ name, href, label, Icon }) => (
              <a key={name} href={href} aria-current={current === name ? 'page' : undefined}>
                <Icon size={16} aria-hidden="true" /> {label}
              </a>
            ))}
          </nav>
          <Status />
        </div>
      </header>
      <main id="main" tabIndex={-1} className="page">
        {page(route)}
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
