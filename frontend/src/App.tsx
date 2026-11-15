import { useEffect, useState } from 'react';
import { BookOpen, Eye, LayoutDashboard, Network, ScanSearch, ShieldAlert } from 'lucide-react';
import { BASE } from './api';
import { useRoute } from './store';
import type { Route } from './store';
import Overview from './pages/Overview';
import Alerts from './pages/Alerts';
import AlertReport from './pages/AlertReport';
import Graph from './pages/Graph';
import Watchlist from './pages/Watchlist';
import Analyse from './pages/Analyse';
import Learn from './pages/Learn';

const NAV = [
  { name: 'overview', href: '#/', label: 'Overview', Icon: LayoutDashboard },
  { name: 'alerts', href: '#/alerts', label: 'Alerts', Icon: ShieldAlert },
  { name: 'graph', href: '#/graph', label: 'Connections', Icon: Network },
  { name: 'watchlist', href: '#/watchlist', label: 'Watchlist', Icon: Eye },
  { name: 'analyse', href: '#/analyse', label: 'Check a post', Icon: ScanSearch },
  { name: 'learn', href: '#/learn', label: 'How it works', Icon: BookOpen },
] as const;

function Status() {
  const [ok, setOk] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    fetch(`${BASE}/api/health`)
      .then((r) => live && setOk(r.ok))
      .catch(() => live && setOk(false));
    return () => { live = false; };
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
    case 'alerts': return <Alerts />;
    case 'alert': return <AlertReport id={route.id} />;
    case 'graph': return <Graph />;
    case 'watchlist': return <Watchlist />;
    case 'analyse': return <Analyse />;
    case 'learn': return <Learn />;
    default: return <Overview />;
  }
}

export default function App() {
  const route = useRoute();
  const current = route.name === 'alert' ? 'alerts' : route.name;

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [route]);

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
        DarkLens is a Samsung Innovation Campus capstone project. Demo data is synthetic. It reads text only and never stores real stolen data.
      </footer>
    </>
  );
}
