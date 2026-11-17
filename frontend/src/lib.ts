import type { Alert, GraphLink, GraphNode, Severity } from './types';

export const REPO_URL = 'https://github.com/bhavitanand/darkweb-threat-intel-capstone';
export const RANSOMWARE_LIVE_URL = 'https://www.ransomware.live';

/** Ransomware.live's terms require its name, with a link back, wherever its data is shown. */
export function needsRansomwareLiveCredit(alerts: { source: string }[]): boolean {
  return alerts.some((a) => a.source === 'ransomware.live');
}

export type Tone ='danger' | 'orange' | 'caution' | 'safe' | 'info' | 'muted';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

export const SEVERITY_META: Record<Severity, { label: string; tone: Tone; verdict: string; advice: string }> = {
  critical: {
    label: 'Critical',
    tone: 'danger',
    verdict: 'Act now',
    advice: 'This looks like it directly concerns you or is very serious. Treat it as an incident and look at it today.',
  },
  high: {
    label: 'High',
    tone: 'orange',
    verdict: 'Look at this soon',
    advice: 'Strong signs of a real threat. Review it within a day and decide whether to respond.',
  },
  medium: {
    label: 'Medium',
    tone: 'caution',
    verdict: 'Worth a check',
    advice: 'Some warning signs, but not conclusive. Keep an eye on it and check it when you can.',
  },
  low: {
    label: 'Low',
    tone: 'safe',
    verdict: 'Probably fine',
    advice: 'Very little to worry about. It is kept so you can see everything the system looked at.',
  },
};

export const CATEGORY_META: Record<string, { label: string; blurb: string }> = {
  ransomware_leak: {
    label: 'Ransomware leak',
    blurb: 'A criminal group says it locked or stole data from an organisation and is threatening to publish it.',
  },
  credential_dump: {
    label: 'Stolen logins or data',
    blurb: 'Stolen logins or personal data: a list of emails and passwords being shared or sold, or a report that customer or staff data was stolen or exposed.',
  },
  exploit_sale: {
    label: 'Exploit for sale',
    blurb: 'Someone is selling a way to break into a specific product or service.',
  },
  phishing_kit: {
    label: 'Phishing kit',
    blurb: 'Ready-made fake login pages that scammers use to steal passwords.',
  },
  malware_sale: {
    label: 'Malware for sale',
    blurb: 'Harmful software, such as a password stealer or remote-access tool, being sold or rented.',
  },
  carding_fraud: {
    label: 'Card fraud',
    blurb: 'Stolen payment cards or fraud services being traded.',
  },
  threat_chatter: {
    label: 'Threat chatter',
    blurb: 'Talk about planning or boasting about attacks, without a concrete offer.',
  },
  known_exploited: {
    label: 'Exploited software flaw',
    blurb: 'A software flaw that the US cyber agency CISA says attackers are using in real attacks right now. Check whether you run the affected product.',
  },
  uncertain: {
    label: 'Not sure',
    blurb: 'DarkLens could not tell what this is, and found no clear warning signs. That is not proof it is harmless.',
  },
  ioc_feed: {
    label: 'Known bad indicator',
    blurb: 'An address, file or website that a public threat feed has already flagged as malicious.',
  },
  benign: {
    label: 'Harmless',
    blurb: 'Ordinary content that does not look like a threat.',
  },
};

export function categoryLabel(category: string): string {
  return CATEGORY_META[category]?.label ?? category.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());
}

export function categoryBlurb(category: string): string {
  return CATEGORY_META[category]?.blurb ?? '';
}

/** Same thresholds as the backend (darklens/scoring.py): 85 critical, 65 high, 40 medium. */
export function severityFromScore(score: number): Severity {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

export const TONE_HEX: Record<string, string> = {
  danger: '#d93a45', orange: '#e0702b', caution: '#b9811a', safe: '#2e9e6b',
};

export function severityMeta(s: string) {
  return SEVERITY_META[s as Severity] ?? SEVERITY_META.low;
}

export const IOC_LABELS: Record<string, string> = {
  btc: 'Bitcoin address',
  eth: 'Ethereum address',
  xmr: 'Monero address',
  trx: 'Tron address',
  email: 'Email address',
  domain: 'Website',
  ipv4: 'IP address',
  sha256: 'File fingerprint (SHA-256)',
  md5: 'File fingerprint (MD5)',
  onion: 'Dark web address',
  cve: 'Known vulnerability (CVE)',
  url: 'Link',
  actor: 'Poster',
  org: 'Organisation',
  item: 'Alert',
};

export function iocLabel(kind: string): string {
  return IOC_LABELS[kind] ?? kind;
}

/** Rule signals are named like "DL-EXP-001 Zero-day or exploit for sale": lead with the words, keep the code small. */
export function splitRule(name: string): { code: string; title: string } {
  const m = /^(DL-[A-Z]+-\d+)\s+(.+)$/.exec(name);
  return m ? { code: m[1], title: m[2] } : { code: '', title: name };
}

export function pct(n: number, digits = 0): string {
  return `${(n * 100).toFixed(digits)}%`;
}

export function timeAgo(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return 'date unknown';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 'date unknown';
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} hour${h === 1 ? '' : 's'} ago`;
  const d = Math.round(h / 24);
  if (d < 45) return `${d} day${d === 1 ? '' : 's'} ago`;
  return new Date(t).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export interface AlertFilter {
  severity: string;
  category: string;
  q: string;
  /** '' = everything, 'real' = live feeds only, 'demo' = the synthetic samples only. */
  data?: string;
}

export function filterAlerts(alerts: Alert[], f: AlertFilter): Alert[] {
  const q = f.q.trim().toLowerCase();
  return alerts
    .filter((a) => !f.severity || a.severity === f.severity)
    .filter((a) => !f.category || a.category === f.category)
    .filter((a) => !f.data || (f.data === 'demo' ? a.demo : !a.demo))
    .filter((a) => !q || `${a.title} ${a.text} ${a.actor ?? ''} ${a.org ?? ''}`.toLowerCase().includes(q))
    .sort((x, y) => y.score - x.score);
}

/** The top alerts for the overview. Real alerts come first: made-up demo alerts only fill in when there are none. */
export function mostWorrying(alerts: Alert[], n = 5): Alert[] {
  const real = alerts.filter((a) => !a.demo);
  return [...(real.length ? real : alerts)].sort((x, y) => y.score - x.score).slice(0, n);
}

/** Domain, email or product name, as the watchlist accepts them. Returns the cleaned value or null. */
export function cleanWatchValue(kind: 'domain' | 'email' | 'product', raw: string): string | null {
  const v = raw.trim().toLowerCase();
  if (kind === 'product') {
    const p = v.replace(/\s+/g, ' ');
    return /^[a-z0-9][a-z0-9 .+_#-]{1,58}[a-z0-9+#]$/.test(p) ? p : null;
  }
  if (kind === 'email') return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? v : null;
  const d = v.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  return /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(d) ? d : null;
}

// ---------- graph layout ----------

export interface Placed extends GraphNode {
  x: number;
  y: number;
}

/** Small deterministic PRNG so the same graph always lays out the same way. */
function mulberry32(seed: number) {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Force-directed layout (repulsion + springs + centring). Pure and synchronous. */
export function layoutGraph(nodes: GraphNode[], links: GraphLink[], width: number, height: number, iterations = 220): Placed[] {
  const rand = mulberry32(nodes.length * 7919 + links.length);
  const pts = nodes.map((n) => ({
    ...n,
    x: width / 2 + (rand() - 0.5) * width * 0.6,
    y: height / 2 + (rand() - 0.5) * height * 0.6,
    vx: 0,
    vy: 0,
  }));
  const index = new Map(pts.map((p, i) => [p.id, i]));
  const edges = links
    .map((l) => [index.get(l.source), index.get(l.target)] as const)
    .filter((e): e is readonly [number, number] => e[0] !== undefined && e[1] !== undefined);
  const k = Math.sqrt((width * height) / Math.max(pts.length, 1)) * 0.7;
  // Repulsion compares every pair, so cost grows with the square of the node count. Keep the work bounded
  // (about 4 million pair checks) so a big graph never freezes the page: fewer passes when there are many nodes.
  const steps = Math.max(30, Math.min(iterations, Math.floor(4_000_000 / Math.max(pts.length * pts.length, 1))));

  for (let it = 0; it < steps; it++) {
    const cool = 1 - it / steps;
    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        let dx = pts[i].x - pts[j].x;
        let dy = pts[i].y - pts[j].y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) {
          dx = rand() - 0.5;
          dy = rand() - 0.5;
          d2 = dx * dx + dy * dy + 0.01;
        }
        const d = Math.sqrt(d2);
        const f = (k * k) / d2;
        const fx = (dx / d) * f;
        const fy = (dy / d) * f;
        pts[i].vx += fx; pts[i].vy += fy;
        pts[j].vx -= fx; pts[j].vy -= fy;
      }
    }
    for (const [a, b] of edges) {
      const dx = pts[b].x - pts[a].x;
      const dy = pts[b].y - pts[a].y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const f = (d - k * 0.6) * 0.05;
      const fx = (dx / d) * f;
      const fy = (dy / d) * f;
      pts[a].vx += fx; pts[a].vy += fy;
      pts[b].vx -= fx; pts[b].vy -= fy;
    }
    for (const p of pts) {
      p.vx += (width / 2 - p.x) * 0.01;
      p.vy += (height / 2 - p.y) * 0.01;
      const speed = Math.sqrt(p.vx * p.vx + p.vy * p.vy) || 1;
      const cap = 12 * cool + 0.5;
      const m = Math.min(speed, cap) / speed;
      p.x += p.vx * m;
      p.y += p.vy * m;
      p.vx = 0;
      p.vy = 0;
      p.x = Math.min(width - 24, Math.max(24, p.x));
      p.y = Math.min(height - 24, Math.max(24, p.y));
    }
  }
  return pts.map((p) => ({ id: p.id, kind: p.kind, label: p.label, category: p.category, score: p.score, x: p.x, y: p.y }));
}
