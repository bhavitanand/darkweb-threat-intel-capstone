export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface Signal {
  name: string;
  score: number;
  why: string;
  evidence: string;
  full: boolean;
}

export type Iocs = Record<string, string[]>;

export interface Alert {
  item_id: string;
  score: number;
  severity: Severity;
  category: string;
  confidence: number;
  signals: Signal[];
  probs: Record<string, number>;
  source: string;
  kind: string;
  title: string;
  text: string;
  url: string | null;
  seen_at: string | null;
  actor: string | null;
  org: string | null;
  country: string | null;
  iocs: Iocs;
  /** True for the synthetic sample data that ships with the project. */
  demo: boolean;
  /** True when the source's terms forbid re-publishing its text: the API withholds `text` and exports skip it. */
  restricted: boolean;
}

export interface MitreTechnique {
  id: string;
  name: string;
  url: string;
}

export interface FeedbackCounts {
  correct: number;
  wrong: number;
}

export interface AlertDetail extends Alert {
  mitre: MitreTechnique[];
  feedback: FeedbackCounts;
}

export interface SourceStatus {
  source: string;
  status: 'ok' | 'skipped' | 'error';
  items: number;
  note: string;
}

export interface IngestStatus {
  last: {
    started_at: string;
    finished_at: string;
    mode: 'live' | 'demo';
    items: number;
    alerts: number;
    ok: boolean;
    notified: number;
    pruned: number;
    sources: SourceStatus[];
  } | null;
  auto_ingest_minutes: number;
  live_ready: boolean;
}

export interface Stats {
  alerts: number;
  demo_alerts: number;
  real_alerts: number;
  items: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  ioc_types: Record<string, number>;
  attribution: string;
}

export type NodeKind =
  | 'item' | 'actor' | 'org' | 'btc' | 'eth' | 'xmr' | 'trx'
  | 'email' | 'domain' | 'ipv4' | 'sha256' | 'md5' | 'onion' | 'cve';

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  category?: string;
  score?: number;
}

export interface GraphLink {
  source: string;
  target: string;
  rel: string;
}

export interface LinkedActors {
  shared: string;
  type: string;
  actors: string[];
}

export interface Campaign {
  items: string[];
  size: number;
  max_score: number;
  shared: string[];
  risk: number;
}

export interface GraphData {
  graph: { nodes: GraphNode[]; links: GraphLink[] };
  linked_actors: LinkedActors[];
  campaigns: Campaign[];
}

export interface WatchEntry {
  kind: 'domain' | 'email' | 'product';
  value: string;
}

export interface Analysis {
  category: string;
  confidence: number;
  score: number;
  severity: Severity;
  signals: Signal[];
  iocs: Iocs;
  probs: Record<string, number>;
  exposures: { email?: string }[];
  /** True when the text was longer than the server classifies; indicators were still searched in all of it. */
  truncated?: boolean;
}

export interface EvalResult {
  n_test: number;
  rules: number;
  ml: number;
  hybrid: number;
  note: string;
}
