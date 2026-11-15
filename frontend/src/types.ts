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
}

export interface MitreTechnique {
  id: string;
  name: string;
  url: string;
}

export interface AlertDetail extends Alert {
  mitre: MitreTechnique[];
}

export interface Stats {
  alerts: number;
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
  kind: 'domain' | 'email';
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
}

export interface EvalResult {
  n_test: number;
  rules: number;
  ml: number;
  hybrid: number;
  note: string;
}
