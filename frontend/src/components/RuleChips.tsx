import { useState } from 'react';
import { Plus, X } from 'lucide-react';
import type { RuleSpec, Severity } from '../types';
import { SEVERITY_META } from '../lib';
import { ATTACK_LABELS, THREAT_LABELS } from '../rules';

type ListKey = 'products' | 'keywords' | 'attacks' | 'categories' | 'cves' | 'domains' | 'emails';

const GROUPS: { key: ListKey; label: string; tone: 'amber' | 'ink' }[] = [
  { key: 'products', label: 'Software or vendor', tone: 'amber' },
  { key: 'keywords', label: 'Also about', tone: 'amber' },
  { key: 'attacks', label: 'Kind of attack', tone: 'amber' },
  { key: 'categories', label: 'Threat type', tone: 'amber' },
  { key: 'cves', label: 'CVE', tone: 'ink' },
  { key: 'domains', label: 'Domain', tone: 'ink' },
  { key: 'emails', label: 'Email', tone: 'ink' },
];

function show(key: ListKey, v: string): string {
  if (key === 'attacks') return ATTACK_LABELS[v] ?? v;
  if (key === 'categories') return THREAT_LABELS[v] ?? v;
  return v;
}

/** Read-only chips: what a rule looks for. */
export function RuleChips({ spec }: { spec: RuleSpec }) {
  const chips = GROUPS.flatMap((g) => spec[g.key].map((v) => ({ g, v })));
  return (
    <div className="chips" style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
      {chips.map(({ g, v }) => (
        <span key={`${g.key}:${v}`} className={`edit-chip${g.tone === 'ink' ? ' ink' : ''}`} style={{ paddingRight: 10 }} title={g.label}>
          {show(g.key, v)}
        </span>
      ))}
      <span className="chip">{SEVERITY_META[spec.min_severity].label}{spec.min_severity === 'critical' ? ' only' : ' and worse'}</span>
    </div>
  );
}

/** Editable: remove any chip, add a word, an attack kind or a threat type, and set the lowest severity to alert on. */
export function RuleEditor({ spec, onChange }: { spec: RuleSpec; onChange: (s: RuleSpec) => void }) {
  const [word, setWord] = useState('');
  const drop = (key: ListKey, v: string) => onChange({ ...spec, [key]: spec[key].filter((x) => x !== v) });
  const add = (key: ListKey, v: string) => {
    const clean = v.trim().toLowerCase();
    if (!clean || spec[key].includes(clean)) return;
    onChange({ ...spec, [key]: [...spec[key], clean] });
  };
  // Not a <form>: this sits inside the "Save alert" form, and Enter here must add a word, not save the alert.
  function addWord() {
    const w = word.trim();
    if (!w) return;
    if (/^cve-\d{4}-\d{4,7}$/i.test(w)) onChange({ ...spec, cves: [...new Set([...spec.cves, w.toUpperCase()])] });
    else if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(w)) add('emails', w);
    else if (/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(w)) add('domains', w);
    else add('keywords', w);
    setWord('');
  }

  return (
    <div className="understood-grid">
      {GROUPS.filter((g) => spec[g.key].length || g.key === 'attacks' || g.key === 'categories' || g.key === 'products').map((g) => (
        <div key={g.key} style={{ display: 'contents' }}>
          <span>{g.label}</span>
          <div className="row" style={{ gap: 6 }}>
            {spec[g.key].map((v) => (
              <span key={v} className={`edit-chip${g.tone === 'ink' ? ' ink' : ''}`}>
                {show(g.key, v)}
                <button type="button" aria-label={`Remove ${show(g.key, v)}`} onClick={() => drop(g.key, v)}><X size={12} aria-hidden="true" /></button>
              </span>
            ))}
            {g.key === 'attacks' && (
              <select aria-label="Add a kind of attack" value="" onChange={(e) => add('attacks', e.target.value)} style={{ width: 'auto', padding: '4px 8px', fontSize: 13 }}>
                <option value="">+ add</option>
                {Object.entries(ATTACK_LABELS).filter(([k]) => !spec.attacks.includes(k)).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
              </select>
            )}
            {g.key === 'categories' && (
              <select aria-label="Add a threat type" value="" onChange={(e) => add('categories', e.target.value)} style={{ width: 'auto', padding: '4px 8px', fontSize: 13 }}>
                <option value="">+ add</option>
                {Object.entries(THREAT_LABELS).filter(([k]) => !spec.categories.includes(k)).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
              </select>
            )}
            {g.key === 'products' && !spec.products.length && <span className="muted" style={{ fontSize: 13 }}>none</span>}
          </div>
        </div>
      ))}
      <span>Add a word</span>
      <div className="row" style={{ gap: 6 }}>
        <input value={word} onChange={(e) => setWord(e.target.value)} placeholder="a product, CVE, domain or word" aria-label="Add a word, product, CVE, domain or email"
          style={{ maxWidth: 260, padding: '6px 10px', fontSize: 13 }}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addWord(); } }} />
        <button type="button" className="btn btn-ghost btn-sm" disabled={!word.trim()} onClick={addWord}><Plus size={14} aria-hidden="true" /> Add</button>
      </div>
      <span>Alert from</span>
      <div className="pills" role="group" aria-label="Lowest severity to alert on">
        {(['low', 'medium', 'high', 'critical'] as Severity[]).map((s) => (
          <button key={s} type="button" className="pill" aria-pressed={spec.min_severity === s} onClick={() => onChange({ ...spec, min_severity: s })}>
            {SEVERITY_META[s].label}{s === 'critical' ? ' only' : '+'}
          </button>
        ))}
      </div>
    </div>
  );
}
