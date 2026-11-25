import { useMemo } from 'react';

interface Box { id: string; x: number; y: number; w: number; h: number; label: string; sub?: string; hot?: boolean }

const SOURCES: Box[] = [
  { id: 's1', x: 16, y: 26, w: 140, h: 36, label: 'Ransomware claims', sub: 'leak sites' },
  { id: 's2', x: 16, y: 78, w: 140, h: 36, label: 'Malware and IOCs', sub: 'abuse.ch' },
  { id: 's3', x: 16, y: 130, w: 140, h: 36, label: 'Exploited flaws', sub: 'CISA KEV' },
  { id: 's4', x: 16, y: 182, w: 140, h: 36, label: 'Security news', sub: '17 outlets' },
  { id: 's5', x: 16, y: 234, w: 140, h: 36, label: 'Breaches, phishing', sub: 'HIBP, OpenPhish' },
];
const STAGES: Box[] = [
  { id: 'collect', x: 206, y: 124, w: 118, h: 48, label: 'Collect', sub: 'every 30 min' },
  { id: 'extract', x: 360, y: 124, w: 142, h: 48, label: 'Extract clues', sub: 'IPs, wallets, CVEs' },
  { id: 'rules', x: 538, y: 66, w: 132, h: 48, label: 'Detection rules', sub: '27 hand-written' },
  { id: 'model', x: 538, y: 182, w: 132, h: 48, label: 'Text model', sub: '8 threat types' },
  { id: 'score', x: 706, y: 124, w: 112, h: 48, label: 'Score 0-100', sub: 'with reasons' },
  { id: 'you', x: 858, y: 118, w: 128, h: 60, label: 'Your alert rules', sub: '"alert me for..."', hot: true },
];
const OUTS: Box[] = [
  { id: 'o1', x: 1026, y: 54, w: 108, h: 38, label: 'My alerts' },
  { id: 'o2', x: 1026, y: 129, w: 108, h: 38, label: 'Slack, Discord' },
  { id: 'o3', x: 1026, y: 204, w: 108, h: 38, label: 'Email digest' },
];
const ALL = [...SOURCES, ...STAGES, ...OUTS];
const EDGES: [string, string][] = [
  ...SOURCES.map((s) => [s.id, 'collect'] as [string, string]),
  ['collect', 'extract'], ['extract', 'rules'], ['extract', 'model'], ['rules', 'score'], ['model', 'score'], ['score', 'you'],
  ['you', 'o1'], ['you', 'o2'], ['you', 'o3'],
];

function wire(a: Box, b: Box): string {
  const x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2;
  const mid = (x1 + x2) / 2;
  return `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`;
}

/** How DarkLens works, as one picture: sources on the left, your alerts on the right, and amber embers travelling along
 *  the wires the way an item does. Pure SVG. */
export default function Pipeline() {
  const byId = useMemo(() => new Map(ALL.map((b) => [b.id, b])), []);
  const wires = EDGES.map(([a, b], i) => ({ d: wire(byId.get(a)!, byId.get(b)!), i, hot: b === 'you' || a === 'you' }));
  // Reduced motion: the embers still move (they are small and do not shift the page), just more slowly.
  const slow = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ? 2 : 1;

  return (
    <svg className="pipe" viewBox="0 0 1150 300" role="img"
      aria-label="How DarkLens works: five kinds of public source are collected, clues are extracted, detection rules and a text model score each item from 0 to 100, your own alert rules pick what is about you, and you are told in the website, in Slack or Discord, or by email.">
      {wires.map((w) => (
        <path key={`w${w.i}`} className="wire" d={w.d} style={w.hot ? { stroke: '#b4500f', opacity: 0.8 } : undefined} />
      ))}
      {wires.map((w) => {
        const dur = (2.2 + ((w.i * 37) % 13) / 10) * slow;
        return (
          <g key={`e${w.i}`}>
            <circle className="halo" r="7">
              <animateMotion dur={`${dur}s`} repeatCount="indefinite" begin={`${(w.i * 0.31) % 2}s`} path={w.d} />
            </circle>
            <circle className="ember" r="3.6">
              <animateMotion dur={`${dur}s`} repeatCount="indefinite" begin={`${(w.i * 0.31) % 2}s`} path={w.d} />
            </circle>
          </g>
        );
      })}
      {ALL.map((b) => (
        <g key={b.id} className={`node${b.hot ? ' hot' : ''}`}>
          <rect x={b.x} y={b.y} width={b.w} height={b.h} rx="6" />
          <text x={b.x + 12} y={b.y + (b.sub ? b.h / 2 - 2 : b.h / 2 + 4.5)}>{b.label}</text>
          {b.sub && <text className="sub" x={b.x + 12} y={b.y + b.h / 2 + 13}>{b.sub}</text>}
        </g>
      ))}
    </svg>
  );
}
