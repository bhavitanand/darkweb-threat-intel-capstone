import { ArrowRight, ExternalLink } from 'lucide-react';
import { REPO_URL, SEVERITY_META, SEVERITY_ORDER } from '../lib';
import { Chip, PageHead, Section } from '../components/ui';

const STEPS = [
  {
    title: 'Tell DarkLens what belongs to you',
    body: 'Open the Watchlist and add your company website domains and any email addresses you care about. This is the single most useful step: from now on, anything that mentions them is pushed to the top and marked as being about you.',
    href: '#/watchlist',
    cta: 'Open the watchlist',
  },
  {
    title: 'Look at the alerts, worst first',
    body: 'The Alerts page lists everything, highest score first. Start with Critical and High. You can filter by severity, by type of threat, or search for a company or word.',
    href: '#/alerts',
    cta: 'See the alerts',
  },
  {
    title: 'Open one and read why it scored that way',
    body: 'Every report shows the score, each warning sign that added to it, the clues found in the text (wallets, addresses, file fingerprints) and the attack techniques it matches. Nothing is hidden: if you disagree with a score you can see exactly what caused it.',
    href: '#/alerts',
    cta: 'Open the top alert',
  },
  {
    title: 'Decide what to do',
    body: 'Use the table below. When in doubt, the "Open evidence pack" button makes a sealed, self-contained page you can hand to your security team or keep as a record.',
  },
  {
    title: 'Tell DarkLens when it gets something wrong',
    body: 'At the bottom of each report, say whether the type it chose is right. Corrections are collected so the system can be measured honestly and improved on real examples.',
  },
  {
    title: 'Take the results with you',
    body: 'On the Alerts page you can download everything as a spreadsheet (CSV) or in STIX, the standard format other security tools import. The server can also message a chat channel or an inbox when something about your watchlist appears.',
    href: `${REPO_URL}/blob/main/docs/alerts-and-notifications.md`,
    cta: 'How to switch on notifications',
    external: true,
  },
];

export default function Start() {
  return (
    <>
      <PageHead
        title="Get started"
        sub="DarkLens watches places criminals boast and sell, and tells you in plain words when something might concern you. Here is how to use it, in about two minutes."
      />
      <div className="stack">
        <Section title="The routine">
          <ol className="steps">
            {STEPS.map((s) => (
              <li key={s.title}>
                <div>
                  <strong>{s.title}.</strong>
                  <p>{s.body}</p>
                  {s.href && (
                    <a className="btn btn-ghost" href={s.href} {...(s.external ? { target: '_blank', rel: 'noreferrer' } : {})}>
                      {s.cta} {s.external ? <ExternalLink size={14} aria-hidden="true" /> : <ArrowRight size={14} aria-hidden="true" />}
                    </a>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </Section>

        <Section title="What to do about each level" hint="Severity is a guide to where to look first, not a verdict.">
          <ul className="alert-list">
            {SEVERITY_ORDER.map((s) => (
              <li key={s} className="camp">
                <div className="row">
                  <Chip tone={SEVERITY_META[s].tone}>{SEVERITY_META[s].label}</Chip>
                  <strong>{SEVERITY_META[s].verdict}</strong>
                </div>
                <p>{ACTIONS[s]}</p>
              </li>
            ))}
          </ul>
        </Section>

        <div className="grid grid-2">
          <Section title="Real data and demo data">
            <p>
              The site mixes two kinds of alerts. Ones from the live feeds are real public claims. Ones marked{' '}
              <Chip tone="info">Demo</Chip> are made-up examples so the tool is never empty. Use the "Data" filter on the
              Alerts page to see only the real ones.
            </p>
          </Section>
          <Section title="What DarkLens does not do">
            <ul>
              <li>It does not prove anything happened. A score points you at where to look.</li>
              <li>It reads public feeds and text. It does not break into anything or visit hidden sites on its own.</li>
              <li>Keyword rules can miss unusual wording, so no alert does not mean no risk.</li>
            </ul>
          </Section>
        </div>

        <Section title="Want the technical side?">
          <p>
            How scoring works is on <a href="#/learn">How it works</a>. Setup, hosting, the API and how to contribute are in{' '}
            <a href={REPO_URL} target="_blank" rel="noreferrer">the project on GitHub</a>, including the{' '}
            <a href={`${REPO_URL}/blob/main/docs/workflow.md`} target="_blank" rel="noreferrer">full workflow guide</a>.
          </p>
        </Section>
      </div>
    </>
  );
}

const ACTIONS: Record<string, string> = {
  critical:
    'Treat it as an incident now. If it names your domain or shows your logins, reset those passwords, tell whoever runs your IT or security, and keep the evidence pack.',
  high: 'Review it within a day. Decide whether it concerns you. If it does, escalate to your security contact.',
  medium: 'Worth a look when you can. Note it, and see whether related alerts appear in the Connections map.',
  low: 'No action needed. These are kept so you can see everything that was checked.',
};
