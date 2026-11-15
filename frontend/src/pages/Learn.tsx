import { api } from '../api';
import { useAsync } from '../hooks';
import { CATEGORY_META, SEVERITY_META, SEVERITY_ORDER, pct } from '../lib';
import { Bar, Chip, ErrorBox, Loading, PageHead, Section } from '../components/ui';

export default function Learn() {
  const ev = useAsync(api.evaluation);

  return (
    <>
      <PageHead title="How it works" sub="No black box. Here is what DarkLens does, how much to trust it, and where it falls short." />
      <div className="stack">
        <Section title="From a post to a score">
          <ol className="steps">
            <li><div><strong>Collect.</strong> Posts come from public ransomware-victim feeds and the demo set. The demo data is synthetic.</div></li>
            <li><div><strong>Sort.</strong> Rules written by hand and a text model each guess what kind of post it is. The two are combined, so a clear rule wins and the model fills the gaps.</div></li>
            <li><div><strong>Look for warning signs.</strong> Payment addresses, stolen-login formats, mentions of your domains and more each add points, with a reason attached.</div></li>
            <li><div><strong>Combine.</strong> The signs are merged so several weak signs add up without ever passing 100. Mentioning your own domain counts most.</div></li>
            <li><div><strong>Explain.</strong> You get the score, the reasons, the clues found, and a sealed evidence pack you can hand to someone else.</div></li>
          </ol>
        </Section>

        <div className="grid grid-2">
          <Section title="What the severity means">
            <ul className="alert-list">
              {SEVERITY_ORDER.map((s) => (
                <li key={s}>
                  <Chip tone={SEVERITY_META[s].tone}>{SEVERITY_META[s].label}</Chip> <strong>{SEVERITY_META[s].verdict}.</strong>
                  <p className="muted">{SEVERITY_META[s].advice}</p>
                </li>
              ))}
            </ul>
          </Section>
          <Section title="The kinds of threat">
            <ul className="alert-list">
              {Object.entries(CATEGORY_META).map(([k, v]) => (
                <li key={k}><strong>{v.label}.</strong> <span className="muted">{v.blurb}</span></li>
              ))}
            </ul>
          </Section>
        </div>

        <Section title="How accurate is the sorting?" hint="Tested on sentence shapes the model never saw while learning, so the numbers are not flattered.">
          {ev.loading && !ev.data && <Loading what="the test results" slow={ev.slow} />}
          {ev.error && <ErrorBox message={ev.error} onRetry={ev.reload} />}
          {ev.data && (
            <>
              {(
                [
                  ['Hand-written rules', ev.data.rules],
                  ['Text model only', ev.data.ml],
                  ['Both together', ev.data.hybrid],
                ] as const
              ).map(([name, v]) => (
                <div className="metric-row" key={name}>
                  <span>{name}</span>
                  <Bar value={v} max={1} tone={name === 'Both together' ? 'safe' : 'info'} label={`${name}: ${pct(v)}`} />
                  <span className="mono">{pct(v)}</span>
                </div>
              ))}
              <p className="muted">Scored on {ev.data.n_test} test posts. {ev.data.note}</p>
            </>
          )}
        </Section>

        <Section title="Honest limits">
          <ul>
            <li>The test posts are synthetic, so real-world accuracy will be lower than these figures.</li>
            <li>It reads text only. It does not visit dark web sites, and it never stores real stolen data.</li>
            <li>A score is a guide for where to look first, not proof that something happened.</li>
            <li>Alerts are kept in a small database that resets when the free server restarts.</li>
          </ul>
        </Section>
      </div>
    </>
  );
}
