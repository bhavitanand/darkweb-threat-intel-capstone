import { RANSOMWARE_LIVE_URL, needsRansomwareLiveCredit } from '../lib';

/** The attribution Ransomware.live's terms ask for: its name, linked, on any page that shows its data. */
export default function SourceCredit({ alerts }: { alerts: { source: string }[] }) {
  if (!needsRansomwareLiveCredit(alerts)) return null;
  return (
    <p className="muted source-credit">
      Source: <a href={RANSOMWARE_LIVE_URL} target="_blank" rel="noreferrer">Ransomware.live</a>. A listing there is a claim
      made by criminals, not a confirmed breach.
    </p>
  );
}
