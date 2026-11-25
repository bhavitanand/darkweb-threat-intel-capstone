import { SEVERITY_META } from './lib';
import type { RuleSpec } from './types';

/** Labels for the parser's attack kinds and threat types (the same keys as darklens/alert_rules.py). */
export const ATTACK_LABELS: Record<string, string> = {
  rce: 'Remote code execution', sqli: 'SQL injection', xss: 'Cross-site scripting', auth_bypass: 'Login bypass',
  privesc: 'Privilege escalation', traversal: 'Path traversal', file_inclusion: 'File inclusion', ssrf: 'Server-side request forgery',
  deserialization: 'Unsafe deserialisation', memory: 'Memory corruption', zeroday: 'Zero-day', dos: 'Denial of service',
  any_vuln: 'Any flaw or exploit',
};
export const THREAT_LABELS: Record<string, string> = {
  ransomware_leak: 'Ransomware', credential_dump: 'Leaked logins or data', phishing_kit: 'Phishing', malware_sale: 'Malware',
  carding_fraud: 'Card fraud', exploit_sale: 'Exploits for sale', known_exploited: 'Exploited in the wild',
};

export function isEmptySpec(s: RuleSpec): boolean {
  return !(s.products.length || s.keywords.length || s.attacks.length || s.categories.length || s.cves.length || s.domains.length || s.emails.length);
}

/** The same plain sentence the server writes (darklens/alert_rules.py describe), so edits to the chips update it live. */
export function describeSpec(s: RuleSpec): string {
  const parts: string[] = [];
  if (s.categories.length) parts.push(s.categories.map((c) => THREAT_LABELS[c] ?? c).join(' or ').toLowerCase());
  if (s.attacks.length) parts.push(s.attacks.map((a) => ATTACK_LABELS[a] ?? a).join(' or ').toLowerCase());
  let what = parts.length ? parts.join(' involving ') : 'anything';
  const topics = [...s.products, ...s.keywords];
  if (topics.length) what += ` about ${topics.join(' or ')}`;
  const direct = [...s.cves, ...s.domains, ...s.emails];
  if (direct.length) what += `${parts.length || topics.length ? ' that also mentions ' : ' that mentions '}${direct.join(' or ')}`;
  const floor = s.min_severity === 'low' ? 'of any severity' : s.min_severity === 'critical' ? 'rated Critical' : `rated ${SEVERITY_META[s.min_severity].label} or worse`;
  return `Alert on ${what}, ${floor}.`;
}

