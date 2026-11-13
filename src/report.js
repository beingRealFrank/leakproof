import { SEVERITIES } from './rules.js';

const ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '⚪' };
const COLOR = { critical: '\x1b[31;1m', high: '\x1b[33;1m', medium: '\x1b[33m', low: '\x1b[37m' };

function counts(findings) {
  const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) c[f.severity]++;
  return c;
}

export function text({ findings, scannedFiles }, { color = true } = {}) {
  const z = (code, s) => (color ? code + s + '\x1b[0m' : s);
  const lines = [];
  for (const f of findings) {
    lines.push(`${z(COLOR[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.rule} ${f.title}`);
    lines.push(`         ${f.file}:${f.line}  ${z('\x1b[2m', f.evidence)}`);
    lines.push(`         ${f.detail}`);
    lines.push(`         Fix: ${f.fix}`);
    lines.push('');
  }
  const c = counts(findings);
  lines.push(`Scanned ${scannedFiles} files: ${SEVERITIES.map((s) => `${c[s]} ${s}`).join(', ')}.`);
  if (!findings.length) lines.push('No findings. That does not mean the app is secure: these are automated checks for the most common holes.');
  lines.push('Free scanner by Leakproof — a human-reviewed audit with fix PRs: https://beingrealfrank.github.io/leakproof/');
  return lines.join('\n');
}

export function markdown({ findings, scannedFiles }) {
  const c = counts(findings);
  const out = ['# Leakproof scan', '', `Scanned ${scannedFiles} files. ${SEVERITIES.map((s) => `${ICON[s]} ${c[s]} ${s}`).join(' · ')}`, ''];
  for (const f of findings) {
    out.push(`### ${ICON[f.severity]} ${f.title} (${f.rule})`, '', `\`${f.file}:${f.line}\` — \`${f.evidence.replace(/`/g, "'")}\``, '', f.detail, '', `**Fix:** ${f.fix}`, '');
  }
  if (!findings.length) out.push('No findings from the automated checks.', '');
  out.push('---', 'Automated checks only. For a human-reviewed audit with fix PRs: https://beingrealfrank.github.io/leakproof/');
  return out.join('\n');
}

export function json(result) {
  return JSON.stringify({ ...result, counts: counts(result.findings) }, null, 2);
}

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
export function sarif({ findings }, version) {
  const ruleIds = [...new Map(findings.map((f) => [f.rule, f])).values()];
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'leakproof', version, informationUri: 'https://github.com/beingRealFrank/leakproof',
        rules: ruleIds.map((f) => ({ id: f.rule, name: f.title, shortDescription: { text: f.title } })) } },
      results: findings.map((f) => ({
        ruleId: f.rule, level: SARIF_LEVEL[f.severity],
        message: { text: `${f.detail} Fix: ${f.fix}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }],
        properties: { severity: f.severity },
      })),
    }],
  }, null, 2);
}
