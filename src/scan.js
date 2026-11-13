import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { execFileSync } from 'node:child_process';
import { rules, SEVERITIES } from './rules.js';

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', '.nuxt', '.svelte-kit', 'dist', 'build', 'out', 'coverage',
  'vendor', '.vercel', '.turbo', '.output', '.cache', '__pycache__', '.venv', 'venv', 'env', '.expo', 'ios', 'android', 'target']);
const WANT = /\.(m?[jt]sx?|cjs|cts|vue|svelte|astro|py|rb|go|php|sql|rules|json|ya?ml|toml)$|(^|\/)\.env(\.[\w-]+)?$/;
const MAX_BYTES = 1_000_000;

function walk(root) {
  const out = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(full); continue; }
      if (!e.isFile()) continue;
      const rel = relative(root, full).split(sep).join('/');
      if (!WANT.test(rel) || /\.min\.js$|package-lock\.json$|yarn\.lock$|pnpm-lock\.yaml$/.test(rel)) continue;
      try { if (statSync(full).size > MAX_BYTES) continue; } catch { continue; }
      out.push(rel);
    }
  }
  return out.sort();
}

function gitTracked(root) {
  try {
    const outp = execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64e6 });
    return new Set(outp.split('\0').filter(Boolean));
  } catch { return null; }
}

export async function scan(root, { network = true } = {}) {
  const tracked = gitTracked(root);
  // Outside a git repo we can't tell, so treat .env files as shipped (conservative).
  const ctx = { trackedByGit: (p) => (tracked ? tracked.has(p) : true) };
  const files = [];
  for (const path of walk(root)) {
    let text;
    try { text = readFileSync(join(root, path), 'utf8'); } catch { continue; }
    if (text.includes('\0')) continue;
    files.push({ path, text });
  }
  const findings = [];
  for (const rule of rules) {
    if (rule.project) {
      for (const f of rule.checkProject(files, ctx)) findings.push({ rule: rule.id, title: rule.title, ...f });
      continue;
    }
    for (const { path, text } of files) {
      for (const f of rule.check(path, text, ctx)) findings.push({ rule: rule.id, title: rule.title, file: path, ...f });
    }
  }
  if (network) findings.push(...(await dependencyFindings(root)));
  findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.file.localeCompare(b.file) || a.line - b.line);
  return { root, scannedFiles: files.length, findings };
}

// --- Dependencies: known vulnerabilities from OSV.dev (only package names + versions are sent) ---

function npmPackages(root) {
  const lock = join(root, 'package-lock.json');
  if (!existsSync(lock)) return [];
  try {
    const j = JSON.parse(readFileSync(lock, 'utf8'));
    const out = new Map();
    for (const [k, v] of Object.entries(j.packages || {})) {
      if (!k || !v.version || v.dev) continue;
      const name = v.name || k.slice(k.lastIndexOf('node_modules/') + 'node_modules/'.length);
      out.set(`${name}@${v.version}`, { ecosystem: 'npm', name, version: v.version, file: 'package-lock.json' });
    }
    return [...out.values()];
  } catch { return []; }
}

function pyPackages(root) {
  const req = join(root, 'requirements.txt');
  if (!existsSync(req)) return [];
  const out = [];
  for (const line of readFileSync(req, 'utf8').split('\n')) {
    const m = /^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*==\s*([\w.+-]+)/.exec(line);
    if (m) out.push({ ecosystem: 'PyPI', name: m[1], version: m[2], file: 'requirements.txt' });
  }
  return out;
}

async function dependencyFindings(root) {
  const pkgs = [...npmPackages(root), ...pyPackages(root)];
  if (!pkgs.length || typeof fetch !== 'function') return [];
  const vulnByPkg = [];
  try {
    for (let i = 0; i < pkgs.length; i += 500) {
      const chunk = pkgs.slice(i, i + 500);
      const res = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
        signal: AbortSignal.timeout(20000),
      });
      if (!res.ok) return [];
      const j = await res.json();
      j.results.forEach((r, idx) => { if (r.vulns?.length) vulnByPkg.push({ pkg: chunk[idx], ids: r.vulns.map((v) => v.id) }); });
    }
  } catch { return []; }
  return vulnByPkg.map(({ pkg, ids }) => {
    const shown = ids.filter((id) => id.startsWith('GHSA')).concat(ids.filter((id) => !id.startsWith('GHSA'))).slice(0, 4);
    return {
      rule: 'LP020', title: 'Dependency with a known vulnerability', severity: 'medium', file: pkg.file, line: 1,
      evidence: `${pkg.name}@${pkg.version}`,
      detail: `${pkg.name} ${pkg.version} has ${ids.length} published advisor${ids.length > 1 ? 'ies' : 'y'}: ${shown.join(', ')}${ids.length > shown.length ? ', …' : ''}. Check each for whether your app uses the affected feature.`,
      fix: `Upgrade ${pkg.name} to a patched version (npm audit fix / pip install -U), then re-run your tests.`,
    };
  });
}
