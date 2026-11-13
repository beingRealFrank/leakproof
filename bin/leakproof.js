#!/usr/bin/env node
import { resolve } from 'node:path';
import { readFileSync, writeFileSync } from 'node:fs';
import { scan } from '../src/scan.js';
import * as report from '../src/report.js';
import { SEVERITIES } from '../src/rules.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const args = process.argv.slice(2);
const opt = { format: 'text', failOn: 'high', network: true, out: null, dir: '.' };
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '-h' || a === '--help') {
    console.log(`leakproof ${pkg.version} — find the security holes AI-built apps usually ship with

Usage: npx leakproof [dir] [--format text|md|json|sarif] [--out file] [--fail-on critical|high|medium|low|never] [--offline]

Checks: secrets in browser env vars and code, committed .env files, Supabase tables without
RLS and allow-all policies, open Firebase rules, admin keys in client code, SQL injection,
XSS sinks, unverified JWTs, unauthenticated API routes / server actions, CORS, and known-
vulnerable dependencies (OSV.dev; only package names+versions are sent; --offline skips it).
Nothing leaves your machine except that dependency lookup.`);
    process.exit(0);
  } else if (a === '-v' || a === '--version') { console.log(pkg.version); process.exit(0); }
  else if (a === '--format' || a === '-f') opt.format = args[++i];
  else if (a === '--out' || a === '-o') opt.out = args[++i];
  else if (a === '--fail-on') opt.failOn = args[++i];
  else if (a === '--offline') opt.network = false;
  else if (a.startsWith('-')) { console.error(`unknown option ${a}`); process.exit(2); }
  else opt.dir = a;
}

const result = await scan(resolve(opt.dir), { network: opt.network });
const render = { text: () => report.text(result, { color: !opt.out && process.stdout.isTTY }), md: () => report.markdown(result),
  markdown: () => report.markdown(result), json: () => report.json(result), sarif: () => report.sarif(result, pkg.version) }[opt.format];
if (!render) { console.error(`unknown format ${opt.format}`); process.exit(2); }
const output = render();
if (opt.out) writeFileSync(opt.out, output + '\n'); else console.log(output);

if (opt.failOn !== 'never') {
  const limit = SEVERITIES.indexOf(opt.failOn);
  if (result.findings.some((f) => SEVERITIES.indexOf(f.severity) <= limit)) process.exit(1);
}
