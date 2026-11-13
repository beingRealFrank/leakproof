// Each rule looks at one file at a time and returns findings.
// A finding: { rule, severity, title, file, line, evidence, fix }
// Rules aim for few false positives: a noisy scanner gets uninstalled.

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];

const CLIENT_ENV_PREFIX = /\b(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_)([A-Z0-9_]+)/g;
const SECRET_WORD = /(SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD|DATABASE_URL|DB_URL|POSTGRES_URL|MONGODB_URI|AUTH_TOKEN)/;
const VENDOR = /(OPENAI|ANTHROPIC|CLAUDE|STRIPE|RESEND|SENDGRID|TWILIO|AWS|GROQ|GEMINI|REPLICATE|ELEVENLABS|MISTRAL|PERPLEXITY|OPENROUTER|COHERE|HUGGINGFACE|DEEPSEEK|PINECONE|UPSTASH|LEMON|POLAR|PAYPAL)/;
const isSecretName = (n) => SECRET_WORD.test(n) || (VENDOR.test(n) && /(KEY|TOKEN)/.test(n));
// Names that look secret but are meant to be public.
const PUBLIC_OK = /(PUBLISHABLE|PK_|CLIENT_ID|ANON_KEY|SITE_KEY|PUBLIC_KEY|MEASUREMENT_ID|POSTHOG_KEY|SENTRY_DSN|MAPBOX_TOKEN)/;

const TOKEN_PATTERNS = [
  { re: /\bsk_live_[0-9a-zA-Z]{20,}/, what: 'Stripe live secret key' },
  { re: /\brk_live_[0-9a-zA-Z]{20,}/, what: 'Stripe live restricted key' },
  { re: /\bsk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{20,}/, what: 'Anthropic API key' },
  { re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}/, what: 'OpenAI API key' },
  { re: /\bsk-proj-[A-Za-z0-9_-]{40,}/, what: 'OpenAI project key' },
  { re: /\bAKIA[0-9A-Z]{16}\b/, what: 'AWS access key id' },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, what: 'private key' },
  { re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, what: 'GitHub token' },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, what: 'Slack token' },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/, what: 'Google API key', severity: 'medium',
    note: 'Google/Firebase browser keys are often meant to be public; make sure this one is restricted by HTTP referrer and API in Google Cloud console.' },
  { re: /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}/, what: 'Resend API key' },
  { re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/, what: 'SendGrid API key' },
  { re: /\bgsk_[A-Za-z0-9]{40,}/, what: 'Groq API key' },
  { re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^:\s'"`]+:[^@\s'"`]{3,}@[^\s'"`]+/, what: 'database URL with password' },
];

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

function jwtRole(token) {
  try {
    const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(Buffer.from(payload, 'base64').toString('utf8'));
    if (claims.iss === 'supabase-demo') return 'demo'; // Supabase CLI's well-known local key
    return claims.role;
  } catch { return undefined; }
}

function lineOf(text, index) {
  let n = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

function redact(s) {
  if (s.length <= 12) return s.slice(0, 4) + '…';
  return s.slice(0, 8) + '…' + s.slice(-4);
}

function snippet(text, index) {
  const start = text.lastIndexOf('\n', index) + 1;
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  return text.slice(start, end).trim().slice(0, 160);
}

const isEnvFile = (p) => /(^|\/)\.env(\.[\w-]+)?$/.test(p) && !/\.(example|sample|template|dist)$/.test(p);
const isExampleFile = (p) => /\.(example|sample|template|dist)$|(^|\/)(examples?|fixtures?|__tests__|tests?|spec|docs?)\//i.test(p);
const isCode = (p) => /\.(m?[jt]sx?|cjs|cts|vue|svelte|astro|py|rb|go|php)$/.test(p);
const isJsLike = (p) => /\.(m?[jt]sx?|cjs|cts|vue|svelte|astro)$/.test(p);

// Is this file shipped to the browser?
function isClientFile(path, text) {
  if (!isJsLike(path)) return false;
  if (/^\s*['"]use client['"]/m.test(text)) return true;
  if (/(^|\/)(pages\/api|app\/api|server|api|functions|supabase\/functions|backend|scripts?|lib\/server)\//.test(path)) return false;
  if (/['"]use server['"]/.test(text) || /\broute\.(m?[jt]s)$/.test(path) || /(^|\/)middleware\.[jt]s$/.test(path)) return false;
  if (/(^|\/)(components|hooks)\//.test(path)) return true;
  if (/\.(vue|svelte)$/.test(path)) return !/\+(page|layout)\.server\.|\+server\./.test(path);
  if (/(^|\/)src\//.test(path) && /import\.meta\.env/.test(text)) return true; // Vite app code
  return false;
}

export const rules = [
  {
    id: 'LP001',
    title: 'Secret exposed through a browser-visible env var',
    check(path, text) {
      if (!(isEnvFile(path) || isCode(path)) || isExampleFile(path)) return [];
      const out = [];
      for (const m of text.matchAll(CLIENT_ENV_PREFIX)) {
        const name = m[2];
        if (!isSecretName(name) || PUBLIC_OK.test(name)) continue;
        out.push({
          severity: 'critical', line: lineOf(text, m.index), evidence: m[0],
          detail: `${m[0]} is inlined into the JavaScript bundle that every visitor downloads, so anyone can read it.`,
          fix: `Rename it without the ${m[1]} prefix, read it only in server code (API route, server action, edge function), and rotate the current value — assume it has already leaked.`,
        });
      }
      return dedupeByEvidence(out);
    },
  },
  {
    id: 'LP002',
    title: 'Hard-coded secret',
    check(path, text, ctx) {
      if (isExampleFile(path)) return [];
      if (isEnvFile(path) && !ctx.trackedByGit(path)) return []; // local .env that git ignores is fine
      const out = [];
      for (const p of TOKEN_PATTERNS) {
        const m = p.re.exec(text);
        if (!m) continue;
        if (/x{6,}|your[_-]|<|placeholder|example|dummy|changeme/i.test(m[0])) continue;
        out.push({
          severity: p.severity || (isClientFile(path, text) ? 'critical' : 'high'),
          line: lineOf(text, m.index), evidence: redact(m[0]),
          detail: `Looks like a ${p.what} committed to the repository.${p.note ? ' ' + p.note : ''}`,
          fix: p.note ? 'Restrict the key, or move it to a server-side env var.' : 'Revoke and rotate the key now, move it to a server-side env var, and purge it from git history (git filter-repo or BFG).',
        });
      }
      for (const m of text.matchAll(JWT)) {
        if (jwtRole(m[0]) !== 'service_role') continue;
        out.push({
          severity: 'critical', line: lineOf(text, m.index), evidence: redact(m[0]),
          detail: 'A Supabase service_role key is committed. It bypasses every Row Level Security policy: whoever has it can read and write your whole database.',
          fix: 'Rotate the JWT secret / service key in Supabase now, keep the new one only in server-side env vars, and purge it from git history.',
        });
      }
      return out;
    },
  },
  {
    id: 'LP003',
    title: '.env file committed to git',
    check(path, text, ctx) {
      if (!isEnvFile(path) || !ctx.trackedByGit(path)) return [];
      if (!/^\s*[A-Z0-9_]+\s*=\s*\S+/m.test(text)) return [];
      return [{
        severity: 'high', line: 1, evidence: path,
        detail: 'This env file is tracked by git, so every value in it is in the repository history.',
        fix: 'git rm --cached it, add it to .gitignore, commit a .env.example with blank values instead, and rotate anything secret it held.',
      }];
    },
  },
  {
    id: 'LP004',
    title: 'Supabase/Postgres table without Row Level Security',
    project: true,
    checkProject(files) {
      const created = new Map();
      const enabled = new Set();
      const norm = (n) => n.replace(/"/g, '').toLowerCase().replace(/^public\./, '');
      for (const { path, text } of files) {
        if (!/\.sql$/.test(path)) continue;
        const clean = text.replace(/--[^\n]*/g, '');
        for (const m of clean.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?((?:"?[\w]+"?\.)?"?[\w]+"?)/gi)) {
          const name = norm(m[1]);
          if (name.includes('.')) continue; // non-public schema
          if (!created.has(name)) created.set(name, { path, line: lineOf(clean, m.index) });
        }
        for (const m of clean.matchAll(/alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?((?:"?[\w]+"?\.)?"?[\w]+"?)\s+enable\s+row\s+level\s+security/gi)) {
          enabled.add(norm(m[1]));
        }
      }
      const usesSupabase = files.some((f) => /supabase/.test(f.path) || /@supabase\/supabase-js|supabase-py|from supabase/.test(f.text));
      if (!usesSupabase) return [];
      const out = [];
      for (const [name, at] of created) {
        if (enabled.has(name)) continue;
        out.push({
          severity: 'critical', file: at.path, line: at.line, evidence: `create table ${name}`,
          detail: `Table "${name}" never gets "enable row level security". With Supabase, the anon key in your frontend can then read and write every row of it through the REST API.`,
          fix: `alter table public.${name} enable row level security;  then add policies, e.g. create policy "own rows" on public.${name} for all using (auth.uid() = user_id) with check (auth.uid() = user_id);`,
        });
      }
      return out;
    },
  },
  {
    id: 'LP005',
    title: 'Row Level Security policy that allows everyone',
    check(path, text) {
      if (!/\.sql$/.test(path)) return [];
      const out = [];
      const clean = text.replace(/--[^\n]*/g, '');
      for (const m of clean.matchAll(/create\s+policy\s+("[^"]+"|\w+)\s+on\s+([\w."]+)([\s\S]*?);/gi)) {
        const body = m[3];
        const forWhat = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(body)?.[1] || 'all').toLowerCase();
        const open = /\b(using|with\s+check)\s*\(\s*true\s*\)/i.test(body);
        if (!open) continue;
        const toAnon = !/\bto\s+(authenticated|service_role)\b/i.test(body);
        if (forWhat === 'select' && toAnon) {
          out.push({ severity: 'low', line: lineOf(clean, m.index), evidence: snippet(clean, m.index),
            detail: `Policy ${m[1]} lets anyone, signed in or not, read every row of ${m[2]}. Fine for truly public data, a leak for anything per-user.`,
            fix: 'If rows belong to users, use using (auth.uid() = user_id). If the table is public by design, ignore this.' });
        } else if (forWhat !== 'select') {
          out.push({ severity: toAnon ? 'critical' : 'high', line: lineOf(clean, m.index), evidence: snippet(clean, m.index),
            detail: `Policy ${m[1]} lets ${toAnon ? 'anyone, even signed-out visitors,' : 'any signed-in user'} ${forWhat === 'all' ? 'read, insert, change and delete' : forWhat} rows of ${m[2]}, including other users' rows.`,
            fix: 'Replace true with an ownership check, e.g. using (auth.uid() = user_id) with check (auth.uid() = user_id).' });
        }
      }
      return out;
    },
  },
  {
    id: 'LP006',
    title: 'Firebase security rules open to everyone',
    check(path, text) {
      const out = [];
      if (/(^|\/)(firestore|storage)\.rules$|\.rules$/.test(path)) {
        for (const m of text.matchAll(/allow\s+([\w,\s]+?)\s*:\s*if\s+true\s*;/g)) {
          out.push({ severity: 'critical', line: lineOf(text, m.index), evidence: m[0],
            detail: `Anyone on the internet can ${m[1].trim()} this data with your public Firebase config.`,
            fix: 'Require auth and ownership, e.g. allow read, write: if request.auth != null && request.auth.uid == resource.data.uid;' });
        }
        for (const m of text.matchAll(/allow\s+([\w,\s]+?)\s*:\s*if\s+request\.time\s*<\s*timestamp\.date/g)) {
          out.push({ severity: 'critical', line: lineOf(text, m.index), evidence: snippet(text, m.index),
            detail: 'These are Firebase "test mode" rules: wide open to everyone until the date passes.',
            fix: 'Replace with rules that check request.auth and document ownership.' });
        }
      }
      if (/(^|\/)database\.rules\.json$/.test(path)) {
        for (const m of text.matchAll(/"\.(read|write)"\s*:\s*(true|"true")/g)) {
          out.push({ severity: 'critical', line: lineOf(text, m.index), evidence: m[0],
            detail: `Realtime Database ${m[1]} access is open to everyone.`,
            fix: 'Use "auth != null && auth.uid === $uid" style rules.' });
        }
      }
      return out;
    },
  },
  {
    id: 'LP007',
    title: 'Admin/service-role database client in browser code',
    check(path, text) {
      if (!isClientFile(path, text)) return [];
      const m = /(SUPABASE_SERVICE_ROLE(?:_KEY)?|SERVICE_ROLE_KEY|serviceRoleKey|firebase-admin|FIREBASE_PRIVATE_KEY)/.exec(text);
      if (!m) return [];
      return [{ severity: 'critical', line: lineOf(text, m.index), evidence: snippet(text, m.index),
        detail: `${m[1]} is referenced in a file that runs in the browser. Admin credentials there give every visitor full database access (or the build silently breaks auth).`,
        fix: 'Move admin calls into a server-only route or server action; the browser should only use the anon/publishable key plus RLS.' }];
    },
  },
  {
    id: 'LP008',
    title: 'SQL built from string interpolation',
    check(path, text) {
      if (!isCode(path) || isExampleFile(path)) return [];
      const out = [];
      const patterns = [
        /\$(?:query|execute)RawUnsafe\s*\(/g,
        /\b(?:query|execute|raw|unsafe)\s*\(\s*`[^`]*\b(?:select|insert|update|delete)\b[^`]*\$\{/gi,
        /\bsql\.raw\s*\(\s*`[^`]*\$\{/g,
        /\b(?:execute|query)\s*\(\s*f["'][^"']*\b(?:select|insert|update|delete)\b[^"']*\{/gi,
        /\b(?:execute|query)\s*\(\s*["'][^"']*\b(?:select|insert|update|delete)\b[^"']*["']\s*(?:%|\+)\s*/gi,
      ];
      for (const re of patterns) {
        for (const m of text.matchAll(re)) {
          out.push({ severity: 'high', line: lineOf(text, m.index), evidence: snippet(text, m.index),
            detail: 'User input that reaches this query string can change the SQL itself (SQL injection).',
            fix: 'Use parameters: Prisma $queryRaw`... ${x}` (tagged, not Unsafe), pg query("... $1", [x]), cursor.execute("... %s", (x,)).' });
        }
      }
      return dedupeByLine(out);
    },
  },
  {
    id: 'LP009',
    title: 'HTML injection sink (possible XSS)',
    check(path, text) {
      if (!isJsLike(path) || isExampleFile(path)) return [];
      const out = [];
      for (const m of text.matchAll(/dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}/g)) {
        const v = m[1].trim().replace(/,$/, "").trim();
        if (/^['"`][^$]*['"`]$/.test(v) || /sanitize|purify|DOMPurify|xss\(|escape/i.test(v)) continue;
        if (/JSON\.stringify/.test(v)) continue; // JSON-LD pattern
        if (/^[A-Z][A-Z0-9_]*$/.test(v)) continue; // module constant
        out.push({ severity: 'medium', line: lineOf(text, m.index), evidence: snippet(text, m.index),
          detail: 'Raw HTML from a variable is rendered. If any part comes from users (profiles, comments, AI output, markdown), it can run script in other users\' sessions.',
          fix: 'Sanitize first: __html: DOMPurify.sanitize(html), or render markdown with a sanitizing renderer.' });
      }
      for (const m of text.matchAll(/\.innerHTML\s*=\s*(?!['"`][^$]*['"`]\s*;)([^;\n]+)/g)) {
        if (/sanitize|purify/i.test(m[1]) || /^\s*['"]{2}\s*$/.test(m[1])) continue;
        out.push({ severity: 'low', line: lineOf(text, m.index), evidence: snippet(text, m.index),
          detail: 'innerHTML is assigned a dynamic value. If any of it comes from users or AI output, it can run script.', fix: 'Use textContent, or sanitize with DOMPurify.' });
      }
      return out;
    },
  },
  {
    id: 'LP010',
    title: 'JWT read without verifying its signature',
    check(path, text) {
      if (!isCode(path) || isExampleFile(path)) return [];
      const out = [];
      for (const m of text.matchAll(/\bjwt\.decode\s*\(|\bjwtDecode\s*\(|\bdecodeJwt\s*\(|algorithms\s*:\s*\[\s*['"]none['"]|verify_signature['"]?\s*:\s*False/g)) {
        if (isClientFile(path, text) && !/algorithms|verify_signature/.test(m[0])) continue; // decoding in UI is normal
        out.push({ severity: 'high', line: lineOf(text, m.index), evidence: snippet(text, m.index),
          detail: 'Server code reads a JWT without checking its signature. Anyone can forge a token claiming to be any user or an admin.',
          fix: 'Use jwt.verify(token, secret, { algorithms: ["HS256"] }) / jose jwtVerify, or your auth provider\'s getUser() which validates server-side.' });
      }
      return out;
    },
  },
  {
    id: 'LP011',
    title: 'Data-changing endpoint with no auth check',
    check(path, text) {
      if (!isJsLike(path) || isExampleFile(path)) return [];
      const isRoute = /(^|\/)app\/.*\/route\.(m?[jt]s)$/.test(path) || /(^|\/)pages\/api\//.test(path);
      const isAction = /^\s*['"]use server['"]/m.test(text);
      if (!isRoute && !isAction) return [];
      const writes = /\b(?:prisma|db|tx|database)\.\w+\.(?:create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\(|\.from\([^)]*\)\s*\.(?:insert|update|upsert|delete)\s*\(|\b(?:db|tx|database)\s*\.\s*(?:insert|update|delete)\s*\(|\.(?:insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|findOneAndUpdate|findByIdAndUpdate|findByIdAndDelete)\s*\(|\b(?:INSERT\s+INTO|DELETE\s+FROM)\b|\bUPDATE\s+\w+\s+SET\b|\b(?:setDoc|addDoc|updateDoc|deleteDoc)\s*\(/;
      if (!writes.test(text)) return [];
      if (isRoute && !/export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\b|export\s+default/.test(text)) return [];
      const authSignal = /\b(auth|getServerSession|getSession|getUser|currentUser|getAuth|requireAuth|requireUser|withAuth|verifyToken|jwtVerify|jwt\.verify|clerk|kinde|lucia|validateRequest|getToken|authorization|session|isAdmin|checkAuth|ensureAuth|stripe\.webhooks\.constructEvent|verifyWebhook|svix|signature)\b/i;
      if (authSignal.test(text) || /\b(?:get|fetch|load)\w*(?:User|Session|Profile|Account|Viewer)\s*\(|\b(?:require|ensure|check|verify|assert|protect)\w*(?:Auth|User|Session|Admin|Owner|Login)\w*\s*\(/.test(text)) return [];
      const m = writes.exec(text);
      return [{ severity: 'high', line: lineOf(text, m.index), evidence: snippet(text, m.index),
        detail: `This ${isAction ? 'server action' : 'API route'} writes to the database but never checks who is calling. Server actions and API routes are public HTTP endpoints: anyone can call them directly, without your UI.`,
        fix: 'At the top: const user = await getUser(); if (!user) return 401; then make sure the row being changed belongs to user.id.' }];
    },
  },
  {
    id: 'LP012',
    title: 'CORS allows any origin with credentials',
    check(path, text) {
      if (!isCode(path) || isExampleFile(path)) return [];
      const out = [];
      const re = /cors\s*\(\s*\{[^}]*origin\s*:\s*(true|['"]\*['"])[^}]*credentials\s*:\s*true|cors\s*\(\s*\{[^}]*credentials\s*:\s*true[^}]*origin\s*:\s*(true|['"]\*['"])|allow_origins\s*=\s*\[\s*["']\*["']\s*\][\s\S]{0,200}allow_credentials\s*=\s*True/g;
      for (const m of text.matchAll(re)) {
        out.push({ severity: 'medium', line: lineOf(text, m.index), evidence: snippet(text, m.index),
          detail: 'Any website can make credentialed requests to this API and read the responses as the logged-in user.',
          fix: 'List your real frontend origins explicitly.' });
      }
      return out;
    },
  },
  {
    id: 'LP013',
    title: 'AI endpoint with no rate limit',
    project: true,
    checkProject(files) {
      const RL = /@upstash\/ratelimit|express-rate-limit|rate-limiter-flexible|@arcjet|slowapi|flask[_-]limiter|django-ratelimit|\bratelimit\b|\brateLimit\b|\brate_limit\b|\blimiter\b/i;
      if (files.some((f) => RL.test(f.text))) return []; // some rate limiting exists; can't tell coverage statically
      const LLM = /\.chat\.completions\.create\s*\(|\.messages\.create\s*\(|\.responses\.create\s*\(|\b(?:generateText|streamText|generateObject|streamObject)\s*\(|\.generateContent\s*\(/;
      const out = [];
      for (const { path, text } of files) {
        if (!isJsLike(path) && !/\.py$/.test(path)) continue;
        if (isExampleFile(path)) continue;
        const endpoint = /(^|\/)app\/.*\/route\.(m?[jt]s)$/.test(path) || /(^|\/)pages\/api\//.test(path) || /^\s*['"]use server['"]/m.test(text)
          || /(^|\/)(supabase\/functions|netlify\/functions|api)\//.test(path) || /@app\.(post|get)\(|@router\.(post|get)\(/.test(text);
        if (!endpoint) continue;
        const m = LLM.exec(text);
        if (!m) continue;
        if (/apiKey\s*:\s*(?:profile|user|body|req|settings|custom|userKey|byok)|(?:profile|user|settings)\.\w*api_?key/i.test(text)) continue; // users bring their own key
        out.push({ severity: 'medium', file: path, line: lineOf(text, m.index), evidence: snippet(text, m.index),
          detail: 'This endpoint calls a paid AI model and the project has no rate limiting anywhere. One script looping on it can run up a large bill or exhaust your quota.',
          fix: 'Add a per-user/IP limit, e.g. @upstash/ratelimit (Ratelimit.slidingWindow(10, "1 m")) at the top of the handler, and set a hard monthly spend cap with your AI provider.' });
      }
      return out;
    },
  },
  {
    id: 'LP014',
    title: 'Public Supabase storage bucket',
    check(path, text) {
      if (!/\.sql$/.test(path)) return [];
      const out = [];
      for (const m of text.matchAll(/insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values\s*\(([^)]*)\)/gi)) {
        const cols = m[1].split(',').map((s) => s.trim().replace(/"/g, ''));
        const vals = m[2].split(',').map((s) => s.trim());
        const i = cols.indexOf('public');
        if (i === -1 || !/^true$/i.test(vals[i] || '')) continue;
        out.push({ severity: 'low', line: lineOf(text, m.index), evidence: snippet(text, m.index),
          detail: `Bucket ${vals[cols.indexOf('id')] || vals[0]} is public: anyone with (or guessing) a file URL can download it, with no policy check. Fine for avatars and marketing images, a leak for invoices, uploads or exports.`,
          fix: 'Make the bucket private and serve files with createSignedUrl(), unless everything in it is meant to be public.' });
      }
      return out;
    },
  },
];

function dedupeByEvidence(list) {
  const seen = new Set();
  return list.filter((f) => (seen.has(f.evidence) ? false : seen.add(f.evidence)));
}
function dedupeByLine(list) {
  const seen = new Set();
  return list.filter((f) => (seen.has(f.line) ? false : seen.add(f.line)));
}
