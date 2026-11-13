import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
import { scan } from '../src/scan.js';

// Fake secrets are assembled at runtime so this repo never contains strings that look like real keys.
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const serviceJwt = `${b64({ alg: 'HS256' })}.${b64({ iss: 'supabase', role: 'service_role', ref: 'abcdefghijkl' })}.${'s'.repeat(30)}`;
const anonJwt = `${b64({ alg: 'HS256' })}.${b64({ iss: 'supabase', role: 'anon', ref: 'abcdefghijkl' })}.${'a'.repeat(30)}`;
const stripe = 'sk_' + 'live_' + '4eC39HqLyjWDarjtT1zdp7dc0000';

function project(files, { git = true, commit = [] } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'lp-'));
  for (const [p, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), body);
  }
  if (git) {
    execFileSync('git', ['init', '-q'], { cwd: root });
    execFileSync('git', ['add', '--', ...Object.keys(files).filter((p) => !p.startsWith('.env') || commit.includes(p))], { cwd: root });
  }
  return root;
}
const rulesOf = (r) => r.findings.map((f) => `${f.rule}:${f.file}`).sort();

test('vulnerable vibe-coded app: every planted hole is found', async () => {
  const root = project({
    '.env.local': `NEXT_PUBLIC_SUPABASE_URL=https://x.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=${anonJwt}\nNEXT_PUBLIC_OPENAI_API_KEY=sk-123\nSUPABASE_SERVICE_ROLE_KEY=${serviceJwt}\n`,
    'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}',
    'supabase/migrations/001_init.sql': `create table public.profiles (id uuid primary key, user_id uuid);\nalter table public.profiles enable row level security;\ncreate table todos (id serial, user_id uuid, body text);\ncreate policy "anyone" on public.profiles for all using (true) with check (true);\ncreate policy "read" on public.profiles for select using (true);\n`,
    'firestore.rules': `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}\n`,
    'components/Admin.tsx': `'use client'\nimport { createClient } from '@supabase/supabase-js'\nconst s = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)\nexport default function A({ bio }) { return <div dangerouslySetInnerHTML={{ __html: bio }} /> }\n`,
    'app/api/todos/route.ts': `import { db } from '@/lib/db'\nexport async function POST(req) { const b = await req.json(); await db.todo.create({ data: b }); return Response.json({ ok: true }) }\n`,
    'app/actions.ts': `'use server'\nexport async function deleteTodo(id) { await prisma.todo.delete({ where: { id } }) }\n`,
    'lib/search.ts': `export const find = (q) => prisma.$queryRawUnsafe(\`select * from todos where body like '%\${q}%'\`)\n`,
    'lib/pay.ts': `const stripe = new Stripe('${stripe}')\n`,
    'lib/me.ts': `import jwt from 'jsonwebtoken'\nexport const me = (t) => jwt.decode(t).sub\n`,
    'server.js': `app.use(cors({ origin: true, credentials: true }))\n`,
    'config.js': `export const key = '${serviceJwt}'\n`,
    'app/api/suggest/route.ts': `import { auth } from '@/auth'\nexport async function POST(req) { await auth(); const r = await openai.chat.completions.create({ model: 'x', messages: [] }); return Response.json(r) }\n`,
    'supabase/migrations/002_storage.sql': `insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true);\n`,
  });
  const r = await scan(root, { network: false });
  const got = rulesOf(r);
  for (const want of ['LP001:.env.local', 'LP002:config.js', 'LP002:lib/pay.ts', 'LP004:supabase/migrations/001_init.sql',
    'LP005:supabase/migrations/001_init.sql', 'LP006:firestore.rules', 'LP007:components/Admin.tsx', 'LP008:lib/search.ts',
    'LP009:components/Admin.tsx', 'LP010:lib/me.ts', 'LP011:app/api/todos/route.ts', 'LP011:app/actions.ts', 'LP012:server.js', 'LP013:app/api/suggest/route.ts', 'LP014:supabase/migrations/002_storage.sql']) {
    assert.ok(got.includes(want), `missing ${want}; got ${got.join(', ')}`);
  }
  // .env.local is not committed, so its service-role key is not a "committed secret" (LP002/LP003)
  assert.ok(!got.includes('LP002:.env.local') && !got.includes('LP003:.env.local'));
  const rls = r.findings.filter((f) => f.rule === 'LP004');
  assert.equal(rls.length, 1, 'only todos lacks RLS');
  assert.match(rls[0].detail, /todos/);
});

test('committed .env is flagged', async () => {
  const root = project({ '.env': `DATABASE_URL=postgres://u:hunter22@db.acme-prod.net/x\n` }, { commit: ['.env'] });
  const got = rulesOf(await scan(root, { network: false }));
  assert.ok(got.includes('LP003:.env'));
  assert.ok(got.includes('LP002:.env'));
});

test('well-built app: no findings', async () => {
  const root = project({
    '.env.example': `NEXT_PUBLIC_SUPABASE_ANON_KEY=\nSUPABASE_SERVICE_ROLE_KEY=\nSTRIPE_SECRET_KEY=${'sk_' + 'live_' + 'x'.repeat(24)}\n`,
    '.env.local': `NEXT_PUBLIC_SUPABASE_ANON_KEY=${anonJwt}\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_abc\nSUPABASE_SERVICE_ROLE_KEY=${serviceJwt}\n`,
    'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}',
    'supabase/migrations/001.sql': `create table todos (id serial, user_id uuid);\nalter table todos enable row level security;\ncreate policy "own" on todos for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);\ncreate policy "public read" on todos for select to authenticated using (true);\n`,
    'app/api/todos/route.ts': `import { auth } from '@/auth'\nexport async function POST(req) { const s = await auth(); if (!s) return new Response(null,{status:401}); await db.todo.create({ data: { userId: s.user.id } }) }\n`,
    'app/actions.ts': `'use server'\nexport async function del(id) { const user = await getUser(); await prisma.todo.delete({ where: { id, userId: user.id } }) }\n`,
    'lib/admin.ts': `import 'server-only'\nexport const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY)\n`,
    'lib/q.ts': 'export const f = (q) => prisma.$queryRaw`select * from t where b = ${q}`\n',
    'components/Ld.tsx': `export const Ld = (d) => <script dangerouslySetInnerHTML={{ __html: JSON.stringify(d) }} />\n`,
    'components/Token.tsx': `'use client'\nimport { jwtDecode } from 'jwt-decode'\nexport const exp = (t) => jwtDecode(t).exp\n`,
    'firestore.rules': `allow read, write: if request.auth != null && request.auth.uid == userId;\n`,
    'app/api/suggest/route.ts': `import { ratelimit } from '@/lib/rl'\nexport async function POST(req) { await ratelimit.limit(ip); return Response.json(await openai.chat.completions.create({})) }\n`,
    'supabase/migrations/002.sql': `insert into storage.buckets (id, name, public) values ('avatars', 'avatars', false);\n`,
  });
  const r = await scan(root, { network: false });
  assert.deepEqual(rulesOf(r), []);
});
