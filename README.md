# Leakproof

Find the security holes that AI-built ("vibe-coded") apps usually ship with, in one command:

```bash
npx github:beingRealFrank/leakproof
```

No install, no account, no dependencies. Your code never leaves your machine; the only network call
is a lookup of your dependency names and versions on [OSV.dev](https://osv.dev) (`--offline` skips it).

## What it checks

| Rule | Finds | Why it matters |
|---|---|---|
| LP001 | Secrets in `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_` / `REACT_APP_` env vars | Those are pasted into the JS every visitor downloads |
| LP002 | Hard-coded keys: Stripe, OpenAI, Anthropic, AWS, GitHub, Supabase `service_role`, DB URLs… | Anyone with repo or bundle access has them |
| LP003 | `.env` files committed to git | Every value lives on in history |
| LP004 | Supabase tables with no Row Level Security | The anon key in your frontend can read/write every row |
| LP005 | RLS policies with `using (true)` | "Secured" tables that let everyone in |
| LP006 | Firebase rules `if true` or test-mode dates | Open database |
| LP007 | Service-role / firebase-admin keys in browser code | Full admin to every visitor |
| LP008 | SQL built by string interpolation | SQL injection |
| LP009 | `dangerouslySetInnerHTML` / `innerHTML` with dynamic values | XSS |
| LP010 | JWTs decoded without signature verification | Forged logins |
| LP011 | API routes / server actions that write data but never check the caller | Anyone can call them with curl |
| LP012 | CORS `*` with credentials | Other sites act as your users |
| LP013 | AI endpoints (OpenAI, Anthropic, AI SDK) with no rate limiting anywhere | One looping script = a huge bill |
| LP014 | Public Supabase storage buckets | Uploaded files readable by URL |
| LP020 | Dependencies with published advisories (OSV) | Known exploits |

It is tuned for few false positives: on popular open-source Next.js + Supabase starters it reports only a handful of low-severity notes.

## Options

```
npx github:beingRealFrank/leakproof [dir] [--format text|md|json|sarif] [--out file]
                                          [--fail-on critical|high|medium|low|never] [--offline]
```

Exit code 1 when anything at `--fail-on` severity (default `high`) or worse is found, so it can gate CI.

## GitHub Action

```yaml
# .github/workflows/leakproof.yml
name: leakproof
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: beingRealFrank/leakproof@v0
        with: { fail-on: high }
```

The findings appear in the job summary. Set `sarif: true` and add `github/codeql-action/upload-sarif` to see them in the Security tab.

## Limits

Pattern checks can't see your deployed configuration (Supabase dashboard settings, storage buckets, Vercel env), business-logic flaws (user A reading user B's order by changing an id), missing rate limits, or anything that needs the app running. A clean scan is a good start, not a clean bill of health.

## Guides

- [The Supabase RLS checklist for AI-built apps](https://beingrealfrank.github.io/leakproof/supabase-rls-checklist.html)
- [The Firebase security rules checklist for AI-built apps](https://beingrealfrank.github.io/leakproof/firebase-rules-checklist.html)
- [Secret keys in your frontend: the NEXT_PUBLIC_ and VITE_ checklist](https://beingrealfrank.github.io/leakproof/public-env-secrets-checklist.html)

## Want a full audit?

[Leakproof audits](https://beingrealfrank.github.io/leakproof/) go further for a fixed price: a review of the whole codebase and your
live Supabase/Firebase config (with your permission, read-only), every finding reproduced and checked before you see it,
and you get a written report plus pull requests that fix what was found.

## License

MIT
