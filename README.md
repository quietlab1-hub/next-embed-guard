# next-embed-guard

Per-tenant iframe embedding for Next.js middleware.

One page of your app — a chat widget, a public dashboard, a booking form —
needs to be framable by *your customers' sites*, and only by those. The rest of
the app must stay `SAMEORIGIN`. `X-Frame-Options` cannot express that;
`Content-Security-Policy: frame-ancestors` can, but only if the allowlist is
resolved per request, per tenant.

That is all this module does:

```
authorized origins for the tenant  ->  Content-Security-Policy:
                                       frame-ancestors 'self' <origins...>
empty list / unknown tenant        ->  SAMEORIGIN
data source throws or times out    ->  SAMEORIGIN
```

## Design

- **Fail-closed, with no exceptions.** No error path widens the policy. A
  thrown lookup, a malformed value, an unparsable origin, an unknown tenant —
  all collapse to same-origin only.
- **No vendor, no schema.** You inject
  `getAllowedOrigins: (tenantId: string) => Promise<string[]>`. Static object,
  Postgres, KV, HTTP API — the module never knows.
- **Cached with a short TTL.** Middleware runs on every matching request; the
  data source should not. Negative results are cached too, so unknown tenants
  cannot be used to hammer the backend.
- **Edge-safe.** Only Web standards (`URL`, `RegExp`, `Map`). No Node built-ins,
  no framework imports.

## Usage

```ts
// middleware.ts
import { NextResponse, type NextRequest } from 'next/server'
import { createEmbedGuard } from 'next-embed-guard'

const guard = createEmbedGuard({
  pathPrefix: '/embed/',
  getAllowedOrigins: async (tenantId) => lookupOrigins(tenantId), // yours
})

export async function middleware(request: NextRequest) {
  const response = NextResponse.next()
  await guard.apply(request.nextUrl.pathname, response)
  return response
}

export const config = { matcher: ['/embed/:path*'] }
```

See [`examples/middleware.ts`](examples/middleware.ts) (static allowlist) and
[`examples/with-database.ts`](examples/with-database.ts) (async source, timeout,
error reporting, cache invalidation).

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `getAllowedOrigins` | *(required)* | `(tenantId) => Promise<string[]>`. Return `[]` for "not allowed". |
| `pathPrefix` | `'/embed/'` | Protected route; the first segment after it is the tenant id. Sub-paths match. |
| `extractTenantId` | — | Full control over matching; overrides `pathPrefix`. |
| `minTenantIdLength` | `1` | Reject short ids before the data source is called. |
| `maxTenantIdLength` | `128` | Reject over-long ids before the data source is called. |
| `tenantIdPattern` | — | Positive validation of the id, e.g. `/^[a-f0-9]{32}$/`. A non-matching id is treated as "not an embed route" and never reaches your lookup. |
| `cacheTtlMs` | `60_000` | TTL of the in-process cache. This is your revocation delay. |
| `maxCacheEntries` | `1000` | Oldest-first eviction. `0` disables caching. |
| `enforceFallback` | `true` | When not allowed, write `SAMEORIGIN` + `frame-ancestors 'self'` explicitly. Set `false` if a global header already does it. |
| `onError` | — | Observability hook. The request still fails closed. |

## Origin normalization

Entries may be written as `example.com`, `https://example.com` or
`https://example.com:8443`. Each is normalized to `scheme://host[:port]`; a bare
host is upgraded to `https://`; path, query and fragment are dropped.

Values containing whitespace, quotes, semicolons, backslashes, CR/LF or angle
brackets are **rejected**, not escaped — CSP separates sources with a single
space, so such a value could otherwise smuggle in extra sources or directives.
Rejected entries are dropped from the list; a list that ends up empty means
same-origin only.

Validation is positive, not a blocklist. After parsing, the host must be a
bracketed IPv6 literal or a series of dot-separated DNS labels (letters,
digits, inner hyphens, ≤63 chars each, ≤253 total) — which also covers IPv4 and
`localhost`. Underscores, trailing dots and empty labels are refused.
Non-`http(s)` schemes and embedded credentials are refused as well, so
`ftp://example.com` and `https://user:pass@example.com` both yield `null`
rather than a silently different origin.

## Development

```bash
npm install     # devDependencies only: typescript + @types/node
npm run typecheck
npm test
```

Tests use `node:test` — no test framework, no runtime dependency. Node 20
cannot execute TypeScript, so `npm test` compiles `src/` into `.test-build/`
first; on Node ≥ 22.6 `npm run test:strip` runs the `.ts` file directly.

`examples/` imports `next/server`, an optional peer dependency that is not
installed here, so it sits outside the default typecheck. To include it:
`npm i -D next && npx tsc -p tsconfig.examples.json`.

## Things worth knowing

- **Your CSP is preserved.** `apply()` edits only the `frame-ancestors`
  directive of `Content-Security-Policy`: any existing `frame-ancestors` is
  replaced, every other directive (`default-src`, a `script-src` nonce, …) is
  kept in place. Nothing else in the header is touched.
- **`X-Frame-Options` is removed on allow.** It has no per-origin form and, where
  still honored, would veto the CSP. On deny it is set back to `SAMEORIGIN`.
- **Per-isolate cache.** In serverless/edge deployments every instance caches
  independently. A revoked origin can survive up to `cacheTtlMs` on instances
  that already cached it; `invalidate()` only clears the isolate that runs it.
  Size the TTL for the revocation delay you can accept.
- **Framing is not authorization.** `frame-ancestors` controls who may *display*
  the page. It does not authenticate the visitor. The page itself must still
  enforce its own access rules.

## License

MIT
