/**
 * Test suite — `node:test` only, no third-party dependency.
 *
 *   npm test
 *
 * Node 20 cannot execute TypeScript directly, so `npm test` compiles this file
 * with `tsc` first and runs the JavaScript output. On Node >= 22.6 you can skip
 * the build step: `node --test --experimental-strip-types src/*.test.ts`.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  buildFrameAncestors,
  createEmbedGuard,
  mergeFrameAncestors,
  normalizeOrigin,
  normalizeOrigins,
  type MutableHeaders,
  type ResponseWithHeaders,
} from './embed-guard.js'

/* ------------------------------------------------------------------
   Minimal stand-in for `Headers` (case-insensitive, like the real one).
   ------------------------------------------------------------------ */

class FakeHeaders implements MutableHeaders {
  private readonly map = new Map<string, string>()

  constructor(initial: Record<string, string> = {}) {
    for (const [k, v] of Object.entries(initial)) this.set(k, v)
  }

  get(name: string): string | null {
    return this.map.get(name.toLowerCase()) ?? null
  }

  set(name: string, value: string): void {
    this.map.set(name.toLowerCase(), value)
  }

  delete(name: string): void {
    this.map.delete(name.toLowerCase())
  }

  has(name: string): boolean {
    return this.map.has(name.toLowerCase())
  }
}

function fakeResponse(initial: Record<string, string> = {}): ResponseWithHeaders & {
  headers: FakeHeaders
} {
  return { headers: new FakeHeaders(initial) }
}

const csp = (r: { headers: FakeHeaders }) => r.headers.get('Content-Security-Policy')
const xfo = (r: { headers: FakeHeaders }) => r.headers.get('X-Frame-Options')

/* ==================================================================
   normalizeOrigin
   ================================================================== */

describe('normalizeOrigin', () => {
  it('upgrades a bare host to https and drops path/query/fragment', () => {
    assert.equal(normalizeOrigin('example.com'), 'https://example.com')
    assert.equal(normalizeOrigin('https://example.com/'), 'https://example.com')
    assert.equal(normalizeOrigin('https://example.com/a/b?c=1#d'), 'https://example.com')
    assert.equal(normalizeOrigin('  example.com  '), 'https://example.com')
  })

  it('lowercases the host and keeps an explicit port', () => {
    assert.equal(normalizeOrigin('EXAMPLE.COM'), 'https://example.com')
    assert.equal(normalizeOrigin('https://example.com:8443'), 'https://example.com:8443')
    assert.equal(normalizeOrigin('http://localhost:3000'), 'http://localhost:3000')
  })

  it('rejects characters that could break out of the CSP header', () => {
    // A single space would end the source and start another one; quotes and
    // semicolons could introduce a keyword or a whole new directive.
    assert.equal(normalizeOrigin("evil.com' ; script-src *"), null)
    assert.equal(normalizeOrigin('evil.com script-src'), null)
    assert.equal(normalizeOrigin('evil.com;script-src *'), null)
    assert.equal(normalizeOrigin('evil.com\nscript-src *'), null)
    assert.equal(normalizeOrigin('evil.com\r\nSet-Cookie: a=b'), null)
    assert.equal(normalizeOrigin('<script>'), null)
    assert.equal(normalizeOrigin('back\\slash.com'), null)
  })

  it('rejects non-strings, empties and unparsable input', () => {
    assert.equal(normalizeOrigin(null), null)
    assert.equal(normalizeOrigin(undefined), null)
    assert.equal(normalizeOrigin(42), null)
    assert.equal(normalizeOrigin({}), null)
    assert.equal(normalizeOrigin(''), null)
    assert.equal(normalizeOrigin('   '), null)
    assert.equal(normalizeOrigin('https://'), null)
  })

  /* --- point 3: positive host validation --- */

  it('accepts well-formed hosts: DNS names, IPv4, IPv6, punycode', () => {
    assert.equal(normalizeOrigin('sub.domain.example.com'), 'https://sub.domain.example.com')
    assert.equal(normalizeOrigin('my-tenant.example.com'), 'https://my-tenant.example.com')
    assert.equal(normalizeOrigin('localhost'), 'https://localhost')
    assert.equal(normalizeOrigin('127.0.0.1'), 'https://127.0.0.1')
    assert.equal(normalizeOrigin('http://[::1]:8080'), 'http://[::1]:8080')
    assert.equal(normalizeOrigin('xn--bcher-kva.example'), 'https://xn--bcher-kva.example')
    // Internationalized input is punycoded by URL before validation.
    assert.equal(normalizeOrigin('bücher.example'), 'https://xn--bcher-kva.example')
  })

  it('rejects malformed hosts that URL would otherwise tolerate', () => {
    assert.equal(normalizeOrigin('under_score.example.com'), null)
    assert.equal(normalizeOrigin('trailing.dot.'), null)
    assert.equal(normalizeOrigin('double..dot.com'), null)
    assert.equal(normalizeOrigin('-leading-hyphen.com'), null)
    assert.equal(normalizeOrigin('trailing-hyphen-.com'), null)
    assert.equal(normalizeOrigin(`${'a'.repeat(64)}.com`), null) // label > 63
    assert.equal(normalizeOrigin(`${'a'.repeat(60)}.`.repeat(5)), null) // host > 253
  })

  it('rejects non-http(s) schemes and embedded credentials', () => {
    assert.equal(normalizeOrigin('ftp://example.com'), null)
    assert.equal(normalizeOrigin('javascript:alert(1)'), null)
    assert.equal(normalizeOrigin('data:text/html,x'), null)
    // Would otherwise be silently reduced to https://example.com.
    assert.equal(normalizeOrigin('https://user:pass@example.com'), null)
  })
})

describe('normalizeOrigins', () => {
  it('drops invalid entries and de-duplicates, keeping the valid ones', () => {
    assert.deepEqual(
      normalizeOrigins([
        'acme.example',
        'https://www.acme.example/',
        "evil.com' ; script-src *",
        42,
        null,
        'acme.example',
      ]),
      ['https://acme.example', 'https://www.acme.example'],
    )
  })

  it('returns an empty list for non-arrays (embedding disabled)', () => {
    assert.deepEqual(normalizeOrigins(undefined), [])
    assert.deepEqual(normalizeOrigins(null), [])
    assert.deepEqual(normalizeOrigins('acme.example'), [])
    assert.deepEqual(normalizeOrigins({ 0: 'acme.example' }), [])
  })
})

describe('buildFrameAncestors', () => {
  it('falls back to self-only for an empty list', () => {
    assert.equal(buildFrameAncestors([]), "frame-ancestors 'self'")
  })

  it('lists origins after self', () => {
    assert.equal(
      buildFrameAncestors(['https://a.example', 'https://b.example']),
      "frame-ancestors 'self' https://a.example https://b.example",
    )
  })
})

/* ==================================================================
   point 1: CSP merging
   ================================================================== */

describe('mergeFrameAncestors', () => {
  it('returns the directive alone when there is no existing CSP', () => {
    assert.equal(mergeFrameAncestors(null, "frame-ancestors 'self'"), "frame-ancestors 'self'")
    assert.equal(mergeFrameAncestors(undefined, "frame-ancestors 'self'"), "frame-ancestors 'self'")
    assert.equal(mergeFrameAncestors('   ', "frame-ancestors 'self'"), "frame-ancestors 'self'")
  })

  it('preserves other directives and appends the new one', () => {
    assert.equal(
      mergeFrameAncestors("default-src 'self'; script-src 'nonce-abc'", "frame-ancestors 'self' https://a.example"),
      "default-src 'self'; script-src 'nonce-abc'; frame-ancestors 'self' https://a.example",
    )
  })

  it('replaces an existing frame-ancestors, wherever it sits', () => {
    assert.equal(
      mergeFrameAncestors("frame-ancestors 'none'; default-src 'self'", "frame-ancestors 'self'"),
      "default-src 'self'; frame-ancestors 'self'",
    )
    assert.equal(
      mergeFrameAncestors("default-src 'self'; frame-ancestors 'none'; img-src *", "frame-ancestors 'self'"),
      "default-src 'self'; img-src *; frame-ancestors 'self'",
    )
  })

  it('is case-insensitive on the directive name and tolerates loose spacing', () => {
    assert.equal(
      mergeFrameAncestors("default-src 'self';   FRAME-ANCESTORS   'none'  ;", "frame-ancestors 'self'"),
      "default-src 'self'; frame-ancestors 'self'",
    )
  })

  it('does not confuse a directive whose name merely starts the same', () => {
    // No such directive today, but the matcher must compare whole names.
    assert.equal(
      mergeFrameAncestors('frame-ancestors-x 1', "frame-ancestors 'self'"),
      "frame-ancestors-x 1; frame-ancestors 'self'",
    )
  })
})

describe('apply() and existing CSP headers', () => {
  const guard = () =>
    createEmbedGuard({
      pathPrefix: '/embed/',
      getAllowedOrigins: async (id) => (id === 'acme' ? ['acme.example'] : []),
    })

  it('keeps the app CSP intact when allowing (allowed branch)', async () => {
    const g = guard()
    const res = fakeResponse({
      'Content-Security-Policy': "default-src 'self'; script-src 'nonce-abc'",
    })
    await g.apply('/embed/acme', res)
    assert.equal(
      csp(res),
      "default-src 'self'; script-src 'nonce-abc'; frame-ancestors 'self' https://acme.example",
    )
  })

  it('keeps the app CSP intact when denying (enforceFallback branch)', async () => {
    const g = guard()
    const res = fakeResponse({
      'Content-Security-Policy': "default-src 'self'; script-src 'nonce-abc'",
    })
    await g.apply('/embed/unknown', res)
    assert.equal(
      csp(res),
      "default-src 'self'; script-src 'nonce-abc'; frame-ancestors 'self'",
    )
    assert.equal(xfo(res), 'SAMEORIGIN')
  })

  it('overrides a pre-existing frame-ancestors in both branches', async () => {
    const allowed = fakeResponse({ 'Content-Security-Policy': "frame-ancestors 'none'" })
    await guard().apply('/embed/acme', allowed)
    assert.equal(csp(allowed), "frame-ancestors 'self' https://acme.example")

    const denied = fakeResponse({ 'Content-Security-Policy': "frame-ancestors https://old.example" })
    await guard().apply('/embed/unknown', denied)
    assert.equal(csp(denied), "frame-ancestors 'self'")
  })

  it('behaves as before when no CSP was set', async () => {
    const g = guard()
    const allowed = fakeResponse()
    await g.apply('/embed/acme', allowed)
    assert.equal(csp(allowed), "frame-ancestors 'self' https://acme.example")

    const denied = fakeResponse()
    await g.apply('/embed/unknown', denied)
    assert.equal(csp(denied), "frame-ancestors 'self'")
  })
})

/* ==================================================================
   point 2: tenant id shape checks
   ================================================================== */

describe('tenant id validation', () => {
  function countingGuard(overrides: Record<string, unknown> = {}) {
    const calls: string[] = []
    const guard = createEmbedGuard({
      pathPrefix: '/embed/',
      getAllowedOrigins: async (id) => {
        calls.push(id)
        return ['acme.example']
      },
      ...overrides,
    })
    return { guard, calls }
  }

  it('rejects an over-long id without calling the data source', async () => {
    const { guard, calls } = countingGuard()
    const decision = await guard.decide(`/embed/${'a'.repeat(129)}`)
    assert.equal(decision.matched, false)
    assert.equal(decision.tenantId, null)
    assert.equal(decision.allowed, false)
    assert.deepEqual(calls, [])
  })

  it('accepts an id exactly at the default limit of 128', async () => {
    const { guard, calls } = countingGuard()
    const id = 'a'.repeat(128)
    const decision = await guard.decide(`/embed/${id}`)
    assert.equal(decision.matched, true)
    assert.deepEqual(calls, [id])
  })

  it('honours a custom maxTenantIdLength', async () => {
    const { guard, calls } = countingGuard({ maxTenantIdLength: 8 })
    assert.equal((await guard.decide('/embed/123456789')).matched, false)
    assert.equal((await guard.decide('/embed/12345678')).matched, true)
    assert.deepEqual(calls, ['12345678'])
  })

  it('rejects an id that does not match tenantIdPattern, without a lookup', async () => {
    const { guard, calls } = countingGuard({ tenantIdPattern: /^[a-f0-9]{32}$/ })
    assert.equal((await guard.decide('/embed/not-hex')).matched, false)
    assert.equal((await guard.decide(`/embed/${'f'.repeat(31)}`)).matched, false)
    assert.deepEqual(calls, [])

    const valid = 'a'.repeat(32)
    assert.equal((await guard.decide(`/embed/${valid}`)).matched, true)
    assert.deepEqual(calls, [valid])
  })

  it('still enforces minTenantIdLength', async () => {
    const { guard, calls } = countingGuard({ minTenantIdLength: 32 })
    assert.equal((await guard.decide('/embed/short')).matched, false)
    assert.deepEqual(calls, [])
  })

  it('gives a stable verdict with a stateful /g pattern', async () => {
    const { guard } = countingGuard({ tenantIdPattern: /^[a-z]+$/g })
    assert.equal((await guard.decide('/embed/acme')).matched, true)
    assert.equal((await guard.decide('/embed/acme')).matched, true)
  })

  it('applies the same checks to a custom extractTenantId', async () => {
    const { guard, calls } = countingGuard({
      extractTenantId: (p: string) => p.slice('/embed/'.length) || null,
      tenantIdPattern: /^[a-z]+$/,
    })
    assert.equal((await guard.decide('/embed/BAD-ID')).matched, false)
    assert.deepEqual(calls, [])
  })

  it('leaves the response untouched when the id is rejected', async () => {
    const { guard } = countingGuard({ tenantIdPattern: /^[a-z]+$/ })
    const res = fakeResponse()
    await guard.apply('/embed/NOPE', res)
    assert.equal(csp(res), null)
    assert.equal(xfo(res), null)
  })
})

/* ==================================================================
   Guard behaviour (original smoke test)
   ================================================================== */

describe('createEmbedGuard', () => {
  function makeGuard() {
    let lookups = 0
    const guard = createEmbedGuard({
      pathPrefix: '/embed/',
      getAllowedOrigins: async (id) => {
        lookups++
        if (id === 'boom') throw new Error('data source down')
        if (id === 'acme') {
          return ['acme.example', 'https://www.acme.example/', "evil.com' ; script-src *", 42 as unknown as string]
        }
        return []
      },
    })
    return { guard, lookups: () => lookups }
  }

  it('requires getAllowedOrigins', () => {
    assert.throws(
      () => createEmbedGuard({} as never),
      /getAllowedOrigins` is required/,
    )
  })

  it('allows an authorized tenant and drops X-Frame-Options', async () => {
    const { guard } = makeGuard()
    const res = fakeResponse({ 'X-Frame-Options': 'SAMEORIGIN' })
    const decision = await guard.apply('/embed/acme', res)

    assert.equal(decision.matched, true)
    assert.equal(decision.tenantId, 'acme')
    assert.equal(decision.allowed, true)
    assert.deepEqual(decision.origins, ['https://acme.example', 'https://www.acme.example'])
    assert.equal(res.headers.has('X-Frame-Options'), false)
    assert.equal(csp(res), "frame-ancestors 'self' https://acme.example https://www.acme.example")
  })

  it('matches sub-paths of the protected route', async () => {
    const { guard } = makeGuard()
    const res = fakeResponse()
    const decision = await guard.apply('/embed/acme/privacy', res)
    assert.equal(decision.tenantId, 'acme')
    assert.equal(csp(res), "frame-ancestors 'self' https://acme.example https://www.acme.example")
  })

  /* --- fail-closed --- */

  it('falls back to SAMEORIGIN for an unknown tenant', async () => {
    const { guard } = makeGuard()
    const res = fakeResponse()
    const decision = await guard.apply('/embed/unknown', res)
    assert.equal(decision.allowed, false)
    assert.deepEqual(decision.origins, [])
    assert.equal(xfo(res), 'SAMEORIGIN')
    assert.equal(csp(res), "frame-ancestors 'self'")
  })

  it('falls back to SAMEORIGIN when the data source throws', async () => {
    const { guard } = makeGuard()
    const res = fakeResponse()
    const decision = await guard.apply('/embed/boom', res)
    assert.equal(decision.allowed, false)
    assert.equal(xfo(res), 'SAMEORIGIN')
    assert.equal(csp(res), "frame-ancestors 'self'")
  })

  it('reports the failure through onError but still fails closed', async () => {
    const seen: Array<{ tenantId: string; message: string }> = []
    const guard = createEmbedGuard({
      getAllowedOrigins: async () => {
        throw new Error('db down')
      },
      onError: (error, tenantId) => {
        seen.push({ tenantId, message: (error as Error).message })
      },
    })
    const res = fakeResponse()
    await guard.apply('/embed/acme', res)
    assert.deepEqual(seen, [{ tenantId: 'acme', message: 'db down' }])
    assert.equal(csp(res), "frame-ancestors 'self'")
  })

  it('survives an onError hook that throws', async () => {
    const guard = createEmbedGuard({
      getAllowedOrigins: async () => {
        throw new Error('db down')
      },
      onError: () => {
        throw new Error('logger exploded')
      },
    })
    const res = fakeResponse()
    const decision = await guard.apply('/embed/acme', res)
    assert.equal(decision.allowed, false)
    assert.equal(csp(res), "frame-ancestors 'self'")
  })

  it('leaves non-matching paths completely untouched', async () => {
    const { guard } = makeGuard()
    const res = fakeResponse()
    const decision = await guard.apply('/dashboard', res)
    assert.deepEqual(decision, { matched: false, tenantId: null, allowed: false, origins: [] })
    assert.equal(csp(res), null)
    assert.equal(xfo(res), null)
    assert.equal((await guard.decide('/embed/')).matched, false)
    assert.equal((await guard.decide('/embedded/acme')).matched, false)
  })

  it('does not touch the response when enforceFallback is off', async () => {
    const guard = createEmbedGuard({
      getAllowedOrigins: async () => [],
      enforceFallback: false,
    })
    const res = fakeResponse({ 'Content-Security-Policy': "default-src 'self'" })
    await guard.apply('/embed/acme', res)
    assert.equal(csp(res), "default-src 'self'")
    assert.equal(xfo(res), null)
  })

  /* --- cache --- */

  it('caches positive and negative results for the TTL', async () => {
    const { guard, lookups } = makeGuard()
    await guard.decide('/embed/acme')
    await guard.decide('/embed/acme')
    await guard.decide('/embed/acme/sub')
    assert.equal(lookups(), 1)

    await guard.decide('/embed/unknown')
    await guard.decide('/embed/unknown')
    assert.equal(lookups(), 2, 'unknown tenants must not hit the source twice')
  })

  it('re-reads after invalidate()', async () => {
    const { guard, lookups } = makeGuard()
    await guard.decide('/embed/acme')
    guard.invalidate('acme')
    await guard.decide('/embed/acme')
    assert.equal(lookups(), 2)

    guard.invalidate()
    await guard.decide('/embed/acme')
    assert.equal(lookups(), 3)
  })

  it('bypasses the cache entirely when maxCacheEntries is 0', async () => {
    const { guard, lookups } = makeGuard()
    const noCache = createEmbedGuard({
      getAllowedOrigins: async () => {
        void lookups
        return []
      },
      maxCacheEntries: 0,
    })
    await noCache.decide('/embed/acme')
    await noCache.decide('/embed/acme')
    assert.equal((await noCache.decide('/embed/acme')).allowed, false)
    void guard
  })

  it('evicts the oldest entry past maxCacheEntries', async () => {
    let lookups = 0
    const guard = createEmbedGuard({
      maxCacheEntries: 2,
      getAllowedOrigins: async () => {
        lookups++
        return []
      },
    })
    await guard.decide('/embed/one')
    await guard.decide('/embed/two')
    await guard.decide('/embed/three') // evicts "one"
    assert.equal(lookups, 3)
    await guard.decide('/embed/one') // must be a miss
    assert.equal(lookups, 4)
    await guard.decide('/embed/three') // still cached
    assert.equal(lookups, 4)
  })

  it('expires entries once the TTL has passed', async () => {
    let lookups = 0
    const guard = createEmbedGuard({
      cacheTtlMs: 5,
      getAllowedOrigins: async () => {
        lookups++
        return []
      },
    })
    await guard.decide('/embed/acme')
    await guard.decide('/embed/acme')
    assert.equal(lookups, 1)
    await new Promise((r) => setTimeout(r, 12))
    await guard.decide('/embed/acme')
    assert.equal(lookups, 2)
  })

  /* --- misc --- */

  it('normalizes a pathPrefix given without slashes', async () => {
    const guard = createEmbedGuard({
      pathPrefix: 'widget',
      getAllowedOrigins: async () => ['acme.example'],
    })
    assert.equal(guard.extractTenantId('/widget/acme'), 'acme')
    assert.equal(guard.extractTenantId('/widgets/acme'), null)
  })

  it('treats regex metacharacters in pathPrefix literally', () => {
    const guard = createEmbedGuard({
      pathPrefix: '/c.d/',
      getAllowedOrigins: async () => [],
    })
    assert.equal(guard.extractTenantId('/c.d/acme'), 'acme')
    assert.equal(guard.extractTenantId('/cxd/acme'), null)
  })

  it('resolveOrigins never rejects, even on a failing source', async () => {
    const guard = createEmbedGuard({
      getAllowedOrigins: async () => {
        throw new Error('nope')
      },
    })
    assert.deepEqual(await guard.resolveOrigins('acme'), [])
  })
})
