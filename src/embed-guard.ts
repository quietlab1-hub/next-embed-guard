/**
 * next-embed-guard — per-tenant iframe embedding for Next.js middleware.
 *
 * A single page (e.g. `/embed/<tenantId>`) must be framable only by the
 * origins that the owner of that tenant has explicitly authorized, while the
 * rest of the app stays `SAMEORIGIN`. This module computes the framing headers
 * for one request:
 *
 *   allowed origins for the tenant  ->  Content-Security-Policy:
 *                                       frame-ancestors 'self' <origins...>
 *   empty list / unknown tenant     ->  SAMEORIGIN (fail-closed)
 *   data source throws / times out  ->  SAMEORIGIN (fail-closed)
 *
 * FAIL-CLOSED IS THE WHOLE POINT. There is no code path in which an error, a
 * missing tenant, a malformed value or an unparsable origin widens the framing
 * policy. Everything that is not an explicitly authorized, successfully
 * normalized origin ends up as same-origin-only.
 *
 * Where the allowed origins come from is up to you: this module never talks to
 * a database. You inject a `getAllowedOrigins(tenantId)` function; it can read
 * from a static object, from SQL, from a KV store, from an HTTP API. Results
 * are cached in-process with a short TTL so the hot path does not hit your
 * data source on every request.
 *
 * EDGE-SAFE: only Web standards (URL, RegExp, Map, Headers) are used — no Node
 * built-ins, no framework imports — so it runs unchanged in the Next.js Edge
 * runtime, in Node, and in tests.
 */

/* ============================================================
   Public types
   ============================================================ */

/**
 * User-injected data access. Given a tenant id extracted from the URL, resolve
 * the origins allowed to frame that tenant's page.
 *
 * Accepted shapes per entry: `"example.com"`, `"https://example.com"`,
 * `"https://example.com:8443"`. Entries that cannot be safely normalized are
 * dropped (see {@link normalizeOrigin}).
 *
 * Return an empty array for "not allowed / unknown tenant". Throwing is also
 * safe: it is caught and treated as "not allowed".
 */
export type GetAllowedOrigins = (tenantId: string) => Promise<string[]>

export interface EmbedGuardOptions {
  /** Data access, injected by the caller. Required. */
  getAllowedOrigins: GetAllowedOrigins

  /**
   * Path prefix of the protected route, e.g. `/embed/` for `/embed/<tenantId>`.
   * The first path segment after the prefix is the tenant id; deeper
   * sub-paths (`/embed/<tenantId>/privacy`) are matched too.
   * Default: `'/embed/'`. Ignored when {@link extractTenantId} is provided.
   */
  pathPrefix?: string

  /**
   * Full control over route matching. Return the tenant id, or `null` when the
   * path is not a protected embed route. Overrides {@link pathPrefix}.
   */
  extractTenantId?: (pathname: string) => string | null

  /**
   * Reject tenant ids shorter than this before hitting the data source. Useful
   * when ids are long random tokens, as a cheap guard against enumeration
   * noise. Default: `1` (no practical constraint).
   */
  minTenantIdLength?: number

  /** Cache TTL for resolved origin lists, in ms. Default: `60_000`. */
  cacheTtlMs?: number

  /**
   * Max cached tenants. When exceeded, the oldest inserted entry is evicted.
   * Default: `1000`. Set to `0` to disable caching entirely.
   */
  maxCacheEntries?: number

  /**
   * When the request is NOT allowed to be embedded, explicitly write the
   * restrictive headers (`X-Frame-Options: SAMEORIGIN` and
   * `Content-Security-Policy: frame-ancestors 'self'`) instead of leaving the
   * response untouched. Default: `true`.
   *
   * Set to `false` only if your app already sends a restrictive framing header
   * globally (e.g. from `next.config.js`) and you want this module to be
   * strictly additive.
   */
  enforceFallback?: boolean

  /**
   * Optional error sink for observability. Called when
   * {@link GetAllowedOrigins} throws. Never rethrow from here — errors thrown
   * by the hook are swallowed and the request still fails closed.
   */
  onError?: (error: unknown, tenantId: string) => void
}

/** Outcome of evaluating one request. */
export interface EmbedDecision {
  /** `true` when the path matched the protected route. */
  matched: boolean
  /** Tenant id extracted from the path, `null` when not matched. */
  tenantId: string | null
  /** `true` when at least one origin is authorized to frame the page. */
  allowed: boolean
  /** Normalized origins granted framing rights (empty when not allowed). */
  origins: string[]
}

/** Minimal structural type for a mutable header bag (`Headers`, or a mock). */
export interface MutableHeaders {
  set(name: string, value: string): void
  delete(name: string): void
}

/** Minimal structural type for a response carrying headers (e.g. `NextResponse`). */
export interface ResponseWithHeaders {
  headers: MutableHeaders
}

/* ============================================================
   Origin normalization
   ============================================================ */

/**
 * Normalize one user-supplied entry (`"example.com"`, `"https://example.com/"`)
 * into an origin string (`"https://example.com"`) that is safe to interpolate
 * into a CSP or CORS header. Returns `null` when the input contains unsafe
 * characters or is not parsable.
 *
 * Anti-injection: whitespace, quotes, semicolons, backslashes, CR/LF and angle
 * brackets are rejected outright — CSP separates sources with a single space,
 * so a value containing any of those could otherwise smuggle in extra
 * directives or sources.
 *
 * A bare host is upgraded to `https://`. Path, query and fragment are dropped:
 * only `scheme://host[:port]` survives.
 */
export function normalizeOrigin(input: unknown): string | null {
  if (typeof input !== 'string') return null
  const trimmed = input.trim()
  if (!trimmed) return null
  if (/[\s'";\\<>]/.test(trimmed)) return null
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  try {
    const u = new URL(withScheme)
    // Only scheme + host[:port]; no path/query/fragment.
    return `${u.protocol}//${u.host}`
  } catch {
    return null
  }
}

/**
 * Normalize a whole list, dropping every entry that cannot be safely
 * normalized. A non-array input yields an empty list (= embedding disabled =
 * blocked by default).
 */
export function normalizeOrigins(list: unknown): string[] {
  if (!Array.isArray(list)) return []
  const seen = new Set<string>()
  for (const raw of list) {
    const origin = normalizeOrigin(raw)
    if (origin) seen.add(origin)
  }
  return Array.from(seen)
}

/* ============================================================
   Header values
   ============================================================ */

/** Restrictive framing policy: only the app itself may frame the page. */
export const SAME_ORIGIN_CSP = "frame-ancestors 'self'"

/** Build the permissive-but-scoped `frame-ancestors` value for a tenant. */
export function buildFrameAncestors(origins: string[]): string {
  return origins.length > 0
    ? `frame-ancestors 'self' ${origins.join(' ')}`
    : SAME_ORIGIN_CSP
}

/* ============================================================
   Guard
   ============================================================ */

interface CacheEntry {
  origins: string[]
  ts: number
}

const DEFAULTS = {
  pathPrefix: '/embed/',
  minTenantIdLength: 1,
  cacheTtlMs: 60_000,
  maxCacheEntries: 1000,
  enforceFallback: true,
} as const

export interface EmbedGuard {
  /** Extract the tenant id from a pathname, or `null` when not a protected route. */
  extractTenantId(pathname: string): string | null

  /**
   * Resolve the authorized origins for a tenant, through the TTL cache.
   * Never throws and never returns `null`: an error in the injected data
   * source yields `[]` (fail-closed).
   */
  resolveOrigins(tenantId: string): Promise<string[]>

  /** Evaluate a pathname without touching any response. */
  decide(pathname: string): Promise<EmbedDecision>

  /**
   * Evaluate `pathname` and write the framing headers onto `response`.
   * Returns the decision, so callers can log or branch on it.
   *
   * - Path not matched: the response is left untouched.
   * - Matched and allowed: `X-Frame-Options` is removed (it has no per-origin
   *   form and would otherwise veto the CSP in older browsers) and
   *   `Content-Security-Policy: frame-ancestors 'self' <origins...>` is set.
   * - Matched and not allowed: with `enforceFallback` (default), the
   *   restrictive pair is written explicitly; otherwise nothing is touched and
   *   the app's global `SAMEORIGIN` stands.
   */
  apply(pathname: string, response: ResponseWithHeaders): Promise<EmbedDecision>

  /** Drop cached entries — for one tenant, or all of them. */
  invalidate(tenantId?: string): void
}

/**
 * Build a guard. One instance per process; the cache lives inside it.
 *
 * ```ts
 * const guard = createEmbedGuard({
 *   pathPrefix: '/embed/',
 *   getAllowedOrigins: async (id) => ORIGINS_BY_TENANT[id] ?? [],
 * })
 * ```
 *
 * Note on caching in serverless/edge deployments: each isolate keeps its own
 * copy, so a revoked origin can survive up to `cacheTtlMs` on instances that
 * already cached it. Keep the TTL short (seconds to a minute) — that is the
 * revocation delay you are accepting.
 */
export function createEmbedGuard(options: EmbedGuardOptions): EmbedGuard {
  if (typeof options?.getAllowedOrigins !== 'function') {
    throw new TypeError('createEmbedGuard: `getAllowedOrigins` is required')
  }

  const getAllowedOrigins = options.getAllowedOrigins
  const pathPrefix = options.pathPrefix ?? DEFAULTS.pathPrefix
  const minTenantIdLength = options.minTenantIdLength ?? DEFAULTS.minTenantIdLength
  const cacheTtlMs = options.cacheTtlMs ?? DEFAULTS.cacheTtlMs
  const maxCacheEntries = options.maxCacheEntries ?? DEFAULTS.maxCacheEntries
  const enforceFallback = options.enforceFallback ?? DEFAULTS.enforceFallback
  const onError = options.onError

  // `/embed/` -> /^\/embed\/([^/]+)(?:\/|$)/ : first segment after the prefix
  // is the tenant id, sub-paths are tolerated.
  const normalizedPrefix = pathPrefix.startsWith('/') ? pathPrefix : `/${pathPrefix}`
  const withTrailingSlash = normalizedPrefix.endsWith('/')
    ? normalizedPrefix
    : `${normalizedPrefix}/`
  const prefixPattern = new RegExp(
    `^${withTrailingSlash.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^/]+)(?:/|$)`,
  )

  const cache = new Map<string, CacheEntry>()

  function extractTenantId(pathname: string): string | null {
    if (options.extractTenantId) {
      const custom = options.extractTenantId(pathname)
      if (typeof custom !== 'string') return null
      const trimmed = custom.trim()
      return trimmed.length >= minTenantIdLength ? trimmed : null
    }
    const m = prefixPattern.exec(pathname)
    if (!m) return null
    const tenantId = m[1]
    if (!tenantId || tenantId.length < minTenantIdLength) return null
    return tenantId
  }

  function readCache(tenantId: string, now: number): string[] | null {
    if (maxCacheEntries <= 0) return null
    const cached = cache.get(tenantId)
    if (!cached) return null
    if (now - cached.ts >= cacheTtlMs) {
      cache.delete(tenantId)
      return null
    }
    return cached.origins
  }

  function writeCache(tenantId: string, origins: string[], now: number): void {
    if (maxCacheEntries <= 0) return
    // Refresh insertion order so the eviction below drops the oldest entry.
    cache.delete(tenantId)
    cache.set(tenantId, { origins, ts: now })
    while (cache.size > maxCacheEntries) {
      const oldest = cache.keys().next()
      if (oldest.done) break
      cache.delete(oldest.value)
    }
  }

  async function resolveOrigins(tenantId: string): Promise<string[]> {
    const now = Date.now()
    const cached = readCache(tenantId, now)
    if (cached) return cached

    try {
      const raw = await getAllowedOrigins(tenantId)
      const origins = normalizeOrigins(raw)
      // Negative results are cached too: an unknown tenant must not hammer the
      // data source on every request.
      writeCache(tenantId, origins, now)
      return origins
    } catch (error) {
      // FAIL-CLOSED: an unreachable data source must never widen the policy.
      // Cache the empty result briefly so an outage does not amplify into a
      // request storm against an already struggling backend.
      writeCache(tenantId, [], now)
      if (onError) {
        try {
          onError(error, tenantId)
        } catch {
          /* an error in the error sink must not affect the decision */
        }
      }
      return []
    }
  }

  async function decide(pathname: string): Promise<EmbedDecision> {
    const tenantId = extractTenantId(pathname)
    if (!tenantId) {
      return { matched: false, tenantId: null, allowed: false, origins: [] }
    }
    const origins = await resolveOrigins(tenantId)
    return {
      matched: true,
      tenantId,
      allowed: origins.length > 0,
      origins,
    }
  }

  async function apply(
    pathname: string,
    response: ResponseWithHeaders,
  ): Promise<EmbedDecision> {
    const decision = await decide(pathname)
    if (!decision.matched) return decision

    if (decision.allowed) {
      // X-Frame-Options cannot express a per-origin allowlist and, where it is
      // still honored, would override the CSP. Remove it and let
      // frame-ancestors be the single source of truth for this response.
      response.headers.delete('X-Frame-Options')
      response.headers.set(
        'Content-Security-Policy',
        buildFrameAncestors(decision.origins),
      )
      return decision
    }

    if (enforceFallback) {
      response.headers.set('X-Frame-Options', 'SAMEORIGIN')
      response.headers.set('Content-Security-Policy', SAME_ORIGIN_CSP)
    }
    return decision
  }

  function invalidate(tenantId?: string): void {
    if (typeof tenantId === 'string') cache.delete(tenantId)
    else cache.clear()
  }

  return { extractTenantId, resolveOrigins, decide, apply, invalidate }
}
