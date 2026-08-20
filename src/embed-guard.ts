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

  /**
   * Reject tenant ids longer than this before hitting the data source. Caps
   * the work an attacker can push onto your lookup with a very long URL
   * segment. Default: `128`.
   */
  maxTenantIdLength?: number

  /**
   * Positive validation for the tenant id. When set, an id that does not match
   * is treated as "not an embed route" and the data source is never called —
   * so junk never reaches your database as a query parameter.
   *
   * Example for opaque hex tokens: `/^[a-f0-9]{32,64}$/`.
   *
   * Anchor the pattern (`^…$`), and prefer a non-global regex: `test()` on a
   * `/g` or `/y` pattern is stateful. (The guard resets `lastIndex` before each
   * test, so a global pattern still behaves correctly here.)
   */
  tenantIdPattern?: RegExp

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
  /** Returns `null` when the header is absent, like the DOM `Headers` API. */
  get(name: string): string | null
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
 * One DNS label: alphanumeric, hyphens allowed inside but not at either end,
 * 63 characters max. Internationalized names arrive here already punycoded by
 * `URL`, so ASCII is enough.
 */
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i

/** Bracketed IPv6 literal as `URL` reports it in `hostname`, e.g. `[::1]`. */
const IPV6_HOST = /^\[[0-9a-f:.]{2,45}\]$/i

/**
 * Positive validation of a host: an IPv6 literal, or dot-separated DNS labels
 * (which also covers IPv4 and `localhost`).
 *
 * Deliberately an allowlist, not a denylist. `URL` is permissive — it accepts
 * hosts containing characters that are legal in a URL but have no business in
 * a CSP source, and its parsing quirks differ between runtimes. Anything that
 * is not recognizably a host is rejected rather than escaped.
 *
 * Note that underscores and trailing dots are rejected too: both appear in DNS
 * but neither belongs in a browser-facing origin.
 */
function isValidHost(hostname: string): boolean {
  if (!hostname) return false
  if (hostname.startsWith('[')) {
    return IPV6_HOST.test(hostname) && hostname.includes(':')
  }
  if (hostname.length > 253) return false
  const labels = hostname.split('.')
  return labels.every((label) => DNS_LABEL.test(label))
}

/**
 * Normalize one user-supplied entry (`"example.com"`, `"https://example.com/"`)
 * into an origin string (`"https://example.com"`) that is safe to interpolate
 * into a CSP or CORS header. Returns `null` when the input contains unsafe
 * characters, is not parsable, or does not resolve to a well-formed host.
 *
 * Anti-injection: whitespace, quotes, semicolons, backslashes, CR/LF and angle
 * brackets are rejected outright — CSP separates sources with a single space,
 * so a value containing any of those could otherwise smuggle in extra
 * directives or sources.
 *
 * A bare host is upgraded to `https://`. Path, query, fragment, credentials
 * are dropped: only `scheme://host[:port]` survives. Only `http:` and `https:`
 * are accepted; the parsed host must additionally pass {@link isValidHost}.
 */
export function normalizeOrigin(input: unknown): string | null {
  if (typeof input !== 'string') return null
  const trimmed = input.trim()
  if (!trimmed) return null
  if (/[\s'";\\<>]/.test(trimmed)) return null

  // Distinguish "bare host, add https" from "explicit scheme, must be http(s)".
  // Blindly prefixing would turn `ftp://example.com` into
  // `https://ftp://example.com`, which URL happily reads as host `ftp` — a
  // silently wrong origin. A colon followed by digits is a port, not a scheme,
  // so `example.com:8443` still counts as a bare host.
  const schemeMatch = /^([a-z][a-z0-9+.-]*):/i.exec(trimmed)
  const hasScheme = schemeMatch !== null && !/^\d/.test(trimmed.slice(schemeMatch[0].length))
  if (hasScheme) {
    const scheme = (schemeMatch as RegExpExecArray)[1]!.toLowerCase()
    if (scheme !== 'http' && scheme !== 'https') return null
  }
  const withScheme = hasScheme ? trimmed : `https://${trimmed}`

  try {
    const u = new URL(withScheme)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    // Credentials in the input would be dropped silently by `u.host`; treat
    // them as malformed rather than quietly accepting a different origin.
    if (u.username || u.password) return null
    if (!isValidHost(u.hostname)) return null
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

/**
 * Splice a `frame-ancestors` directive into an existing CSP header value,
 * replacing any `frame-ancestors` already present and leaving every other
 * directive untouched, in order.
 *
 * Your app may well set its own CSP (`default-src`, `script-src`, a nonce…).
 * Overwriting the whole header to control framing would silently drop those
 * protections, so this module only ever edits the one directive it owns.
 *
 * @param existing current header value, or `null`/`''` when absent
 * @param frameAncestors the full directive, e.g. `frame-ancestors 'self'`
 */
export function mergeFrameAncestors(
  existing: string | null | undefined,
  frameAncestors: string,
): string {
  if (!existing || !existing.trim()) return frameAncestors
  const kept = existing
    .split(';')
    .map((directive) => directive.trim())
    .filter((directive) => directive.length > 0)
    .filter((directive) => {
      const name = directive.split(/\s+/)[0] ?? ''
      return name.toLowerCase() !== 'frame-ancestors'
    })
  kept.push(frameAncestors)
  return kept.join('; ')
}

/**
 * Write `frameAncestors` onto the response, keeping every other directive of
 * an already-present `Content-Security-Policy`.
 */
function setFrameAncestors(
  response: ResponseWithHeaders,
  frameAncestors: string,
): void {
  const existing = response.headers.get('Content-Security-Policy')
  response.headers.set(
    'Content-Security-Policy',
    mergeFrameAncestors(existing, frameAncestors),
  )
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
  maxTenantIdLength: 128,
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
   *   `frame-ancestors 'self' <origins...>` is spliced into the CSP.
   * - Matched and not allowed: with `enforceFallback` (default),
   *   `X-Frame-Options: SAMEORIGIN` is set and `frame-ancestors 'self'` is
   *   spliced in; otherwise nothing is touched and the app's global
   *   `SAMEORIGIN` stands.
   *
   * In both writing branches an existing `Content-Security-Policy` is
   * preserved: only its `frame-ancestors` directive is replaced (see
   * {@link mergeFrameAncestors}).
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
  const maxTenantIdLength = options.maxTenantIdLength ?? DEFAULTS.maxTenantIdLength
  const tenantIdPattern = options.tenantIdPattern
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

  /**
   * Shape checks that run BEFORE the data source is consulted: an id that is
   * too short, too long, or off-pattern is simply not an embed route. Nothing
   * is looked up, nothing is cached, and the response falls back to
   * same-origin like any other non-matching path.
   */
  function isAcceptableTenantId(tenantId: string): boolean {
    if (tenantId.length < minTenantIdLength) return false
    if (tenantId.length > maxTenantIdLength) return false
    if (tenantIdPattern) {
      // `test()` advances `lastIndex` on /g and /y patterns, which would make
      // consecutive calls with the same id disagree. Reset first.
      tenantIdPattern.lastIndex = 0
      if (!tenantIdPattern.test(tenantId)) return false
    }
    return true
  }

  function extractTenantId(pathname: string): string | null {
    if (options.extractTenantId) {
      const custom = options.extractTenantId(pathname)
      if (typeof custom !== 'string') return null
      const trimmed = custom.trim()
      return isAcceptableTenantId(trimmed) ? trimmed : null
    }
    const m = prefixPattern.exec(pathname)
    if (!m) return null
    const tenantId = m[1]
    if (!tenantId || !isAcceptableTenantId(tenantId)) return null
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
      setFrameAncestors(response, buildFrameAncestors(decision.origins))
      return decision
    }

    if (enforceFallback) {
      response.headers.set('X-Frame-Options', 'SAMEORIGIN')
      setFrameAncestors(response, SAME_ORIGIN_CSP)
    }
    return decision
  }

  function invalidate(tenantId?: string): void {
    if (typeof tenantId === 'string') cache.delete(tenantId)
    else cache.clear()
  }

  return { extractTenantId, resolveOrigins, decide, apply, invalidate }
}
