/**
 * Usage with an async data source.
 *
 * `getAllowedOrigins` is just a function returning a promise, so the origins
 * can come from anywhere: SQL, an ORM, a KV store, an internal HTTP API. This
 * example uses a stand-in `db` object — replace it with your client of choice.
 *
 * Three things matter more than the storage engine:
 *
 *  1. Return `[]` for "unknown tenant" and for "embedding disabled". Never
 *     return a wildcard: `frame-ancestors *` would make the page framable by
 *     anyone, which is exactly what this module exists to prevent.
 *  2. Let errors propagate (or return `[]`). The guard catches them and falls
 *     back to same-origin — do NOT `catch` and return a permissive default.
 *  3. Bound the call with a timeout. Middleware runs on every matching
 *     request; a hanging data source must not hang the page.
 */

import { NextResponse, type NextRequest } from 'next/server'
import { createEmbedGuard } from '../src/embed-guard'

/* ------------------------------------------------------------------
   Stand-in for your data layer. Replace with a real client.
   ------------------------------------------------------------------ */

interface TenantRow {
  /** Master switch: embedding off => no origin is authorized. */
  embedEnabled: boolean
  /** Raw, user-entered values. Normalization/validation is the guard's job. */
  allowedOrigins: unknown
}

declare const db: {
  findTenantByPublicId(tenantId: string): Promise<TenantRow | null>
}

/** Reject a slow lookup instead of stalling the request. */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error('tenant lookup timed out')), ms),
    ),
  ])
}

/* ------------------------------------------------------------------
   The guard
   ------------------------------------------------------------------ */

const guard = createEmbedGuard({
  // Public ids here are long random tokens: reject anything shorter outright,
  // before it reaches the database.
  pathPrefix: '/embed/',
  minTenantIdLength: 32,

  // Revocation delay: a removed origin keeps working for at most this long on
  // an instance that already cached it.
  cacheTtlMs: 30_000,

  getAllowedOrigins: async (tenantId) => {
    const row = await withTimeout(db.findTenantByPublicId(tenantId), 1_500)
    if (!row || !row.embedEnabled) return []
    // `allowedOrigins` is untrusted, possibly malformed input: hand it over
    // as-is. Non-array values and unsafe entries are dropped by the guard.
    return Array.isArray(row.allowedOrigins) ? (row.allowedOrigins as string[]) : []
  },

  // Route failures to your observability stack; the request still fails closed.
  onError: (error, tenantId) => {
    console.error('[embed-guard] lookup failed', { tenantId, error })
  },
})

/* ------------------------------------------------------------------
   Middleware
   ------------------------------------------------------------------ */

export async function middleware(request: NextRequest) {
  const response = NextResponse.next()

  const decision = await guard.apply(request.nextUrl.pathname, response)

  if (decision.matched && !decision.allowed) {
    // Optional: the page still renders, it simply cannot be framed. Log it to
    // help tenants debug "my widget shows a blank box" tickets.
    console.warn('[embed-guard] framing denied', { tenantId: decision.tenantId })
  }

  return response
}

export const config = {
  matcher: ['/embed/:path*'],
}

/* ------------------------------------------------------------------
   Cache invalidation (optional)
   ------------------------------------------------------------------
   The TTL is the simple answer. If you want a saved change to take effect
   immediately on this instance, export the guard and call `invalidate` from
   the route that writes the settings:

     import { guard } from '@/lib/embed-guard'
     guard.invalidate(tenantId)

   In a multi-instance or serverless deployment this only clears the isolate
   that handled the write — every other instance still waits out its TTL. Size
   `cacheTtlMs` accordingly; do not treat `invalidate` as global revocation.
   ------------------------------------------------------------------ */

export { guard }
