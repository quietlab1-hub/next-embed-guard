/**
 * Minimal usage: a static allowlist, no database.
 *
 * Drop this in `middleware.ts` (or `src/middleware.ts`) of a Next.js app.
 * `/embed/acme` becomes framable by `https://acme.example` and
 * `https://www.acme.example`; every other page — and every unknown tenant —
 * stays same-origin only.
 */

import { NextResponse, type NextRequest } from 'next/server'
import { createEmbedGuard } from '../src/embed-guard'

// Bare hosts are fine: they are normalized to `https://<host>`.
const ALLOWED: Record<string, string[]> = {
  acme: ['acme.example', 'https://www.acme.example'],
  globex: ['https://globex.example:8443'],
}

const guard = createEmbedGuard({
  pathPrefix: '/embed/',
  getAllowedOrigins: async (tenantId) => ALLOWED[tenantId] ?? [],
})

export async function middleware(request: NextRequest) {
  const response = NextResponse.next()

  // Not an /embed/ path -> untouched. Unknown tenant -> SAMEORIGIN.
  await guard.apply(request.nextUrl.pathname, response)

  return response
}

export const config = {
  matcher: ['/embed/:path*'],
}
