import type { Payload } from 'payload'

import type { ReadPath, Viewer } from './index.js'

export type PayloadReadOptions = {
  collection: string
  /** Records to read one by one (e.g. a public record that refers to the canary). */
  ids?: string[]
  /** List reads with this filter (e.g. the site's records). */
  where?: Record<string, unknown>
  /** Depths to try; default 0, 1 and 2. */
  depths?: number[]
  /** Extra request fields, e.g. headers carrying the site's host for a multi-tenant site. */
  req?: Record<string, unknown>
}

/**
 * Read paths through Payload's Local API, with the viewer's own access (`overrideAccess: false`): a list read
 * and a by-id read of each record, at each depth. Add REST and GraphQL paths yourself, through your route
 * handlers, so the HTTP layer is checked too.
 */
export function payloadReadPaths(payload: Payload, o: PayloadReadOptions): ReadPath[] {
  const depths = o.depths ?? [0, 1, 2]
  const as = (viewer: Viewer) => ({ overrideAccess: false as const, user: viewer.user as never, ...(o.req ? { req: o.req as never } : {}) })
  const paths: ReadPath[] = []
  for (const depth of depths) {
    if (o.where)
      paths.push({ name: `find ${o.collection} (depth ${depth})`, read: (v) => payload.find({ collection: o.collection as never, where: o.where as never, depth, pagination: false, ...as(v) }) })
    for (const id of o.ids ?? [])
      paths.push({
        name: `findByID ${o.collection}/${id} (depth ${depth})`,
        read: (v) => payload.findByID({ collection: o.collection as never, id, depth, disableErrors: true, ...as(v) }),
      })
  }
  return paths
}
