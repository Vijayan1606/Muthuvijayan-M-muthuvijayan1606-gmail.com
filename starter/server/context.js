// Per-request context: turn a bearer token into an authenticated caller.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    // 1. Read Bearer token
    const header = req.headers.authorization ?? '';
    const token = header.startsWith('Bearer ')
      ? header.slice(7)
      : null;

    if (!token) {
      throw unauthenticated('missing bearer token');
    }

    // 2. Verify JWT
    const claims = verifyAccessToken(token, secret);

    // 3. Find the caller's membership in the token's org
    const membership = db
      .prepare(
        `SELECT m.*, o.deleted_at AS org_deleted_at
           FROM memberships m
           JOIN organizations o ON o.id = m.org_id
          WHERE m.org_id = ? AND m.user_id = ?`
      )
      .get(claims.org, claims.sub);

    // No membership = caller is not authenticated for this org
    if (!membership) {
      throw unauthenticated('not a member of this org');
    }

    // Deleted org is invisible
    if (membership.org_deleted_at) {
      throw notFound();
    }

    // Removed membership is no longer authenticated
    if (membership.status === 'removed') {
      throw unauthenticated('membership removed');
    }

    // Suspended users are handled as authenticated but have no permissions.
    // Do NOT return TOKEN_STALE here because the expected response is 403 suspended.
    if (membership.status !== 'suspended') {
      assertFresh(claims, membership);
    }

    // 4. Structural org isolation
    // A token for org A can NEVER address org B.
    if (params.org && params.org !== claims.org) {
      throw notFound();
    }

    // 5. Return the authenticated caller context
    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      membership,
      claims,
    };
  };
}