import {
  verifyPassword,
  issueAccessToken,
  newRefreshToken,
  hashRefreshToken,
  REFRESH_TTL_SECONDS,
} from "../auth.js";

import { authenticate } from "../context.js";
import { send, badRequest, unauthenticated } from "../http.js";
import { resolve } from "../permissions.js";
import { randomUUID } from "node:crypto";

export function registerRoutes(router, deps) {
  const { db, secret } = deps;

  // ------------------------------------------------------------
  // POST /v1/auth/login
  // ------------------------------------------------------------
  router.post("/v1/auth/login", async (req, res) => {
    const body = req.body ?? {};

    const email = String(body.email ?? "")
      .trim()
      .toLowerCase();

    const password = String(body.password ?? "");
    const orgId = body.orgId ?? null;

    if (!email || !password) {
      throw badRequest("email and password are required");
    }

    const user = db
      .prepare("SELECT * FROM users WHERE lower(email) = ?")
      .get(email);

    if (!user || !verifyPassword(password, user.password_hash)) {
      throw unauthenticated("invalid credentials");
    }

    let membership;

    if (orgId) {
      membership = db
        .prepare(`
          SELECT m.*, o.name AS org_name
          FROM memberships m
          JOIN organizations o ON o.id = m.org_id
          WHERE m.user_id = ?
            AND m.org_id = ?
            AND m.status != 'removed'
            AND o.deleted_at IS NULL
        `)
        .get(user.id, orgId);
    } else {
      membership = db
        .prepare(`
          SELECT m.*, o.name AS org_name
          FROM memberships m
          JOIN organizations o ON o.id = m.org_id
          WHERE m.user_id = ?
            AND m.status != 'removed'
            AND o.deleted_at IS NULL
          ORDER BY m.created_at
          LIMIT 1
        `)
        .get(user.id);
    }

    if (!membership) {
      throw unauthenticated("not a member of this org");
    }

    // Access token
    const token = issueAccessToken(
      {
        userId: user.id,
        orgId: membership.org_id,
        role: membership.role,
        permVersion: membership.perm_version,
      },
      secret
    );

    // Refresh token
    const rawRefresh = newRefreshToken();
    const refreshHash = hashRefreshToken(rawRefresh);

    const now = new Date();
    const expires = new Date(
      now.getTime() + REFRESH_TTL_SECONDS * 1000
    ).toISOString();

    const familyId = randomUUID();

    db.prepare(`
      INSERT INTO refresh_tokens
        (id, user_id, family_id, token_hash, expires_at)
      VALUES
        (?, ?, ?, ?, ?)
    `).run(
      randomUUID(),
      user.id,
      familyId,
      refreshHash,
      expires
    );

    // IMPORTANT: return login result
    send(res, 200, {
      token,
      refreshToken: rawRefresh,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
      org: {
        id: membership.org_id,
        name: membership.org_name,
        role: membership.role,
      },
    });
  });

  // ------------------------------------------------------------
  // GET /v1/auth/me
  // ------------------------------------------------------------
  router.get("/v1/auth/me", async (req, res) => {
    const ctx = authenticate(db, secret)(req, {});

    const user = db
      .prepare("SELECT * FROM users WHERE id = ?")
      .get(ctx.userId);

    const orgs = db
      .prepare(`
        SELECT
          m.org_id AS id,
          o.name,
          m.role,
          m.status
        FROM memberships m
        JOIN organizations o ON o.id = m.org_id
        WHERE m.user_id = ?
          AND m.status != 'removed'
          AND o.deleted_at IS NULL
        ORDER BY o.name
      `)
      .all(ctx.userId);

    const permissions = resolve(db, {
      userId: ctx.userId,
      orgId: ctx.orgId,
      deviceId: null,
    });

    send(res, 200, {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },

      org: {
        id: ctx.orgId,
        role: ctx.role,
      },

      orgs,

      permissions,
    });
  });
}