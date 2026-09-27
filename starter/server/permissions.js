// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.

import { forbidden } from './http.js';

// Starting a session needs TWO independent permissions.
export const MODE_PERMISSION = {
  view: 'device:view',
  control: 'device:control',
  terminal: 'device:terminal',
};

// ---------------------------------------------------------------------------
// Wildcard expansion
// ---------------------------------------------------------------------------
function expand(pattern, catalogue) {
  if (pattern === '*') return catalogue;

  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1);
    return catalogue.filter((key) => key.startsWith(prefix));
  }

  return catalogue.includes(pattern) ? [pattern] : [];
}

// ---------------------------------------------------------------------------
// Collect applicable grants
// ---------------------------------------------------------------------------
function collectGrants(db, { userId, orgId, deviceId, at }) {
  const common = `
    SELECT g.id AS grant_id, g.device_id, g.effect, gp.permission
      FROM grants g
      JOIN grant_permissions gp ON gp.grant_id = g.id
     WHERE g.user_id = ?
       AND g.org_id = ?
       AND g.revoked_at IS NULL
       AND (g.starts_at IS NULL OR g.starts_at <= ?)
       AND (g.expires_at IS NULL OR g.expires_at > ?)`;

  if (deviceId === null) {
    return db.prepare(common).all(userId, orgId, at, at);
  }

  return db
    .prepare(`${common} AND (g.device_id IS NULL OR g.device_id = ?)`)
    .all(userId, orgId, at, at, deviceId);
}

// ---------------------------------------------------------------------------
// Deny everything
// ---------------------------------------------------------------------------
function denyAll(catalogue, role, reason) {
  const permissions = {};

  for (const key of catalogue) {
    permissions[key] = {
      effect: 'deny',
      source: null,
      reason,
    };
  }

  return { role, permissions };
}

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------
const loadCatalogue = (db) =>
  db.prepare('SELECT key FROM permissions').all().map((r) => r.key);

const loadBaseline = (db, role) =>
  new Set(
    db
      .prepare(
        'SELECT permission FROM role_permissions WHERE role = ?'
      )
      .all(role)
      .map((r) => r.permission)
  );

const membershipOf = (db, orgId, userId) =>
  db
    .prepare(
      `SELECT role, status
         FROM memberships
        WHERE org_id = ? AND user_id = ?`
    )
    .get(orgId, userId);

// ---------------------------------------------------------------------------
// Membership gates
// ---------------------------------------------------------------------------
function gateReason(status) {
  if (status === 'suspended') return 'suspended';
  if (status !== 'active') return 'inactive_membership';
  return null;
}

// ---------------------------------------------------------------------------
// Build final permission set
//
// DENY ALWAYS WINS.
// Otherwise role baseline / allow grant can allow.
// Otherwise implicit deny.
// ---------------------------------------------------------------------------
function buildPermissions({ catalogue, role, baseline, grants }) {
  const denied = new Map();
  const allowed = new Map();

  // Explicit denies first.
  for (const row of grants) {
    if (row.effect !== 'deny') continue;

    for (const key of expand(row.permission, catalogue)) {
      if (!denied.has(key)) {
        denied.set(key, row.grant_id);
      }
    }
  }

  // Role baseline.
  for (const key of baseline) {
    allowed.set(key, `role:${role}`);
  }

  // Explicit allow grants.
  for (const row of grants) {
    if (row.effect !== 'allow') continue;

    for (const key of expand(row.permission, catalogue)) {
      if (!allowed.has(key)) {
        allowed.set(key, `grant:${row.grant_id}`);
      }
    }
  }

  const permissions = {};

  for (const key of catalogue) {
    if (denied.has(key)) {
      permissions[key] = {
        effect: 'deny',
        source: `grant:${denied.get(key)}`,
        reason: 'explicit_deny',
      };
    } else if (allowed.has(key)) {
      permissions[key] = {
        effect: 'allow',
        source: allowed.get(key),
        reason: null,
      };
    } else {
      permissions[key] = {
        effect: 'deny',
        source: null,
        reason: 'implicit',
      };
    }
  }

  return permissions;
}

// ---------------------------------------------------------------------------
// Resolve one user's permissions
// ---------------------------------------------------------------------------
export function resolve(
  db,
  { userId, orgId, deviceId = null, now = new Date() }
) {
  const at = now.toISOString();

  const catalogue = loadCatalogue(db);

  const membership = membershipOf(db, orgId, userId);

  if (!membership) {
    return denyAll(catalogue, null, 'not_a_member');
  }

  const gate = gateReason(membership.status);

  if (gate) {
    return denyAll(catalogue, membership.role, gate);
  }

  const baseline = loadBaseline(db, membership.role);

  const grants = collectGrants(db, {
    userId,
    orgId,
    deviceId,
    at,
  });

  return {
    role: membership.role,
    permissions: buildPermissions({
      catalogue,
      role: membership.role,
      baseline,
      grants,
    }),
  };
}

// ---------------------------------------------------------------------------
// Batched device resolution
// ---------------------------------------------------------------------------
export function resolveDevices(
  db,
  { userId, orgId, deviceIds, now = new Date() }
) {
  const at = now.toISOString();

  const catalogue = loadCatalogue(db);

  const membership = membershipOf(db, orgId, userId);

  const role = membership?.role ?? null;

  const gate = membership
    ? gateReason(membership.status)
    : 'not_a_member';

  if (gate) {
    const { permissions } = denyAll(
      catalogue,
      role,
      gate
    );

    const byDevice = {};

    for (const id of deviceIds) {
      byDevice[id] = permissions;
    }

    return {
      role,
      byDevice,
    };
  }

  const baseline = loadBaseline(db, role);

  const all = collectGrants(db, {
    userId,
    orgId,
    deviceId: null,
    at,
  });

  const byDevice = {};

  for (const id of deviceIds) {
    const grants = all.filter(
      (row) =>
        row.device_id === null ||
        row.device_id === id
    );

    byDevice[id] = buildPermissions({
      catalogue,
      role,
      baseline,
      grants,
    });
  }

  return {
    role,
    byDevice,
  };
}

// ---------------------------------------------------------------------------
// Simple permission check
// ---------------------------------------------------------------------------
export function can(db, ctx, permission, deviceId) {
  const { permissions } = resolve(db, {
    ...ctx,
    deviceId,
  });

  return permissions[permission]?.effect === 'allow';
}

// ---------------------------------------------------------------------------
// Assert permission
// ---------------------------------------------------------------------------
export function assertCan(db, ctx, permission, deviceId) {
  const { permissions } = resolve(db, {
    ...ctx,
    deviceId,
  });

  const entry = permissions[permission];

  if (entry?.effect === 'allow') {
    return;
  }

  const reasons = {
    explicit_deny: 'explicit_deny',
    suspended: 'suspended',
    not_a_member: 'not_a_member',
    inactive_membership: 'not_a_member',
    implicit: 'missing_permission',
  };

  throw forbidden(
    `missing permission: ${permission}`,
    reasons[entry?.reason] ?? 'missing_permission'
  );
}

// ---------------------------------------------------------------------------
// Prevent privilege laundering
// ---------------------------------------------------------------------------
export function assertMayGrant(
  db,
  ctx,
  patterns,
  deviceId = null
) {
  const { permissions } = resolve(db, {
    ...ctx,
    deviceId,
  });

  const catalogue = Object.keys(permissions);

  for (const pattern of patterns) {
    for (const key of expand(pattern, catalogue)) {
      if (permissions[key]?.effect === 'allow') {
        continue;
      }

      throw forbidden(
        `you cannot grant a permission you do not hold at this scope: ${key}`,
        permissions[key]?.reason === 'explicit_deny'
          ? 'explicit_deny'
          : 'missing_permission'
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Session start requires TWO permissions
// ---------------------------------------------------------------------------
export function assertCanStartSession(
  db,
  ctx,
  mode,
  deviceId
) {
  const modePermission = MODE_PERMISSION[mode];

  if (!modePermission) {
    throw forbidden(
      'unknown session mode',
      'validation'
    );
  }

  // First requirement.
  assertCan(
    db,
    ctx,
    'session:start',
    deviceId
  );

  // Second requirement.
  const { permissions } = resolve(db, {
    ...ctx,
    deviceId,
  });

  if (
    permissions[modePermission]?.effect !== 'allow'
  ) {
    throw forbidden(
      `${mode} sessions also require ${modePermission}`,
      'missing_device_permission'
    );
  }
}