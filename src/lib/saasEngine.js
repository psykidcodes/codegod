/**
 * @file saasEngine.js
 * @description Resilient Multi-Tenant SaaS Telemetry Engine
 * 
 * Step 1: Core Telemetry Engine
 * - Strict allow-list key firewall with audit logging
 * - Enforced category and severity enums
 * - Memory-isolated multi-tenant partitions (Map<tenantId, TenantPartition>)
 * - 50-slot ring buffer audit log for ingest lifecycle & security events
 * - Idempotent payload handling via per-tenant seenPayloadIds Set
 * - Out-of-order UTC timeline healing with ascending chronological sort
 * - Batch recovery ingestion for buffered outage recovery
 * - Tenant isolation query API with region filtering and staleness detection
 */

/**
 * Valid schema keys permitted through the ingestion firewall.
 */
export const ALLOW_LISTED_KEYS = Object.freeze([
  'payloadId',
  'tenantId',
  'region',
  'sourceAlias',
  'eventTimestampUtc',
  'category',
  'severity',
  'metrics',
  'summary',
]);

/**
 * Permitted operational category enums.
 */
export const VALID_CATEGORIES = Object.freeze([
  'infra',
  'network',
  'security',
  'collector',
]);

/**
 * Permitted severity level enums.
 */
export const VALID_SEVERITIES = Object.freeze([
  'low',
  'medium',
  'high',
  'critical',
]);

// Aliases for convenience
export const CATEGORIES = VALID_CATEGORIES;
export const SEVERITIES = VALID_SEVERITIES;

export const MAX_AUDIT_LOG_SIZE = 50;
export const STALENESS_THRESHOLD_MS = 30 * 1000; // 30 seconds

/**
 * Isolated multi-tenant in-memory partition store.
 * Key: tenantId (string)
 * Value: {
 *   events: Array<object>,
 *   seenPayloadIds: Set<string>,
 *   auditLog: Array<object>,
 *   stats: {
 *     totalIngested: number,
 *     duplicatesBlocked: number,
 *     fieldsStrippedCount: number,
 *     outOfOrderCorrected: number,
 *     rejectedCount: number,
 *     lastSeenUtc: string | null
 *   }
 * }
 */
export const tenantStore = new Map();

/**
 * Custom error thrown when tenant isolation is breached or tenantId is missing.
 */
export class TenantIsolationError extends Error {
  constructor(message = 'Tenant isolation error: tenantId is required and cannot be empty') {
    super(message);
    this.name = 'TenantIsolationError';
  }
}

/**
 * Internal helper to validate ISO-8601 UTC timestamp format and calendar validity.
 * Accepts formats such as:
 * - 2026-11-20T14:25:29Z
 * - 2026-11-20T14:25:29.123Z
 * - 2026-11-20T14:25:29+00:00
 * - 2026-11-20T14:25:29-00:00
 * 
 * @param {any} dateStr
 * @returns {boolean}
 */
export function isValidIsoUtc(dateStr) {
  if (typeof dateStr !== 'string') return false;

  const regex = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|[+-]00(?::?00)?)$/;
  const match = dateStr.match(regex);
  if (!match) return false;

  const year = parseInt(match[1], 10);
  const month = parseInt(match[2], 10);
  const day = parseInt(match[3], 10);
  const hour = parseInt(match[4], 10);
  const minute = parseInt(match[5], 10);
  const second = parseInt(match[6], 10);

  if (month < 1 || month > 12) return false;
  if (day < 1 || day > 31) return false;
  if (hour < 0 || hour > 23) return false;
  if (minute < 0 || minute > 59) return false;
  if (second < 0 || second > 59) return false;

  const parsed = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  return (
    parsed.getUTCFullYear() === year &&
    parsed.getUTCMonth() === month - 1 &&
    parsed.getUTCDate() === day
  );
}

/**
 * Appends an entry to a tenant's ring-buffer audit log (bounded to the last 50 events).
 * 
 * @param {object} partition - Tenant partition
 * @param {('ACCEPTED'|'DUPLICATE_BLOCKED'|'FIELDS_STRIPPED'|'OUT_OF_ORDER_HEALED'|'VALIDATION_REJECTED')} action
 * @param {object} details
 * @returns {object} The appended audit log record
 */
function recordAudit(partition, action, details = {}) {
  const entry = {
    action,
    timestampUtc: new Date().toISOString(),
    ...details,
  };
  partition.auditLog.push(entry);
  if (partition.auditLog.length > MAX_AUDIT_LOG_SIZE) {
    partition.auditLog.splice(0, partition.auditLog.length - MAX_AUDIT_LOG_SIZE);
  }
  return entry;
}

/**
 * Retrieves or initializes an isolated tenant partition in tenantStore.
 * 
 * @param {string} tenantId 
 * @returns {object} The isolated tenant partition
 */
export function getOrCreateTenantPartition(tenantId) {
  if (!tenantStore.has(tenantId)) {
    tenantStore.set(tenantId, {
      events: [],
      seenPayloadIds: new Set(),
      auditLog: [],
      stats: {
        totalIngested: 0,
        duplicatesBlocked: 0,
        fieldsStrippedCount: 0,
        outOfOrderCorrected: 0,
        rejectedCount: 0,
        lastSeenUtc: null,
      },
    });
  }
  return tenantStore.get(tenantId);
}

/**
 * Ingests a single telemetry payload through allow-listing, validation, idempotency,
 * and chronological timeline healing.
 * 
 * @param {object} rawPayload 
 * @returns {object} Structured status response
 */
export function ingestSingle(rawPayload) {
  if (!rawPayload || typeof rawPayload !== 'object' || Array.isArray(rawPayload)) {
    return {
      status: 'rejected',
      errors: ['Payload must be a non-null object'],
    };
  }

  // 1. Allow-list firewall: strip any keys not in ALLOW_LISTED_KEYS
  const payloadKeys = Object.keys(rawPayload);
  const strippedKeys = payloadKeys.filter((key) => !ALLOW_LISTED_KEYS.includes(key));

  const sanitized = {};
  for (const key of ALLOW_LISTED_KEYS) {
    if (key in rawPayload) {
      sanitized[key] = rawPayload[key];
    }
  }

  // Check tenantId early to establish isolated partition if valid
  const hasTenantId =
    typeof sanitized.tenantId === 'string' && sanitized.tenantId.trim() !== '';
  const partition = hasTenantId
    ? getOrCreateTenantPartition(sanitized.tenantId.trim())
    : null;

  // Record stripped keys if any and partition is available
  if (strippedKeys.length > 0 && partition) {
    partition.stats.fieldsStrippedCount += strippedKeys.length;
    recordAudit(partition, 'FIELDS_STRIPPED', {
      payloadId: sanitized.payloadId || null,
      strippedKeys,
      count: strippedKeys.length,
    });
  }

  // 2. Validation
  const errors = [];
  const requiredFields = [
    'payloadId',
    'tenantId',
    'region',
    'sourceAlias',
    'eventTimestampUtc',
    'category',
    'severity',
  ];

  for (const field of requiredFields) {
    const val = sanitized[field];
    if (val === undefined || val === null || val === '') {
      errors.push(`Missing required field: ${field}`);
    } else if (typeof val !== 'string') {
      errors.push(`Field "${field}" must be a non-empty string`);
    } else if (val.trim() === '') {
      errors.push(`Field "${field}" cannot be blank`);
    }
  }

  // ISO-8601 UTC validation
  if (sanitized.eventTimestampUtc && typeof sanitized.eventTimestampUtc === 'string') {
    if (!isValidIsoUtc(sanitized.eventTimestampUtc)) {
      errors.push('eventTimestampUtc must be a valid ISO-8601 UTC timestamp (e.g. 2026-11-20T14:25:29Z)');
    }
  }

  // Category enum validation
  if (sanitized.category && typeof sanitized.category === 'string') {
    if (!VALID_CATEGORIES.includes(sanitized.category)) {
      errors.push(`Invalid category: "${sanitized.category}". Must be one of: ${VALID_CATEGORIES.join(', ')}`);
    }
  }

  // Severity enum validation
  if (sanitized.severity && typeof sanitized.severity === 'string') {
    if (!VALID_SEVERITIES.includes(sanitized.severity)) {
      errors.push(`Invalid severity: "${sanitized.severity}". Must be one of: ${VALID_SEVERITIES.join(', ')}`);
    }
  }

  // Reject on validation failure
  if (errors.length > 0) {
    if (partition) {
      partition.stats.rejectedCount++;
      recordAudit(partition, 'VALIDATION_REJECTED', {
        payloadId: sanitized.payloadId || null,
        errors,
      });
    }
    return {
      status: 'rejected',
      payloadId: sanitized.payloadId || null,
      tenantId: sanitized.tenantId || null,
      errors,
    };
  }

  const tenantId = sanitized.tenantId.trim();
  const payloadId = sanitized.payloadId.trim();

  // 3. Idempotency (payloadId)
  if (partition.seenPayloadIds.has(payloadId)) {
    partition.stats.duplicatesBlocked++;
    recordAudit(partition, 'DUPLICATE_BLOCKED', {
      payloadId,
    });
    return {
      status: 'duplicate',
      payloadId,
    };
  }

  // 4. Out-of-order UTC timeline healing
  const ingestedAtUtc = new Date().toISOString();
  const record = {
    ...sanitized,
    tenantId,
    payloadId,
    ingestedAtUtc,
  };

  const recordTimestamp = new Date(record.eventTimestampUtc).getTime();
  let isOutOfOrder = false;

  if (partition.events.length > 0) {
    const latestEvent = partition.events[partition.events.length - 1];
    const latestTimestamp = new Date(latestEvent.eventTimestampUtc).getTime();
    if (recordTimestamp < latestTimestamp) {
      isOutOfOrder = true;
      partition.stats.outOfOrderCorrected++;
      recordAudit(partition, 'OUT_OF_ORDER_HEALED', {
        payloadId,
        eventTimestampUtc: record.eventTimestampUtc,
        latestEventTimestampUtc: latestEvent.eventTimestampUtc,
      });
    }
  }

  // Insert sorted ascending by eventTimestampUtc
  let insertIndex = partition.events.length;
  for (let i = 0; i < partition.events.length; i++) {
    const currTimestamp = new Date(partition.events[i].eventTimestampUtc).getTime();
    if (recordTimestamp < currTimestamp) {
      insertIndex = i;
      break;
    }
  }
  partition.events.splice(insertIndex, 0, record);

  // Update partition state
  partition.seenPayloadIds.add(payloadId);
  partition.stats.totalIngested++;
  partition.stats.lastSeenUtc = ingestedAtUtc;

  recordAudit(partition, 'ACCEPTED', {
    payloadId,
    eventTimestampUtc: record.eventTimestampUtc,
  });

  return {
    status: 'accepted',
    payloadId,
    tenantId,
    record,
    isOutOfOrder,
  };
}

/**
 * Ingests a batch of telemetry payloads (e.g. buffered outage-recovery payloads)
 * through `ingestSingle`.
 * 
 * @param {Array<object>} payloadArray 
 * @returns {{ accepted: number, duplicates: number, rejected: number, strippedFields: number, outOfOrderHealed: number }}
 */
export function ingestBatch(payloadArray) {
  if (!Array.isArray(payloadArray)) {
    throw new TypeError('Expected an array of payloads for ingestBatch');
  }

  const result = {
    accepted: 0,
    duplicates: 0,
    rejected: 0,
    strippedFields: 0,
    outOfOrderHealed: 0,
  };

  for (const rawPayload of payloadArray) {
    const rawTenantId =
      rawPayload &&
      typeof rawPayload === 'object' &&
      typeof rawPayload.tenantId === 'string'
        ? rawPayload.tenantId.trim()
        : null;

    const partitionBefore = rawTenantId ? tenantStore.get(rawTenantId) : null;
    const strippedBefore = partitionBefore ? partitionBefore.stats.fieldsStrippedCount : 0;
    const oooBefore = partitionBefore ? partitionBefore.stats.outOfOrderCorrected : 0;

    const res = ingestSingle(rawPayload);

    const partitionAfter = rawTenantId ? tenantStore.get(rawTenantId) : null;
    const strippedAfter = partitionAfter ? partitionAfter.stats.fieldsStrippedCount : 0;
    const oooAfter = partitionAfter ? partitionAfter.stats.outOfOrderCorrected : 0;

    const strippedDelta = strippedAfter - strippedBefore;
    const oooDelta = oooAfter - oooBefore;

    // If tenant partition existed, count the delta; if not (e.g. rejected before partition), count raw stripped keys
    if (strippedDelta > 0) {
      result.strippedFields += strippedDelta;
    } else if (!rawTenantId && rawPayload && typeof rawPayload === 'object') {
      const unpartitionedStripped = Object.keys(rawPayload).filter(
        (key) => !ALLOW_LISTED_KEYS.includes(key)
      ).length;
      result.strippedFields += unpartitionedStripped;
    }

    result.outOfOrderHealed += oooDelta;

    if (res.status === 'accepted') {
      result.accepted++;
    } else if (res.status === 'duplicate') {
      result.duplicates++;
    } else if (res.status === 'rejected') {
      result.rejected++;
    }
  }

  return result;
}

/**
 * Queries an isolated tenant partition with optional region filtering and staleness detection.
 * 
 * @param {string} tenantId 
 * @param {string|null} [region=null] 
 * @returns {{ events: Array<object>, stats: object, auditLog: Array<object>, isStale: boolean }}
 */
export function queryTenant(tenantId, region = null) {
  if (!tenantId || typeof tenantId !== 'string' || tenantId.trim() === '') {
    throw new TenantIsolationError(
      'Tenant isolation error: tenantId is required and cannot be empty'
    );
  }

  const normalizedTenantId = tenantId.trim();
  const partition = tenantStore.get(normalizedTenantId) || {
    events: [],
    seenPayloadIds: new Set(),
    auditLog: [],
    stats: {
      totalIngested: 0,
      duplicatesBlocked: 0,
      fieldsStrippedCount: 0,
      outOfOrderCorrected: 0,
      rejectedCount: 0,
      lastSeenUtc: null,
    },
  };

  // Filter events by region if specified
  let events;
  if (region !== null && region !== undefined && region !== '') {
    events = partition.events.filter((event) => event.region === region);
  } else {
    events = [...partition.events];
  }

  // Staleness check: true if lastSeenUtc is null or older than 30 seconds
  let isStale = true;
  if (partition.stats.lastSeenUtc) {
    const lastSeenTimestamp = new Date(partition.stats.lastSeenUtc).getTime();
    if (!Number.isNaN(lastSeenTimestamp)) {
      isStale = (Date.now() - lastSeenTimestamp) > STALENESS_THRESHOLD_MS;
    }
  }

  return {
    events,
    stats: { ...partition.stats },
    auditLog: [...partition.auditLog],
    isStale,
  };
}

/**
 * Resets the in-memory tenant partition store (primarily for testing and cache-clearing).
 */
export function resetTenantStore() {
  tenantStore.clear();
}

/**
 * Step 2: Built-in AIOps Query Helper
 * Executes end-to-end AIOps intelligence analysis against an isolated tenant partition.
 * 
 * @param {string} tenantId
 * @param {string|null} [region=null]
 * @returns {Promise<object>} Full AIOps intelligence report
 */
export async function queryTenantAiops(tenantId, region = null) {
  const { analyzeTenantOps } = await import('./aiopsEngine.js');
  return analyzeTenantOps(tenantId, { region });
}

export default {
  ALLOW_LISTED_KEYS,
  VALID_CATEGORIES,
  VALID_SEVERITIES,
  CATEGORIES,
  SEVERITIES,
  tenantStore,
  TenantIsolationError,
  isValidIsoUtc,
  getOrCreateTenantPartition,
  ingestSingle,
  ingestBatch,
  queryTenant,
  resetTenantStore,
  queryTenantAiops,
};
