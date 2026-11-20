import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ALLOW_LISTED_KEYS,
  VALID_CATEGORIES,
  VALID_SEVERITIES,
  tenantStore,
  resetTenantStore,
  ingestSingle,
  ingestBatch,
  queryTenant,
  TenantIsolationError,
} from '../src/lib/saasEngine.js';

test.beforeEach(() => {
  resetTenantStore();
});

test('1. Enums and Allow-listed keys are properly exported', () => {
  assert.deepEqual(
    [...ALLOW_LISTED_KEYS],
    ['payloadId', 'tenantId', 'region', 'sourceAlias', 'eventTimestampUtc', 'category', 'severity', 'metrics', 'summary']
  );
  assert.deepEqual([...VALID_CATEGORIES], ['infra', 'network', 'security', 'collector']);
  assert.deepEqual([...VALID_SEVERITIES], ['low', 'medium', 'high', 'critical']);
});

test('2. Allow-list firewall strips unknown keys, records exact stripped keys in auditLog, increments fieldsStrippedCount', () => {
  const payload = {
    payloadId: 'payload-001',
    tenantId: 'tenant-acme',
    region: 'us-east-1',
    sourceAlias: 'edge-collector-1',
    eventTimestampUtc: '2026-11-20T10:00:00Z',
    category: 'infra',
    severity: 'high',
    unknownField1: 'should-be-stripped',
    internalSecret: 'sensitive-token',
  };

  const res = ingestSingle(payload);
  assert.equal(res.status, 'accepted');
  assert.equal(res.record.unknownField1, undefined);
  assert.equal(res.record.internalSecret, undefined);
  assert.equal(res.record.payloadId, 'payload-001');

  const tenantData = queryTenant('tenant-acme');
  assert.equal(tenantData.stats.fieldsStrippedCount, 2);
  assert.equal(tenantData.stats.totalIngested, 1);

  const strippedAudit = tenantData.auditLog.find((entry) => entry.action === 'FIELDS_STRIPPED');
  assert.ok(strippedAudit);
  assert.deepEqual(strippedAudit.strippedKeys.sort(), ['internalSecret', 'unknownField1']);
});

test('3. Schema validation rejects missing required fields and invalid enums/timestamps', () => {
  // Missing required fields
  const missingFieldsPayload = {
    tenantId: 'tenant-test',
    category: 'infra',
  };
  const res1 = ingestSingle(missingFieldsPayload);
  assert.equal(res1.status, 'rejected');
  assert.ok(res1.errors.length > 0);

  const tenantData = queryTenant('tenant-test');
  assert.equal(tenantData.stats.rejectedCount, 1);
  const rejectAudit = tenantData.auditLog.find((entry) => entry.action === 'VALIDATION_REJECTED');
  assert.ok(rejectAudit);

  // Invalid ISO-8601 UTC format (non-UTC offset)
  const invalidTimePayload = {
    payloadId: 'payload-bad-time',
    tenantId: 'tenant-test',
    region: 'us-west-2',
    sourceAlias: 'collector-x',
    eventTimestampUtc: '2026-11-20 10:00:00', // Missing T and Z
    category: 'infra',
    severity: 'medium',
  };
  const res2 = ingestSingle(invalidTimePayload);
  assert.equal(res2.status, 'rejected');
  assert.ok(res2.errors.some((e) => e.includes('eventTimestampUtc')));

  // Invalid category & severity
  const invalidEnumsPayload = {
    payloadId: 'payload-bad-enum',
    tenantId: 'tenant-test',
    region: 'us-west-2',
    sourceAlias: 'collector-x',
    eventTimestampUtc: '2026-11-20T10:00:00Z',
    category: 'invalid-cat',
    severity: 'extreme',
  };
  const res3 = ingestSingle(invalidEnumsPayload);
  assert.equal(res3.status, 'rejected');
  assert.ok(res3.errors.some((e) => e.includes('category')));
  assert.ok(res3.errors.some((e) => e.includes('severity')));
});

test('4. Strict Idempotency via seenPayloadIds blocks duplicate payloads and logs DUPLICATE_BLOCKED', () => {
  const payload = {
    payloadId: 'payload-uniq-99',
    tenantId: 'tenant-alpha',
    region: 'eu-west-1',
    sourceAlias: 'sensor-9',
    eventTimestampUtc: '2026-11-20T12:00:00Z',
    category: 'security',
    severity: 'critical',
  };

  const res1 = ingestSingle(payload);
  assert.equal(res1.status, 'accepted');

  const res2 = ingestSingle(payload);
  assert.deepEqual(res2, {
    status: 'duplicate',
    payloadId: 'payload-uniq-99',
  });

  const tenantData = queryTenant('tenant-alpha');
  assert.equal(tenantData.stats.totalIngested, 1);
  assert.equal(tenantData.stats.duplicatesBlocked, 1);

  const duplicateAudit = tenantData.auditLog.find((entry) => entry.action === 'DUPLICATE_BLOCKED');
  assert.ok(duplicateAudit);
  assert.equal(duplicateAudit.payloadId, 'payload-uniq-99');
});

test('5. Out-of-order UTC timeline healing maintains chronological ascending order and logs OUT_OF_ORDER_HEALED', () => {
  const eventT2 = {
    payloadId: 'p-t2',
    tenantId: 'tenant-healing',
    region: 'ap-south-1',
    sourceAlias: 'agent-1',
    eventTimestampUtc: '2026-11-20T14:00:00Z',
    category: 'network',
    severity: 'low',
  };

  const eventT3 = {
    payloadId: 'p-t3',
    tenantId: 'tenant-healing',
    region: 'ap-south-1',
    sourceAlias: 'agent-1',
    eventTimestampUtc: '2026-11-20T15:00:00Z',
    category: 'network',
    severity: 'low',
  };

  const eventT1Delayed = {
    payloadId: 'p-t1',
    tenantId: 'tenant-healing',
    region: 'ap-south-1',
    sourceAlias: 'agent-1',
    eventTimestampUtc: '2026-11-20T13:00:00Z', // Arrives after T3!
    category: 'network',
    severity: 'low',
  };

  ingestSingle(eventT2);
  ingestSingle(eventT3);
  const resDelayed = ingestSingle(eventT1Delayed);

  assert.equal(resDelayed.status, 'accepted');
  assert.equal(resDelayed.isOutOfOrder, true);

  const tenantData = queryTenant('tenant-healing');
  assert.equal(tenantData.stats.outOfOrderCorrected, 1);
  assert.equal(tenantData.stats.totalIngested, 3);

  // Chronological ascending check
  assert.deepEqual(
    tenantData.events.map((e) => e.payloadId),
    ['p-t1', 'p-t2', 'p-t3']
  );

  const healedAudit = tenantData.auditLog.find((entry) => entry.action === 'OUT_OF_ORDER_HEALED');
  assert.ok(healedAudit);
  assert.equal(healedAudit.payloadId, 'p-t1');
});

test('6. Ring buffer maintains maximum of 50 audit entries per tenant', () => {
  const tenantId = 'tenant-ring-buffer';

  for (let i = 0; i < 60; i++) {
    ingestSingle({
      payloadId: `payload-${i}`,
      tenantId,
      region: 'us-west-1',
      sourceAlias: 'generator',
      eventTimestampUtc: `2026-11-20T10:${String(i).padStart(2, '0')}:00Z`,
      category: 'collector',
      severity: 'low',
    });
  }

  const tenantData = queryTenant(tenantId);
  assert.equal(tenantData.auditLog.length, 50);
  assert.equal(tenantData.stats.totalIngested, 60);
});

test('7. ingestBatch processes buffered outage-recovery payloads and returns summary metrics', () => {
  const batch = [
    // Valid 1
    {
      payloadId: 'batch-p1',
      tenantId: 'tenant-batch',
      region: 'us-east-1',
      sourceAlias: 'agent-1',
      eventTimestampUtc: '2026-11-20T16:00:00Z',
      category: 'infra',
      severity: 'medium',
      extraField: 'to-strip',
    },
    // Duplicate of 1
    {
      payloadId: 'batch-p1',
      tenantId: 'tenant-batch',
      region: 'us-east-1',
      sourceAlias: 'agent-1',
      eventTimestampUtc: '2026-11-20T16:00:00Z',
      category: 'infra',
      severity: 'medium',
    },
    // Invalid (malformed category)
    {
      payloadId: 'batch-p2',
      tenantId: 'tenant-batch',
      region: 'us-east-1',
      sourceAlias: 'agent-1',
      eventTimestampUtc: '2026-11-20T16:05:00Z',
      category: 'not-real',
      severity: 'low',
    },
    // Valid 2 (out of order, earlier timestamp)
    {
      payloadId: 'batch-p3',
      tenantId: 'tenant-batch',
      region: 'us-east-1',
      sourceAlias: 'agent-1',
      eventTimestampUtc: '2026-11-20T15:30:00Z',
      category: 'security',
      severity: 'high',
    },
  ];

  const summary = ingestBatch(batch);
  assert.deepEqual(summary, {
    accepted: 2,
    duplicates: 1,
    rejected: 1,
    strippedFields: 1,
    outOfOrderHealed: 1,
  });
});

test('8. queryTenant enforces isolation error on missing/empty tenantId, and supports region filter & isStale', () => {
  // Empty / missing tenantId isolation check
  assert.throws(
    () => queryTenant(''),
    TenantIsolationError
  );
  assert.throws(
    () => queryTenant(null),
    TenantIsolationError
  );
  assert.throws(
    () => queryTenant('   '),
    TenantIsolationError
  );

  // Cross-tenant isolation
  ingestSingle({
    payloadId: 'tenant-a-event',
    tenantId: 'tenant-A',
    region: 'us-east-1',
    sourceAlias: 'host-1',
    eventTimestampUtc: '2026-11-20T17:00:00Z',
    category: 'infra',
    severity: 'low',
  });

  ingestSingle({
    payloadId: 'tenant-b-event',
    tenantId: 'tenant-B',
    region: 'eu-west-1',
    sourceAlias: 'host-2',
    eventTimestampUtc: '2026-11-20T17:00:00Z',
    category: 'network',
    severity: 'high',
  });

  const tenantAData = queryTenant('tenant-A');
  const tenantBData = queryTenant('tenant-B');

  assert.equal(tenantAData.events.length, 1);
  assert.equal(tenantAData.events[0].payloadId, 'tenant-a-event');
  assert.equal(tenantBData.events.length, 1);
  assert.equal(tenantBData.events[0].payloadId, 'tenant-b-event');

  // Region filtering
  ingestSingle({
    payloadId: 'tenant-a-event-west',
    tenantId: 'tenant-A',
    region: 'us-west-2',
    sourceAlias: 'host-3',
    eventTimestampUtc: '2026-11-20T17:10:00Z',
    category: 'infra',
    severity: 'low',
  });

  const filteredEast = queryTenant('tenant-A', 'us-east-1');
  assert.equal(filteredEast.events.length, 1);
  assert.equal(filteredEast.events[0].region, 'us-east-1');

  const filteredWest = queryTenant('tenant-A', 'us-west-2');
  assert.equal(filteredWest.events.length, 1);
  assert.equal(filteredWest.events[0].region, 'us-west-2');

  // Staleness check
  assert.equal(tenantAData.isStale, false); // Just ingested now (<30s)

  // Empty tenant partition staleness
  const freshTenant = queryTenant('brand-new-tenant');
  assert.equal(freshTenant.isStale, true); // lastSeenUtc is null
  assert.equal(freshTenant.events.length, 0);
});
