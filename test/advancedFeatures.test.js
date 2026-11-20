import test from 'node:test';
import assert from 'node:assert/strict';
import { defaultCollector } from '../src/lib/localCollector.js';
import { POST as postCollector, GET as getCollector } from '../src/app/api/collector/route.js';
import { GET as getDatabase } from '../src/app/api/database/route.js';
import { defaultDatabase } from '../src/lib/telemetryDatabase.js';
import { resetTenantStore } from '../src/lib/saasEngine.js';

test.beforeEach(() => {
  resetTenantStore();
  defaultCollector.reset();
});

test('1. Local Buffering + Retry: Buffers payloads during simulated outage and flushes with retry upon recovery', async () => {
  // Step 1: Activate simulated upstream outage
  defaultCollector.setOutageMode(true);
  assert.equal(defaultCollector.isOutageActive, true);

  // Step 2: Send payloads to collector while offline
  const payload1 = {
    tenantId: 'acme-corp',
    region: 'us-east-1',
    sourceAlias: 'edge-queue-test',
    userMessage: 'Test telemetry 1',
    latencyMs: 45,
  };
  const payload2 = {
    tenantId: 'acme-corp',
    region: 'us-east-1',
    sourceAlias: 'edge-queue-test',
    userMessage: 'Test telemetry 2',
    latencyMs: 50,
  };

  const res1 = defaultCollector.processUserInput(payload1);
  const res2 = defaultCollector.processUserInput(payload2);

  assert.equal(res1.status, 'accepted');
  assert.equal(res1.upstreamResult.status, 'buffered_offline');
  assert.equal(res2.upstreamResult.status, 'buffered_offline');
  assert.equal(defaultCollector.metadataBuffer.length, 2);

  // Step 3: Trigger flush with retry
  const flushResult = defaultCollector.flushBufferWithRetry(3);
  assert.equal(flushResult.success, true);
  assert.equal(flushResult.flushed, 2);
  assert.equal(flushResult.remainingBuffer, 0);
  assert.equal(defaultCollector.isOutageActive, false);
  assert.equal(defaultCollector.metadataBuffer.length, 0);
});

test('2. POST /api/collector?action=toggle_outage and flush_buffer endpoints work seamlessly', async () => {
  // Test toggle_outage endpoint
  const reqToggle = {
    url: 'http://localhost:3000/api/collector?action=toggle_outage',
    headers: { get: () => '127.0.0.1' },
    json: async () => ({ outage: true }),
  };
  const resToggle = await postCollector(reqToggle);
  assert.equal(resToggle.status, 200);
  const dataToggle = await resToggle.json();
  assert.equal(dataToggle.isOutageActive, true);

  // Send a payload through HTTP route while offline
  const reqPayload = {
    url: 'http://localhost:3000/api/collector',
    headers: { get: () => '127.0.0.1' },
    json: async () => ({
      tenantId: 'acme-corp',
      region: 'us-east-1',
      sourceAlias: 'test-device',
      metrics: { cpu: 55 },
    }),
  };
  const resPayload = await postCollector(reqPayload);
  assert.equal(resPayload.status, 201);
  const dataPayload = await resPayload.json();
  assert.equal(dataPayload.upstreamResult.status, 'buffered_offline');

  // Test flush_buffer endpoint
  const reqFlush = {
    url: 'http://localhost:3000/api/collector?action=flush_buffer',
    headers: { get: () => '127.0.0.1' },
    json: async () => ({}),
  };
  const resFlush = await postCollector(reqFlush);
  assert.equal(resFlush.status, 200);
  const dataFlush = await resFlush.json();
  assert.equal(dataFlush.success, true);
  assert.equal(dataFlush.flushed >= 1, true);
});

test('3. Idempotent Payload IDs: Blocks duplicate payload IDs deterministically with audit logging', async () => {
  const pId = 'IDEM-TEST-10099';
  const req1 = {
    url: 'http://localhost:3000/api/collector?action=test_idempotency',
    headers: { get: () => '127.0.0.1' },
    json: async () => ({
      payloadId: pId,
      tenantId: 'acme-corp',
      region: 'us-east-1',
      sourceAlias: 'financial-api',
      metrics: { transactionId: 'TX-90' },
      summary: 'Initial financial transaction',
    }),
  };

  // First submission: accepted
  const res1 = await postCollector(req1);
  assert.equal(res1.status, 201);
  const data1 = await res1.json();
  assert.equal(data1.status, 'accepted');
  assert.equal(data1.duplicate, false);

  // Second submission: exact same payloadId -> duplicate blocked!
  const req2 = {
    url: 'http://localhost:3000/api/collector?action=test_idempotency',
    headers: { get: () => '127.0.0.1' },
    json: async () => ({
      payloadId: pId,
      tenantId: 'acme-corp',
      region: 'us-east-1',
      sourceAlias: 'financial-api',
      metrics: { transactionId: 'TX-90' },
      summary: 'Duplicate financial transaction replay',
    }),
  };
  const res2 = await postCollector(req2);
  assert.equal(res2.status, 200);
  const data2 = await res2.json();
  assert.equal(data2.status, 'duplicate_blocked');
  assert.equal(data2.duplicate, true);
  assert.ok(data2.auditMessage.includes('blocked as duplicate'));
});

test('4. Failed-Login Security Summary: Tracks failed attempts, botnet IPs, and blocked SQLi signatures', () => {
  // Simulate recording failed login attempt
  defaultCollector.recordFailedLoginAttempt({
    ip: '198.51.100.44',
    endpoint: '/api/v1/auth/login',
    signature: 'UNION SELECT token FROM system_vault',
    attempts: 5,
  });

  const summary = defaultCollector.getFailedLoginSummary();
  assert.ok(summary.totalFailedAttempts >= 525);
  assert.ok(summary.blockedSignaturesCount >= 143);
  assert.ok(summary.attackerIps.some((item) => item.ip === '198.51.100.44'));
  assert.ok(summary.targetedEndpoints.includes('/api/v1/auth/login'));
  assert.equal(summary.status, 'ATTACK_MITIGATED');
});

test('5. Two-Tenant Separation: Cryptographic isolation audit confirms 0 cross-tenant data leaks', async () => {
  // Seed distinct events for both demo tenants
  defaultDatabase.insertEvent({
    payloadId: 'evt-acme-priv-1',
    tenantId: 'acme-corp',
    region: 'us-east-1',
    sourceAlias: 'acme-db',
    eventTimestampUtc: new Date().toISOString(),
    category: 'infra',
    severity: 'low',
    metrics: { cpu: 40 },
    summary: 'Acme internal database heartbeat',
  });

  defaultDatabase.insertEvent({
    payloadId: 'evt-shield-priv-1',
    tenantId: 'shield-defense',
    region: 'eu-west-1',
    sourceAlias: 'shield-grid',
    eventTimestampUtc: new Date().toISOString(),
    category: 'security',
    severity: 'medium',
    metrics: { firewallDrops: 12 },
    summary: 'CyberShield perimeter scan',
  });

  // Query audit_isolation endpoint
  const req = {
    url: 'http://localhost:3000/api/database?tenantId=acme-corp&resource=audit_isolation&opposingTenant=shield-defense',
  };
  const res = await getDatabase(req);
  assert.equal(res.status, 200);
  const audit = await res.json();

  assert.equal(audit.auditStatus, 'VERIFIED_ISOLATED');
  assert.equal(audit.crossTenantLeaksDetected, 0);
  assert.equal(audit.isZeroLeakage, true);
  assert.equal(audit.primaryTenant.tenantId, 'acme-corp');
  assert.equal(audit.opposingTenant.tenantId, 'shield-defense');
  assert.equal(audit.primaryTenant.leaksDetected, 0);
  assert.equal(audit.opposingTenant.leaksDetected, 0);
});
