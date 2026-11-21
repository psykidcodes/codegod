import test from 'node:test';
import assert from 'node:assert/strict';
import { defaultCollector } from '../src/lib/localCollector.js';
import { POST as postCollector, GET as getCollector } from '../src/app/api/collector/route.js';
import { GET as getDatabase } from '../src/app/api/database/route.js';
import { POST as postSimulate } from '../src/app/api/simulate/route.js';
import { GET as getAiops } from '../src/app/api/aiops/route.js';
import { POST as postAuth, GET as getAuth } from '../src/app/api/auth/route.js';
import { createSessionToken, verifySessionToken } from '../src/lib/auth.js';
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

test('6. Health Condition Updating: Accurately degrades to CRITICAL during attacks and restores immediately to HEALTHY on baseline', async () => {
  const tenantId = 'tenant-health-cycle-test';

  // Step 1: Simulate critical attack (data_leaks)
  const reqAttack = {
    json: async () => ({ scenario: 'data_leaks', tenantId }),
  };
  const resAttack = await postSimulate(reqAttack);
  assert.equal(resAttack.status, 200);
  const dataAttack = await resAttack.json();

  assert.ok(dataAttack.aiopsReport);
  assert.equal(dataAttack.aiopsReport.healthStatus, 'CRITICAL');
  assert.ok(dataAttack.aiopsReport.healthScore < 50);

  // Step 2: Simulate baseline immediately after on the same tenant
  const reqBaseline = {
    json: async () => ({ scenario: 'baseline', tenantId }),
  };
  const resBaseline = await postSimulate(reqBaseline);
  assert.equal(resBaseline.status, 200);
  const dataBaseline = await resBaseline.json();

  assert.ok(dataBaseline.aiopsReport);
  assert.equal(dataBaseline.aiopsReport.healthStatus, 'HEALTHY');
  assert.ok(dataBaseline.aiopsReport.healthScore >= 85);

  // Step 3: Query GET /api/aiops to ensure subsequent queries also return HEALTHY condition
  const reqAiops = {
    url: `http://localhost:3000/api/aiops?tenantId=${tenantId}`,
  };
  const resAiops = await getAiops(reqAiops);
  assert.equal(resAiops.status, 200);
  const dataAiops = await resAiops.json();

  assert.equal(dataAiops.healthStatus, 'HEALTHY');
  assert.ok(dataAiops.healthScore >= 85);
});

test('7. Software Host Privilege: host@arcops.io and host@cicada.io receive isHost=true while regular tenants receive isHost=false', async () => {
  // Test ArcOps Host sign in
  const reqArcOpsHost = {
    url: 'http://localhost:3000/api/auth?action=signin',
    json: async () => ({ identifier: 'host@arcops.io', password: 'Password123!' }),
  };
  const resArcOpsHost = await postAuth(reqArcOpsHost);
  assert.equal(resArcOpsHost.status, 200);
  const dataArcOpsHost = await resArcOpsHost.json();

  assert.equal(dataArcOpsHost.status, 'authenticated');
  assert.equal(dataArcOpsHost.user.isHost, true);
  assert.equal(dataArcOpsHost.user.role, 'host');
  assert.equal(dataArcOpsHost.tenant.tenantId, 'arcops-host');

  // Verify ArcOps host session token
  const arcOpsSession = verifySessionToken(dataArcOpsHost.token);
  assert.equal(arcOpsSession.isHost, true);
  assert.equal(arcOpsSession.role, 'host');

  // Test Legacy Host sign in (compatibility)
  const reqHost = {
    url: 'http://localhost:3000/api/auth?action=signin',
    json: async () => ({ identifier: 'host@cicada.io', password: 'Password123!' }),
  };
  const resHost = await postAuth(reqHost);
  assert.equal(resHost.status, 200);
  const dataHost = await resHost.json();

  assert.equal(dataHost.status, 'authenticated');
  assert.equal(dataHost.user.isHost, true);
  assert.equal(dataHost.user.role, 'host');
  assert.equal(dataHost.tenant.tenantId, 'cicada-host');

  // Verify host session token
  const hostSession = verifySessionToken(dataHost.token);
  assert.equal(hostSession.isHost, true);
  assert.equal(hostSession.role, 'host');

  // Test Regular Tenant sign in (Acme Corp)
  const reqTenant = {
    url: 'http://localhost:3000/api/auth?action=signin',
    json: async () => ({ identifier: 'admin@acme.com', password: 'Password123!' }),
  };
  const resTenant = await postAuth(reqTenant);
  assert.equal(resTenant.status, 200);
  const dataTenant = await resTenant.json();

  assert.equal(dataTenant.status, 'authenticated');
  assert.equal(dataTenant.user.isHost, false);
  assert.equal(dataTenant.user.role, 'tenant');
  assert.equal(dataTenant.tenant.tenantId, 'acme-corp');

  // Verify tenant session token
  const tenantSession = verifySessionToken(dataTenant.token);
  assert.equal(tenantSession.isHost, false);
  assert.equal(tenantSession.role, 'tenant');

  // Test GET /api/auth?action=me with host token
  const reqMeHost = {
    headers: { get: (name) => name.toLowerCase() === 'authorization' ? `Bearer ${dataHost.token}` : null },
  };
  const resMeHost = await getAuth(reqMeHost);
  const dataMeHost = await resMeHost.json();
  assert.equal(dataMeHost.authenticated, true);
  assert.equal(dataMeHost.user.isHost, true);

  // Test GET /api/auth?action=me with tenant token
  const reqMeTenant = {
    headers: { get: (name) => name.toLowerCase() === 'authorization' ? `Bearer ${dataTenant.token}` : null },
  };
  const resMeTenant = await getAuth(reqMeTenant);
  const dataMeTenant = await resMeTenant.json();
  assert.equal(dataMeTenant.authenticated, true);
  assert.equal(dataMeTenant.user.isHost, false);
});
