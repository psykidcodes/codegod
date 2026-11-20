import test from 'node:test';
import assert from 'node:assert/strict';
import { GET as getAiops, POST as postAiops } from '../src/app/api/aiops/route.js';
import { GET as getTelemetry } from '../src/app/api/telemetry/route.js';
import {
  resetTenantStore,
  ingestSingle,
  getOrCreateTenantPartition,
} from '../src/lib/saasEngine.js';
import { HEALTH_STATUS } from '../src/lib/aiopsEngine.js';

test.beforeEach(() => {
  resetTenantStore();
});

function createMockGetRequest(url) {
  return {
    url,
  };
}

function createMockPostRequest({ body, isMalformedJson = false }) {
  return {
    async json() {
      if (isMalformedJson) {
        throw new SyntaxError('Invalid JSON');
      }
      return body;
    },
  };
}

test('1. GET /api/aiops rejects missing or blank tenantId with 400', async () => {
  // Missing tenantId
  const req1 = createMockGetRequest('http://localhost:3000/api/aiops');
  const res1 = await getAiops(req1);
  assert.equal(res1.status, 400);
  const json1 = await res1.json();
  assert.deepEqual(json1, {
    error: 'tenantId query parameter is required for strict tenant isolation',
  });

  // Blank tenantId
  const req2 = createMockGetRequest('http://localhost:3000/api/aiops?tenantId=%20%20');
  const res2 = await getAiops(req2);
  assert.equal(res2.status, 400);
});

test('2. GET /api/aiops returns 200 with full AIOps intelligence report for valid tenant', async () => {
  const tenantId = 'tenant-aiops-api';

  ingestSingle({
    payloadId: 'payload-api-1',
    tenantId,
    region: 'us-east-1',
    sourceAlias: 'worker-node-1',
    eventTimestampUtc: '2026-11-20T10:00:00Z',
    category: 'infra',
    severity: 'critical',
    metrics: { cpuUsage: 98, memoryUsage: 95 },
  });

  const req = createMockGetRequest(`http://localhost:3000/api/aiops?tenantId=${tenantId}`);
  const res = await getAiops(req);
  assert.equal(res.status, 200);

  const data = await res.json();
  assert.equal(data.tenantId, tenantId);
  assert.equal(data.region, 'all');
  assert.ok(typeof data.healthScore === 'number');
  assert.equal(data.healthStatus, HEALTH_STATUS.CRITICAL);
  assert.ok(data.categoryHealth.infra);
  assert.equal(data.summary.totalEventsAnalyzed, 1);
  assert.ok(data.anomalies.length > 0);
  assert.equal(data.incidents.length, 1);
  assert.ok(data.incidents[0].rca);
  assert.ok(data.recommendations.length > 0);
});

test('3. GET /api/aiops applies region filtering properly', async () => {
  const tenantId = 'tenant-region-aiops';

  ingestSingle({
    payloadId: 'p-east',
    tenantId,
    region: 'us-east-1',
    sourceAlias: 'node-east',
    eventTimestampUtc: '2026-11-20T11:00:00Z',
    category: 'infra',
    severity: 'critical',
  });

  ingestSingle({
    payloadId: 'p-west',
    tenantId,
    region: 'us-west-2',
    sourceAlias: 'node-west',
    eventTimestampUtc: '2026-11-20T11:01:00Z',
    category: 'network',
    severity: 'low',
  });

  // Query only us-west-2
  const reqWest = createMockGetRequest(`http://localhost:3000/api/aiops?tenantId=${tenantId}&region=us-west-2`);
  const resWest = await getAiops(reqWest);
  assert.equal(resWest.status, 200);

  const dataWest = await resWest.json();
  assert.equal(dataWest.region, 'us-west-2');
  assert.equal(dataWest.summary.totalEventsAnalyzed, 1);
  assert.ok(dataWest.healthScore >= 95);
  assert.equal(dataWest.healthStatus, HEALTH_STATUS.HEALTHY);
});

test('4. GET /api/aiops detects stale partition when last heartbeat is older than 30 seconds', async () => {
  const tenantId = 'tenant-stale-aiops';
  const partition = getOrCreateTenantPartition(tenantId);
  partition.stats.lastSeenUtc = new Date(Date.now() - 40 * 1000).toISOString(); // 40s ago

  const req = createMockGetRequest(`http://localhost:3000/api/aiops?tenantId=${tenantId}`);
  const res = await getAiops(req);
  assert.equal(res.status, 200);

  const data = await res.json();
  assert.equal(data.isStale, true);
});

test('5. POST /api/aiops rejects invalid JSON or missing tenantId', async () => {
  // Malformed JSON
  const reqBadJson = createMockPostRequest({ isMalformedJson: true });
  const resBadJson = await postAiops(reqBadJson);
  assert.equal(resBadJson.status, 400);

  // Missing tenantId
  const reqNoTenant = createMockPostRequest({ body: { events: [] } });
  const resNoTenant = await postAiops(reqNoTenant);
  assert.equal(resNoTenant.status, 400);
});

test('6. POST /api/aiops analyzes provided events stream on demand', async () => {
  const customEvents = [
    {
      payloadId: 'adhoc-1',
      tenantId: 'tenant-adhoc',
      region: 'eu-central-1',
      sourceAlias: 'custom-probe',
      eventTimestampUtc: '2026-11-20T12:00:00Z',
      category: 'security',
      severity: 'critical',
      metrics: { requestCount: 50000, errorRate: 0.35 },
    },
  ];

  const req = createMockPostRequest({
    body: {
      tenantId: 'tenant-adhoc',
      events: customEvents,
    },
  });

  const res = await postAiops(req);
  assert.equal(res.status, 200);

  const data = await res.json();
  assert.equal(data.tenantId, 'tenant-adhoc');
  assert.equal(data.summary.totalEventsAnalyzed, 1);
  assert.ok(data.healthScore < 50);
  assert.equal(data.healthStatus, HEALTH_STATUS.CRITICAL);
  assert.ok(data.recommendations.some((r) => r.action === 'APPLY_EDGE_RATE_LIMIT'));
});

test('7. GET /api/telemetry supports optional includeAiops=true without breaking standard query API', async () => {
  const tenantId = 'tenant-telemetry-aiops-opt';

  ingestSingle({
    payloadId: 'p-opt-1',
    tenantId,
    region: 'us-east-1',
    sourceAlias: 'srv-1',
    eventTimestampUtc: '2026-11-20T13:00:00Z',
    category: 'infra',
    severity: 'critical',
  });

  // 1. Without includeAiops: healthScore and healthStatus remain undefined (preserves Step 1 test assertions)
  const reqStandard = createMockGetRequest(`http://localhost:3000/api/telemetry?tenantId=${tenantId}`);
  const resStandard = await getTelemetry(reqStandard);
  const dataStandard = await resStandard.json();
  assert.equal(dataStandard.healthScore, undefined);
  assert.equal(dataStandard.healthStatus, undefined);

  // 2. With includeAiops=true: healthScore and healthStatus are enriched
  const reqWithAiops = createMockGetRequest(`http://localhost:3000/api/telemetry?tenantId=${tenantId}&includeAiops=true`);
  const resWithAiops = await getTelemetry(reqWithAiops);
  const dataWithAiops = await resWithAiops.json();
  assert.ok(typeof dataWithAiops.healthScore === 'number');
  assert.ok(typeof dataWithAiops.healthStatus === 'string');
  assert.ok(dataWithAiops.aiops);
});
