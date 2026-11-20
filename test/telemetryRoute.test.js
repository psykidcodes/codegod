import test from 'node:test';
import assert from 'node:assert/strict';
import { GET } from '../src/app/api/telemetry/route.js';
import {
  resetTenantStore,
  ingestSingle,
  tenantStore,
  getOrCreateTenantPartition,
} from '../src/lib/saasEngine.js';

test.beforeEach(() => {
  resetTenantStore();
});

function createMockGetRequest(url) {
  return {
    url,
  };
}

test('1. Missing or blank tenantId returns 400 with exact isolation error message', async () => {
  // No tenantId param
  const req1 = createMockGetRequest('http://localhost:3000/api/telemetry');
  const res1 = await GET(req1);
  assert.equal(res1.status, 400);
  const json1 = await res1.json();
  assert.deepEqual(json1, {
    error: 'tenantId query parameter is required for strict tenant isolation',
  });

  // Empty tenantId param
  const req2 = createMockGetRequest('http://localhost:3000/api/telemetry?tenantId=');
  const res2 = await GET(req2);
  assert.equal(res2.status, 400);
  const json2 = await res2.json();
  assert.deepEqual(json2, {
    error: 'tenantId query parameter is required for strict tenant isolation',
  });

  // Whitespace-only tenantId param
  const req3 = createMockGetRequest('http://localhost:3000/api/telemetry?tenantId=%20%20');
  const res3 = await GET(req3);
  assert.equal(res3.status, 400);
  const json3 = await res3.json();
  assert.deepEqual(json3, {
    error: 'tenantId query parameter is required for strict tenant isolation',
  });
});

test('2. Strict tenant isolation ensures partitions are completely segregated', async () => {
  ingestSingle({
    payloadId: 'payload-tenant-1',
    tenantId: 'tenant-omega',
    region: 'us-east-1',
    sourceAlias: 'alpha-node',
    eventTimestampUtc: '2026-11-20T10:00:00Z',
    category: 'infra',
    severity: 'high',
  });

  ingestSingle({
    payloadId: 'payload-tenant-2',
    tenantId: 'tenant-sigma',
    region: 'eu-west-1',
    sourceAlias: 'beta-node',
    eventTimestampUtc: '2026-11-20T10:05:00Z',
    category: 'security',
    severity: 'critical',
  });

  // Query tenant-omega
  const reqOmega = createMockGetRequest('http://localhost:3000/api/telemetry?tenantId=tenant-omega');
  const resOmega = await GET(reqOmega);
  assert.equal(resOmega.status, 200);
  const dataOmega = await resOmega.json();
  assert.equal(dataOmega.tenantId, 'tenant-omega');
  assert.equal(dataOmega.region, 'all');
  assert.equal(dataOmega.events.length, 1);
  assert.equal(dataOmega.events[0].payloadId, 'payload-tenant-1');
  assert.equal(dataOmega.stats.totalIngested, 1);

  // Query tenant-sigma
  const reqSigma = createMockGetRequest('http://localhost:3000/api/telemetry?tenantId=tenant-sigma');
  const resSigma = await GET(reqSigma);
  assert.equal(resSigma.status, 200);
  const dataSigma = await resSigma.json();
  assert.equal(dataSigma.tenantId, 'tenant-sigma');
  assert.equal(dataSigma.region, 'all');
  assert.equal(dataSigma.events.length, 1);
  assert.equal(dataSigma.events[0].payloadId, 'payload-tenant-2');
  assert.equal(dataSigma.stats.totalIngested, 1);
});

test('3. Region filtering filters events and sets region in response', async () => {
  const tenantId = 'tenant-multi-region';
  ingestSingle({
    payloadId: 'p-us-east',
    tenantId,
    region: 'us-east-1',
    sourceAlias: 'sensor-1',
    eventTimestampUtc: '2026-11-20T11:00:00Z',
    category: 'infra',
    severity: 'low',
  });

  ingestSingle({
    payloadId: 'p-us-west',
    tenantId,
    region: 'us-west-2',
    sourceAlias: 'sensor-2',
    eventTimestampUtc: '2026-11-20T11:01:00Z',
    category: 'network',
    severity: 'medium',
  });

  // Query specific region us-east-1
  const reqEast = createMockGetRequest(
    `http://localhost:3000/api/telemetry?tenantId=${tenantId}&region=us-east-1`
  );
  const resEast = await GET(reqEast);
  assert.equal(resEast.status, 200);
  const dataEast = await resEast.json();
  assert.equal(dataEast.region, 'us-east-1');
  assert.equal(dataEast.events.length, 1);
  assert.equal(dataEast.events[0].payloadId, 'p-us-east');

  // Query with region omitted defaults to 'all'
  const reqAll = createMockGetRequest(
    `http://localhost:3000/api/telemetry?tenantId=${tenantId}`
  );
  const resAll = await GET(reqAll);
  assert.equal(resAll.status, 200);
  const dataAll = await resAll.json();
  assert.equal(dataAll.region, 'all');
  assert.equal(dataAll.events.length, 2);
});

test('4. Severity and category filtering filters events accurately', async () => {
  const tenantId = 'tenant-filters';

  ingestSingle({
    payloadId: 'e-1',
    tenantId,
    region: 'us-east-1',
    sourceAlias: 'edge',
    eventTimestampUtc: '2026-11-20T12:00:00Z',
    category: 'infra',
    severity: 'low',
  });

  ingestSingle({
    payloadId: 'e-2',
    tenantId,
    region: 'us-east-1',
    sourceAlias: 'edge',
    eventTimestampUtc: '2026-11-20T12:01:00Z',
    category: 'security',
    severity: 'critical',
  });

  ingestSingle({
    payloadId: 'e-3',
    tenantId,
    region: 'us-east-1',
    sourceAlias: 'edge',
    eventTimestampUtc: '2026-11-20T12:02:00Z',
    category: 'security',
    severity: 'low',
  });

  // Filter by category=security
  const reqCat = createMockGetRequest(
    `http://localhost:3000/api/telemetry?tenantId=${tenantId}&category=security`
  );
  const resCat = await GET(reqCat);
  const dataCat = await resCat.json();
  assert.equal(dataCat.events.length, 2);
  assert.ok(dataCat.events.every((e) => e.category === 'security'));

  // Filter by severity=critical
  const reqSev = createMockGetRequest(
    `http://localhost:3000/api/telemetry?tenantId=${tenantId}&severity=critical`
  );
  const resSev = await GET(reqSev);
  const dataSev = await resSev.json();
  assert.equal(dataSev.events.length, 1);
  assert.equal(dataSev.events[0].payloadId, 'e-2');

  // Combined category=security & severity=low
  const reqBoth = createMockGetRequest(
    `http://localhost:3000/api/telemetry?tenantId=${tenantId}&category=security&severity=low`
  );
  const resBoth = await GET(reqBoth);
  const dataBoth = await resBoth.json();
  assert.equal(dataBoth.events.length, 1);
  assert.equal(dataBoth.events[0].payloadId, 'e-3');

  // Confirm no health score or health status fields exist
  assert.equal(dataBoth.healthScore, undefined);
  assert.equal(dataBoth.healthStatus, undefined);
});

test('5. isStale detection flags unvisited partitions and stale heartbeats (>30s)', async () => {
  // Brand new tenant without any events -> isStale: true
  const reqNew = createMockGetRequest('http://localhost:3000/api/telemetry?tenantId=tenant-unseen');
  const resNew = await GET(reqNew);
  const dataNew = await resNew.json();
  assert.equal(dataNew.isStale, true);
  assert.equal(dataNew.stats.lastSeenUtc, null);

  // Active tenant ingested just now -> isStale: false
  const activeTenant = 'tenant-active';
  ingestSingle({
    payloadId: 'p-active',
    tenantId: activeTenant,
    region: 'us-east-1',
    sourceAlias: 'agent-now',
    eventTimestampUtc: '2026-11-20T13:00:00Z',
    category: 'collector',
    severity: 'low',
  });

  const reqActive = createMockGetRequest(`http://localhost:3000/api/telemetry?tenantId=${activeTenant}`);
  const resActive = await GET(reqActive);
  const dataActive = await resActive.json();
  assert.equal(dataActive.isStale, false);

  // Tenant whose lastSeenUtc is older than 30 seconds -> isStale: true
  const partition = getOrCreateTenantPartition('tenant-timed-out');
  const oldTimestamp = new Date(Date.now() - 35 * 1000).toISOString(); // 35 seconds ago
  partition.stats.lastSeenUtc = oldTimestamp;

  const reqStale = createMockGetRequest('http://localhost:3000/api/telemetry?tenantId=tenant-timed-out');
  const resStale = await GET(reqStale);
  const dataStale = await resStale.json();
  assert.equal(dataStale.isStale, true);
});
