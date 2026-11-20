import test from 'node:test';
import assert from 'node:assert/strict';
import { POST as postSimulate, GET as getSimulate } from '../src/app/api/simulate/route.js';
import { GET as getDatabase } from '../src/app/api/database/route.js';
import { defaultDatabase } from '../src/lib/telemetryDatabase.js';

test.beforeEach(() => {
  defaultDatabase.reset();
});

function createMockRequest(body) {
  return {
    async json() {
      return body;
    },
  };
}

function createMockGetRequest(url) {
  return { url };
}

test('1. POST /api/simulate runs "spikes" scenario and returns correlated incident & explainable recommendations', async () => {
  const req = createMockRequest({
    scenario: 'spikes',
    tenantId: 'tenant-api-spikes',
    region: 'us-east-1',
  });

  const res = await postSimulate(req);
  assert.equal(res.status, 200);

  const data = await res.json();
  assert.equal(data.tenantId, 'tenant-api-spikes');
  assert.equal(data.scenarioType, 'spikes');
  assert.equal(data.eventsGeneratedCount, 8);
  assert.ok(data.correlatedIncident);
  assert.ok(data.explainableRca);
  assert.ok(data.recommendations.length > 0);
});

test('2. POST /api/simulate runs "outages" scenario and returns cascading incident analysis', async () => {
  const req = createMockRequest({
    scenario: 'outages',
    tenantId: 'tenant-api-outages',
    region: 'us-west-1',
  });

  const res = await postSimulate(req);
  assert.equal(res.status, 200);

  const data = await res.json();
  assert.equal(data.scenarioType, 'outages');
  assert.equal(data.eventsGeneratedCount, 3);
  assert.ok(data.explainableRca.probableRootCause.includes('INFRA'));
});

test('3. POST /api/simulate runs "failed_logins" scenario and triggers AI attack mitigation runbooks', async () => {
  const req = createMockRequest({
    scenario: 'failed_logins',
    tenantId: 'tenant-api-security',
  });

  const res = await postSimulate(req);
  assert.equal(res.status, 200);

  const data = await res.json();
  assert.equal(data.scenarioType, 'failed_logins');
  assert.equal(data.correlatedIncident.category, 'security');
  assert.ok(data.recommendations.some((r) => r.action === 'APPLY_EDGE_RATE_LIMIT'));
});

test('4. POST /api/simulate rejects missing tenantId and invalid scenario with 400', async () => {
  // Missing tenantId
  const reqNoTenant = createMockRequest({ scenario: 'spikes' });
  const resNoTenant = await postSimulate(reqNoTenant);
  assert.equal(resNoTenant.status, 400);

  // Invalid scenario
  const reqBadScenario = createMockRequest({ scenario: 'invalid-scenario', tenantId: 'tenant-x' });
  const resBadScenario = await postSimulate(reqBadScenario);
  assert.equal(resBadScenario.status, 400);
});

test('5. GET /api/simulate retrieves simulation history and correlated incidents for tenant', async () => {
  const tenantId = 'tenant-get-sim';

  // Run a simulation first
  const reqPost = createMockRequest({ scenario: 'outages', tenantId });
  await postSimulate(reqPost);

  // Query GET
  const reqGet = createMockGetRequest(`http://localhost:3000/api/simulate?tenantId=${tenantId}`);
  const resGet = await getSimulate(reqGet);
  assert.equal(resGet.status, 200);

  const data = await resGet.json();
  assert.equal(data.tenantId, tenantId);
  assert.equal(data.incidentsCount, 1);
  assert.equal(data.incidents[0].severity, 'critical');
});

test('6. GET /api/database queries database tables with strict tenant isolation', async () => {
  const tenantId = 'tenant-db-query';

  // Run a simulation
  const reqPost = createMockRequest({ scenario: 'spikes', tenantId });
  await postSimulate(reqPost);

  // Query events resource
  const reqEvents = createMockGetRequest(`http://localhost:3000/api/database?tenantId=${tenantId}&resource=events`);
  const resEvents = await getDatabase(reqEvents);
  assert.equal(resEvents.status, 200);
  const dataEvents = await resEvents.json();
  assert.equal(dataEvents.total, 8);

  // Query incidents resource
  const reqIncidents = createMockGetRequest(`http://localhost:3000/api/database?tenantId=${tenantId}&resource=incidents`);
  const resIncidents = await getDatabase(reqIncidents);
  const dataIncidents = await resIncidents.json();
  assert.equal(dataIncidents.total, 1);

  // Query stats resource
  const reqStats = createMockGetRequest(`http://localhost:3000/api/database?tenantId=${tenantId}`);
  const resStats = await getDatabase(reqStats);
  const dataStats = await resStats.json();
  assert.equal(dataStats.stats.totalEvents, 8);
  assert.equal(dataStats.stats.totalIncidents, 1);
});
