import test from 'node:test';
import assert from 'node:assert/strict';
import { POST as postCollector, GET as getCollector } from '../src/app/api/collector/route.js';
import { defaultCollector } from '../src/lib/localCollector.js';
import { resetTenantStore, queryTenant } from '../src/lib/saasEngine.js';

test.beforeEach(() => {
  resetTenantStore();
  defaultCollector.reset();
});

function createMockRequest({
  body,
  ip = '10.0.0.1',
  isMalformedJson = false,
}) {
  return {
    headers: {
      get(name) {
        if (name.toLowerCase() === 'x-forwarded-for') {
          return ip;
        }
        return null;
      },
    },
    async json() {
      if (isMalformedJson) {
        throw new SyntaxError('Unexpected token in JSON');
      }
      return body;
    },
  };
}

test('1. POST /api/collector accepts valid user data, filters raw fields, and returns 201 metadata', async () => {
  const userInput = {
    tenantId: 'tenant-route-clean',
    region: 'us-east-1',
    sourceAlias: 'client-dashboard',
    userMessage: 'This is my private message content',
    rawUserData: { secretInternalNote: 'Do not leak' },
    latencyMs: 78,
    statusCode: 200,
  };

  const req = createMockRequest({ body: userInput });
  const res = await postCollector(req);
  assert.equal(res.status, 201);

  const json = await res.json();
  assert.equal(json.status, 'accepted');
  assert.ok(json.payloadId);

  // Assert RAW data is NOT present in returned metadata
  assert.equal(json.metadata.userMessage, undefined);
  assert.equal(json.metadata.rawUserData, undefined);
  assert.equal(json.metadata.metrics.latencyMs, 78);
  assert.equal(json.metadata.metrics.statusCode, 200);

  // Confirm upstream partition has it
  const tenantData = queryTenant('tenant-route-clean');
  assert.equal(tenantData.events.length, 1);
  assert.equal(tenantData.events[0].userMessage, undefined);
});

test('2. POST /api/collector neutralizes data leaks (DLP) and reports leak prevention stats', async () => {
  const leakingInput = {
    tenantId: 'tenant-route-leak',
    sourceAlias: 'user-login-form',
    userCredentials: {
      password: 'MyTopSecretPassword99',
      apiKey: 'sk-abcdef1234567890abcdef123456',
    },
  };

  const req = createMockRequest({ body: leakingInput });
  const res = await postCollector(req);
  assert.equal(res.status, 201);

  const json = await res.json();
  assert.equal(json.status, 'accepted');
  assert.ok(json.leaksPrevented >= 2);
  assert.equal(json.metadata.category, 'security');

  const metaString = JSON.stringify(json.metadata);
  assert.equal(metaString.includes('MyTopSecretPassword99'), false);
  assert.equal(metaString.includes('sk-abcdef'), false);
});

test('3. POST /api/collector blocks injection attack with 403 and records security audit', async () => {
  const attackInput = {
    tenantId: 'tenant-route-sqli',
    sourceAlias: 'malicious-agent',
    query: "SELECT * FROM secrets WHERE id = 1 OR '1'='1' --",
  };

  const req = createMockRequest({ body: attackInput });
  const res = await postCollector(req);
  assert.equal(res.status, 403);

  const json = await res.json();
  assert.equal(json.status, 'blocked');
  assert.equal(json.attackType, 'SQL_INJECTION');
  assert.ok(json.error.includes('Malicious attack signature detected'));
});

test('4. POST /api/collector returns 429 when client rate limit is exceeded', async () => {
  const ip = '192.0.2.99';

  // Rapidly consume quota (default maxRequestsPerWindow is 100)
  for (let i = 0; i < 100; i++) {
    const req = createMockRequest({ body: { tenantId: 'tenant-rl', i }, ip });
    const res = await postCollector(req);
    assert.equal(res.status, 201);
  }

  // Request 101 exceeds rate limit
  const reqBlocked = createMockRequest({ body: { tenantId: 'tenant-rl' }, ip });
  const resBlocked = await postCollector(reqBlocked);
  assert.equal(resBlocked.status, 429);

  const jsonBlocked = await resBlocked.json();
  assert.equal(jsonBlocked.status, 'blocked');
  assert.equal(jsonBlocked.attackType, 'RATE_LIMIT_EXCEEDED');
});

test('5. POST /api/collector processes batch array of inputs with summary', async () => {
  const batch = [
    {
      tenantId: 'tenant-route-batch',
      region: 'us-east-1',
      sourceAlias: 'worker-1',
      latencyMs: 30,
    },
    {
      tenantId: 'tenant-route-batch',
      region: 'us-east-1',
      sourceAlias: 'worker-2',
      latencyMs: 45,
    },
  ];

  const req = createMockRequest({ body: batch });
  const res = await postCollector(req);
  assert.equal(res.status, 200);

  const json = await res.json();
  assert.equal(json.total, 2);
  assert.equal(json.accepted, 2);
  assert.equal(json.blocked, 0);
});

test('6. GET /api/collector returns 200 with collector status and live security metrics', async () => {
  const res = await getCollector();
  assert.equal(res.status, 200);

  const json = await res.json();
  assert.equal(json.status, 'online');
  assert.equal(json.collector, 'local-edge-collector');
  assert.ok(json.stats);
  assert.ok(typeof json.stats.totalReceived === 'number');
  assert.ok(typeof json.stats.attacksBlocked === 'number');
  assert.ok(typeof json.stats.leaksPrevented === 'number');
});

test('7. POST /api/collector returns 400 on malformed JSON payload', async () => {
  const req = createMockRequest({ isMalformedJson: true });
  const res = await postCollector(req);
  assert.equal(res.status, 400);

  const json = await res.json();
  assert.equal(json.error, 'Invalid JSON payload');
});
