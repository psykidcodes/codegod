import test from 'node:test';
import assert from 'node:assert/strict';
import { POST } from '../src/app/api/ingest/route.js';
import { resetTenantStore, queryTenant } from '../src/lib/saasEngine.js';

test.beforeEach(() => {
  resetTenantStore();
});

function createMockRequest({ token = 'collector-alpha-token', body, rawBody, isMalformedJson = false }) {
  return {
    headers: {
      get(name) {
        if (name.toLowerCase() === 'x-collector-token') {
          return token;
        }
        return null;
      },
    },
    async json() {
      if (isMalformedJson) {
        throw new SyntaxError('Unexpected token in JSON');
      }
      return body !== undefined ? body : JSON.parse(rawBody);
    },
  };
}

test('1. Rejects missing or unauthorized collector token with 401', async () => {
  // Missing token
  const reqNoToken = createMockRequest({ token: null, body: {} });
  const resNoToken = await POST(reqNoToken);
  assert.equal(resNoToken.status, 401);
  const jsonNoToken = await resNoToken.json();
  assert.deepEqual(jsonNoToken, { error: 'Unauthorized collector token' });

  // Invalid token
  const reqBadToken = createMockRequest({ token: 'wrong-token', body: {} });
  const resBadToken = await POST(reqBadToken);
  assert.equal(resBadToken.status, 401);
  const jsonBadToken = await resBadToken.json();
  assert.deepEqual(jsonBadToken, { error: 'Unauthorized collector token' });
});

test('2. Allows authorized tokens (collector-alpha-token & collector-beta-token)', async () => {
  const validPayload = {
    payloadId: 'p-auth-1',
    tenantId: 'tenant-1',
    region: 'us-east-1',
    sourceAlias: 'sensor',
    eventTimestampUtc: '2026-11-20T12:00:00Z',
    category: 'infra',
    severity: 'low',
  };

  const reqAlpha = createMockRequest({ token: 'collector-alpha-token', body: validPayload });
  const resAlpha = await POST(reqAlpha);
  assert.equal(resAlpha.status, 201);

  const reqBeta = createMockRequest({
    token: 'collector-beta-token',
    body: { ...validPayload, payloadId: 'p-auth-2' },
  });
  const resBeta = await POST(reqBeta);
  assert.equal(resBeta.status, 201);
});

test('3. Returns 400 when body is invalid JSON', async () => {
  const req = createMockRequest({ isMalformedJson: true });
  const res = await POST(req);
  assert.equal(res.status, 400);
  const json = await res.json();
  assert.deepEqual(json, { error: 'Invalid JSON payload' });
});

test('4. Single payload returns 201 on accept, 200 on duplicate, 400 on validation failure', async () => {
  const validPayload = {
    payloadId: 'payload-single-1',
    tenantId: 'tenant-corp',
    region: 'us-west-1',
    sourceAlias: 'edge-1',
    eventTimestampUtc: '2026-11-20T10:00:00Z',
    category: 'network',
    severity: 'medium',
  };

  // 1. Accepted -> 201
  const req1 = createMockRequest({ body: validPayload });
  const res1 = await POST(req1);
  assert.equal(res1.status, 201);
  const json1 = await res1.json();
  assert.equal(json1.status, 'accepted');
  assert.equal(json1.payloadId, 'payload-single-1');

  // 2. Duplicate -> 200
  const req2 = createMockRequest({ body: validPayload });
  const res2 = await POST(req2);
  assert.equal(res2.status, 200);
  const json2 = await res2.json();
  assert.equal(json2.status, 'duplicate');
  assert.equal(json2.payloadId, 'payload-single-1');

  // 3. Validation failure -> 400
  const invalidPayload = {
    payloadId: 'payload-single-bad',
    tenantId: 'tenant-corp',
    // Missing required fields
  };
  const req3 = createMockRequest({ body: invalidPayload });
  const res3 = await POST(req3);
  assert.equal(res3.status, 400);
  const json3 = await res3.json();
  assert.equal(json3.status, 'rejected');
  assert.ok(json3.errors.length > 0);
});

test('5. Batch payloads via Array return 200 with batch summary', async () => {
  const batchArray = [
    {
      payloadId: 'batch-arr-1',
      tenantId: 'tenant-batch',
      region: 'us-east-1',
      sourceAlias: 'collector-1',
      eventTimestampUtc: '2026-11-20T11:00:00Z',
      category: 'infra',
      severity: 'low',
    },
    {
      payloadId: 'batch-arr-1', // duplicate
      tenantId: 'tenant-batch',
      region: 'us-east-1',
      sourceAlias: 'collector-1',
      eventTimestampUtc: '2026-11-20T11:00:00Z',
      category: 'infra',
      severity: 'low',
    },
    {
      payloadId: 'batch-arr-2',
      tenantId: 'tenant-batch',
      region: 'us-east-1',
      sourceAlias: 'collector-1',
      eventTimestampUtc: '2026-11-20T10:30:00Z', // out of order
      category: 'security',
      severity: 'high',
      unknownField: 'stripped',
    },
  ];

  const req = createMockRequest({ body: batchArray });
  const res = await POST(req);
  assert.equal(res.status, 200);
  const json = await res.json();
  assert.deepEqual(json, {
    accepted: 2,
    duplicates: 1,
    rejected: 0,
    strippedFields: 1,
    outOfOrderHealed: 1,
  });
});

test('6. Batch payloads via { batch: [...] } return 200 with batch summary', async () => {
  const batchObj = {
    batch: [
      {
        payloadId: 'batch-obj-1',
        tenantId: 'tenant-batch-obj',
        region: 'eu-central-1',
        sourceAlias: 'probe',
        eventTimestampUtc: '2026-11-20T15:00:00Z',
        category: 'collector',
        severity: 'critical',
      },
      {
        payloadId: 'batch-obj-invalid',
        tenantId: 'tenant-batch-obj',
        // Missing fields -> rejected
      },
    ],
  };

  const req = createMockRequest({ body: batchObj });
  const res = await POST(req);
  assert.equal(res.status, 200);
  const json = await res.json();
  assert.deepEqual(json, {
    accepted: 1,
    duplicates: 0,
    rejected: 1,
    strippedFields: 0,
    outOfOrderHealed: 0,
  });
});
