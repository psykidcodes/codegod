import test from 'node:test';
import assert from 'node:assert/strict';
import { GET as getTenants, POST as postTenants } from '../src/app/api/tenants/route.js';
import { defaultDatabase } from '../src/lib/telemetryDatabase.js';

test('1. GET /api/tenants returns pre-seeded enterprise tenants with operational health stats', async () => {
  const res = await getTenants();
  assert.equal(res.status, 200);

  const data = await res.json();
  assert.ok(data.total >= 4);
  assert.ok(data.tenants.some((t) => t.tenantId === 'acme-corp'));
  assert.ok(data.tenants.some((t) => t.tenantId === 'fintech-cloud'));

  const acme = data.tenants.find((t) => t.tenantId === 'acme-corp');
  assert.equal(acme.tier, 'enterprise');
  assert.equal(acme.slaTarget, '99.99%');
  assert.ok(typeof acme.healthScore === 'number');
});

test('2. POST /api/tenants dynamically provisions a new tenant partition', async () => {
  const newTenant = {
    tenantId: 'quantum-sec-defense',
    name: 'Quantum Security Defense Systems',
    tier: 'enterprise',
    region: 'us-east-1',
    slaTarget: '99.999%',
  };

  const req = {
    async json() {
      return newTenant;
    },
  };

  const res = await postTenants(req);
  assert.equal(res.status, 201);

  const data = await res.json();
  assert.equal(data.tenant.tenantId, 'quantum-sec-defense');
  assert.equal(data.tenant.tier, 'enterprise');
  assert.equal(data.tenant.slaTarget, '99.999%');

  // Verify tenant is now returned in GET /api/tenants
  const listRes = await getTenants();
  const listData = await listRes.json();
  assert.ok(listData.tenants.some((t) => t.tenantId === 'quantum-sec-defense'));
});

test('3. POST /api/tenants rejects missing or blank tenantId with 400', async () => {
  const req = {
    async json() {
      return { name: 'Nameless Tenant' };
    },
  };

  const res = await postTenants(req);
  assert.equal(res.status, 400);

  const data = await res.json();
  assert.ok(data.error.includes('tenantId is required'));
});
