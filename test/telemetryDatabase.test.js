import test from 'node:test';
import assert from 'node:assert/strict';
import {
  TelemetryDatabase,
  SCENARIO_TYPES,
} from '../src/lib/telemetryDatabase.js';

test('1. SQLite Database Schema initializes tables, indexes, and constraints', () => {
  const db = new TelemetryDatabase(':memory:');

  // Verify table existence by inserting a test event
  const event = {
    payloadId: 'test-p1',
    tenantId: 'tenant-test',
    region: 'us-east-1',
    sourceAlias: 'test-source',
    eventTimestampUtc: '2026-11-21T00:00:00Z',
    category: 'infra',
    severity: 'low',
    metrics: { cpuUsage: 25 },
    summary: 'Test summary',
  };

  db.insertEvent(event);
  const events = db.getEvents('tenant-test');
  assert.equal(events.length, 1);
  assert.equal(events[0].payloadId, 'test-p1');
  assert.equal(events[0].metrics.cpuUsage, 25);
  db.close();
});

test('2. Multi-tenant segregation ensures tenant data is strictly partitioned in DB', () => {
  const db = new TelemetryDatabase(':memory:');

  db.insertEvent({
    payloadId: 'p-tenant-1',
    tenantId: 'tenant-Alpha',
    region: 'us-east-1',
    sourceAlias: 'alpha-srv',
    eventTimestampUtc: '2026-11-21T00:01:00Z',
    category: 'network',
    severity: 'low',
  });

  db.insertEvent({
    payloadId: 'p-tenant-2',
    tenantId: 'tenant-Beta',
    region: 'us-west-2',
    sourceAlias: 'beta-srv',
    eventTimestampUtc: '2026-11-21T00:02:00Z',
    category: 'security',
    severity: 'high',
  });

  const alphaEvents = db.getEvents('tenant-Alpha');
  const betaEvents = db.getEvents('tenant-Beta');

  assert.equal(alphaEvents.length, 1);
  assert.equal(alphaEvents[0].payloadId, 'p-tenant-1');

  assert.equal(betaEvents.length, 1);
  assert.equal(betaEvents[0].payloadId, 'p-tenant-2');
  db.close();
});

test('3. Dynamic baseline metric calculation and anomaly detection in DB', () => {
  const db = new TelemetryDatabase(':memory:');
  const tenantId = 'tenant-baseline-test';

  // Insert 5 normal events with latency around 40ms
  for (let i = 0; i < 5; i++) {
    db.insertEvent({
      payloadId: `base-p-${i}`,
      tenantId,
      region: 'us-east-1',
      sourceAlias: 'api-srv',
      eventTimestampUtc: `2026-11-21T00:0${i}:00Z`,
      category: 'network',
      severity: 'low',
      metrics: { latencyMs: 40 + i * 2 },
    });
  }

  const baselines = db.updateMetricBaselines(tenantId);
  assert.ok(baselines.latencyMs);
  assert.equal(baselines.latencyMs.sampleCount, 5);
  assert.ok(baselines.latencyMs.mean >= 40 && baselines.latencyMs.mean <= 50);

  // Insert a severe outlier
  db.insertEvent({
    payloadId: 'outlier-p',
    tenantId,
    region: 'us-east-1',
    sourceAlias: 'api-srv',
    eventTimestampUtc: '2026-11-21T00:10:00Z',
    category: 'network',
    severity: 'high',
    metrics: { latencyMs: 2500, errorRate: 0.25 },
  });

  const anomalies = db.detectAndStoreAnomalies(tenantId);
  assert.ok(anomalies.length > 0);
  assert.ok(anomalies.some((a) => a.payloadId === 'outlier-p'));

  const storedAnomalies = db.getAnomalies(tenantId);
  assert.ok(storedAnomalies.length > 0);
  db.close();
});

test('4. Simulated telemetry: "spikes" scenario generates baseline + spikes and triggers AI incident correlation', () => {
  const db = new TelemetryDatabase(':memory:');
  const tenantId = 'tenant-sim-spikes';

  const result = db.simulateScenario(SCENARIO_TYPES.SPIKES, tenantId, { region: 'us-east-1' });

  assert.equal(result.tenantId, tenantId);
  assert.equal(result.scenarioType, 'spikes');
  assert.equal(result.eventsGeneratedCount, 8); // 5 normal + 3 spikes
  assert.ok(result.anomaliesDetectedCount > 0);

  // Correlated into ONE unified incident
  assert.ok(result.correlatedIncident);
  assert.equal(result.correlatedIncident.severity, 'critical');
  assert.ok(result.correlatedIncident.affectedSources.length >= 2);

  // Explainable RCA narrative
  assert.ok(result.explainableRca);
  assert.ok(result.explainableRca.confidence >= 0.85);
  assert.ok(result.explainableRca.causalChain.length >= 2);

  // Explainable recommendations
  assert.ok(result.recommendations.length > 0);
  const autoscaleRec = result.recommendations.find((r) => r.action === 'HORIZONTAL_AUTOSCALE');
  assert.ok(autoscaleRec);
  assert.ok(autoscaleRec.command.includes('kubectl scale'));

  db.close();
});

test('5. Simulated telemetry: "outages" scenario correlates cascading failure across stack into ONE incident', () => {
  const db = new TelemetryDatabase(':memory:');
  const tenantId = 'tenant-sim-outages';

  const result = db.simulateScenario(SCENARIO_TYPES.OUTAGES, tenantId, { region: 'us-east-1' });

  assert.equal(result.scenarioType, 'outages');
  assert.equal(result.eventsGeneratedCount, 3);

  // Correlated into ONE incident
  assert.ok(result.correlatedIncident);
  assert.equal(result.correlatedIncident.severity, 'critical');
  assert.equal(result.correlatedIncident.eventCount, 3);

  // Verifying cascading propagation across tiers (infra -> network -> collector)
  assert.deepEqual(
    result.correlatedIncident.categories.sort(),
    ['collector', 'infra', 'network']
  );

  // Explainable RCA correctly diagnoses root cause as the DB crash
  assert.ok(result.explainableRca.probableRootCause.includes('INFRA'));
  assert.ok(result.explainableRca.probableRootCause.includes('db-master-us-east'));
  assert.equal(result.explainableRca.rootCauseEvent.sourceAlias, 'db-master-us-east');

  // Verify stored in DB
  const storedIncidents = db.getIncidents(tenantId);
  assert.equal(storedIncidents.length, 1);
  assert.equal(storedIncidents[0].severity, 'critical');

  db.close();
});

test('6. Simulated telemetry: "failed_logins" & malicious activity scenario detects attacks and generates AI mitigation', () => {
  const db = new TelemetryDatabase(':memory:');
  const tenantId = 'tenant-sim-security';

  const result = db.simulateScenario(SCENARIO_TYPES.FAILED_LOGINS, tenantId, { region: 'eu-central-1' });

  assert.equal(result.scenarioType, 'failed_logins');
  assert.equal(result.eventsGeneratedCount, 3);

  // Correlated into ONE security incident
  assert.ok(result.correlatedIncident);
  assert.equal(result.correlatedIncident.category, 'security');
  assert.equal(result.correlatedIncident.severity, 'critical');

  // Security attack logged in security_attacks table
  const attacks = db.getAttacks(tenantId);
  assert.equal(attacks.length, 1);
  assert.equal(attacks[0].attackType, 'CREDENTIAL_STUFFING_AND_SQLI');
  assert.equal(attacks[0].mitigationStatus, 'MITIGATED_BY_SHIELD');

  // Explainable AI recommendations provide edge blocking and rate-limiting
  assert.ok(result.recommendations.some((r) => r.action === 'APPLY_EDGE_RATE_LIMIT'));
  assert.ok(result.recommendations.some((r) => r.action === 'ROTATE_CREDENTIALS'));

  db.close();
});
