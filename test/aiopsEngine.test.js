import test from 'node:test';
import assert from 'node:assert/strict';
import {
  HEALTH_STATUS,
  calculateHealthScore,
  detectAnomalies,
  correlateIncidents,
  performRootCauseAnalysis,
  generateRecommendations,
  analyzeTenantOps,
} from '../src/lib/aiopsEngine.js';
import {
  ingestSingle,
  resetTenantStore,
  queryTenant,
  queryTenantAiops,
  TenantIsolationError,
} from '../src/lib/saasEngine.js';

test.beforeEach(() => {
  resetTenantStore();
});

test('1. Health score computation accurately degrades on high/critical severities and adverse metrics', () => {
  const now = new Date('2026-11-20T12:00:00Z').getTime();

  // Test 1a: Perfect health on low-severity events
  const normalEvents = [
    {
      payloadId: 'p-norm-1',
      tenantId: 'tenant-healthy',
      region: 'us-east-1',
      sourceAlias: 'worker-1',
      eventTimestampUtc: '2026-11-20T11:58:00Z',
      category: 'collector',
      severity: 'low',
    },
    {
      payloadId: 'p-norm-2',
      tenantId: 'tenant-healthy',
      region: 'us-east-1',
      sourceAlias: 'worker-2',
      eventTimestampUtc: '2026-11-20T11:59:00Z',
      category: 'infra',
      severity: 'low',
    },
  ];

  const healthyResult = calculateHealthScore(normalEvents, { isStale: false, now });
  assert.ok(healthyResult.healthScore >= 95);
  assert.equal(healthyResult.healthStatus, HEALTH_STATUS.HEALTHY);

  // Test 1b: Critical infrastructure outage causing degradation
  const criticalEvents = [
    {
      payloadId: 'p-crit-1',
      tenantId: 'tenant-degraded',
      region: 'us-west-1',
      sourceAlias: 'db-master',
      eventTimestampUtc: '2026-11-20T11:58:00Z',
      category: 'infra',
      severity: 'critical',
      metrics: { cpuUsage: 99, memoryUsage: 96 },
    },
    {
      payloadId: 'p-crit-2',
      tenantId: 'tenant-degraded',
      region: 'us-west-1',
      sourceAlias: 'api-gw',
      eventTimestampUtc: '2026-11-20T11:59:00Z',
      category: 'network',
      severity: 'high',
      metrics: { latencyMs: 2200, errorRate: 0.18 },
    },
  ];

  const criticalResult = calculateHealthScore(criticalEvents, { isStale: false, now });
  assert.ok(criticalResult.healthScore < 50);
  assert.equal(criticalResult.healthStatus, HEALTH_STATUS.CRITICAL);
});

test('2. Category-level health breakdown isolates health impact per operational domain', () => {
  const now = new Date('2026-11-20T12:00:00Z').getTime();

  // Infra has critical failure; security is untouched; network has medium alerts
  const events = [
    {
      payloadId: 'p-cat-1',
      tenantId: 'tenant-cat',
      region: 'eu-west-1',
      sourceAlias: 'compute-1',
      eventTimestampUtc: '2026-11-20T11:57:00Z',
      category: 'infra',
      severity: 'critical',
      metrics: { memoryUsage: 98 },
    },
    {
      payloadId: 'p-cat-2',
      tenantId: 'tenant-cat',
      region: 'eu-west-1',
      sourceAlias: 'gw-1',
      eventTimestampUtc: '2026-11-20T11:58:00Z',
      category: 'network',
      severity: 'medium',
    },
  ];

  const result = calculateHealthScore(events, { isStale: false, now });
  assert.ok(result.categoryHealth.infra.score < 50);
  assert.equal(result.categoryHealth.infra.status, HEALTH_STATUS.CRITICAL);
  assert.equal(result.categoryHealth.infra.criticalCount, 1);

  assert.ok(result.categoryHealth.network.score >= 80);
  assert.equal(result.categoryHealth.security.score, 100);
  assert.equal(result.categoryHealth.security.status, HEALTH_STATUS.HEALTHY);
});

test('3. Staleness penalty applies when tenant partition has lost heartbeat (>30s)', () => {
  const events = [
    {
      payloadId: 'p-stale-1',
      tenantId: 'tenant-stale',
      region: 'us-east-1',
      sourceAlias: 'edge-1',
      eventTimestampUtc: '2026-11-20T10:00:00Z',
      category: 'infra',
      severity: 'low',
    },
  ];

  const staleResult = calculateHealthScore(events, { isStale: true });
  assert.ok(staleResult.healthScore < 90); // Penalized due to staleness
});

test('4. Anomaly detection identifies statistical metric outliers (Z-score) and hard limit breaches', () => {
  // Baseline latency is ~100ms. Outlier latency is 1500ms
  const events = [
    {
      payloadId: 'e-1',
      tenantId: 'tenant-anomaly',
      region: 'us-east-1',
      sourceAlias: 'api-service',
      eventTimestampUtc: '2026-11-20T10:00:00Z',
      category: 'network',
      severity: 'low',
      metrics: { latencyMs: 95 },
    },
    {
      payloadId: 'e-2',
      tenantId: 'tenant-anomaly',
      region: 'us-east-1',
      sourceAlias: 'api-service',
      eventTimestampUtc: '2026-11-20T10:01:00Z',
      category: 'network',
      severity: 'low',
      metrics: { latencyMs: 105 },
    },
    {
      payloadId: 'e-3',
      tenantId: 'tenant-anomaly',
      region: 'us-east-1',
      sourceAlias: 'api-service',
      eventTimestampUtc: '2026-11-20T10:02:00Z',
      category: 'network',
      severity: 'low',
      metrics: { latencyMs: 100 },
    },
    {
      payloadId: 'e-outlier',
      tenantId: 'tenant-anomaly',
      region: 'us-east-1',
      sourceAlias: 'api-service',
      eventTimestampUtc: '2026-11-20T10:03:00Z',
      category: 'network',
      severity: 'high',
      metrics: { latencyMs: 1500, errorRate: 0.22 },
    },
  ];

  const anomalies = detectAnomalies(events);
  assert.ok(anomalies.length > 0);

  const outlierAnomaly = anomalies.find((a) => a.payloadId === 'e-outlier');
  assert.ok(outlierAnomaly);
  assert.ok(outlierAnomaly.anomalyScore > 0.7);
  assert.ok(outlierAnomaly.reasons.some((r) => r.includes('latencyMs')));
  assert.ok(outlierAnomaly.reasons.some((r) => r.includes('Error rate')));
});

test('5. Alert storm detection flags high-frequency clusters of severe events', () => {
  const events = [
    {
      payloadId: 'storm-1',
      tenantId: 'tenant-storm',
      region: 'us-west-2',
      sourceAlias: 'node-1',
      eventTimestampUtc: '2026-11-20T14:00:10Z',
      category: 'infra',
      severity: 'critical',
    },
    {
      payloadId: 'storm-2',
      tenantId: 'tenant-storm',
      region: 'us-west-2',
      sourceAlias: 'node-2',
      eventTimestampUtc: '2026-11-20T14:00:30Z',
      category: 'infra',
      severity: 'high',
    },
    {
      payloadId: 'storm-3',
      tenantId: 'tenant-storm',
      region: 'us-west-2',
      sourceAlias: 'node-3',
      eventTimestampUtc: '2026-11-20T14:00:50Z',
      category: 'infra',
      severity: 'critical',
    },
  ];

  const anomalies = detectAnomalies(events);
  assert.ok(anomalies.some((a) => a.reasons.some((r) => r.includes('Alert storm detected'))));
});

test('6. Incident correlation clusters cascading alerts within 10-minute sliding window', () => {
  const events = [
    {
      payloadId: 'p-inc-1',
      tenantId: 'tenant-incident',
      region: 'ap-northeast-1',
      sourceAlias: 'db-host',
      eventTimestampUtc: '2026-11-20T15:00:00Z',
      category: 'infra',
      severity: 'critical',
      metrics: { memoryUsage: 99 },
    },
    {
      payloadId: 'p-inc-2',
      tenantId: 'tenant-incident',
      region: 'ap-northeast-1',
      sourceAlias: 'api-server',
      eventTimestampUtc: '2026-11-20T15:03:00Z',
      category: 'network',
      severity: 'high',
      metrics: { latencyMs: 2500 },
    },
    {
      payloadId: 'p-inc-3',
      tenantId: 'tenant-incident',
      region: 'ap-northeast-1',
      sourceAlias: 'edge-collector',
      eventTimestampUtc: '2026-11-20T15:05:00Z',
      category: 'collector',
      severity: 'high',
    },
  ];

  const incidents = correlateIncidents(events);
  assert.equal(incidents.length, 1);

  const inc = incidents[0];
  assert.equal(inc.severity, 'critical');
  assert.equal(inc.eventCount, 3);
  assert.deepEqual(inc.correlatedPayloadIds, ['p-inc-1', 'p-inc-2', 'p-inc-3']);
  assert.deepEqual(inc.affectedSources.sort(), ['api-server', 'db-host', 'edge-collector']);
  assert.equal(inc.durationSeconds, 300); // 5 minutes
});

test('7. Root Cause Analysis (RCA) traces causal propagation chain and calculates confidence score', () => {
  const incidentEvents = [
    {
      payloadId: 'rca-origin',
      tenantId: 'tenant-rca',
      region: 'us-east-1',
      sourceAlias: 'db-node-primary',
      eventTimestampUtc: '2026-11-20T16:00:00Z',
      category: 'infra',
      severity: 'critical',
      metrics: { memoryUsage: 97, cpuUsage: 92 },
    },
    {
      payloadId: 'rca-downstream',
      tenantId: 'tenant-rca',
      region: 'us-east-1',
      sourceAlias: 'web-gateway',
      eventTimestampUtc: '2026-11-20T16:02:00Z',
      category: 'network',
      severity: 'high',
      metrics: { latencyMs: 1800 },
    },
  ];

  const incident = {
    incidentId: 'inc-test-rca',
    title: 'Test Incident',
    severity: 'critical',
    category: 'infra',
    categories: ['infra', 'network'],
    regions: ['us-east-1'],
    affectedSources: ['db-node-primary', 'web-gateway'],
    events: incidentEvents,
  };

  const rca = performRootCauseAnalysis(incident, incidentEvents);

  assert.ok(rca.probableRootCause.includes('INFRA'));
  assert.ok(rca.probableRootCause.includes('db-node-primary'));
  assert.equal(rca.rootCauseEvent.payloadId, 'rca-origin');
  assert.ok(rca.confidence >= 0.85);
  assert.ok(rca.causalChain.length >= 2);
  assert.ok(rca.causalChain[0].includes('Origin: infra'));
  assert.ok(rca.causalChain[1].includes('Cascade: network'));
});

test('8. Prescriptive remediation runbooks generate actionable, prioritized operational commands', () => {
  const incident = {
    category: 'infra',
    severity: 'critical',
  };
  const rca = {
    probableRootCause: 'Memory exhaustion on compute-worker-1 in us-east-1',
    rootCauseEvent: {
      sourceAlias: 'compute-worker-1',
      region: 'us-east-1',
    },
  };

  const recs = generateRecommendations(incident, rca);
  assert.ok(recs.length >= 2);

  const scaleRec = recs.find((r) => r.action === 'HORIZONTAL_AUTOSCALE');
  assert.ok(scaleRec);
  assert.equal(scaleRec.priority, 'P1_CRITICAL');
  assert.ok(scaleRec.command.includes('kubectl scale'));
  assert.equal(scaleRec.automatedRemediationPossible, true);
});

test('9. analyzeTenantOps enforces strict tenant isolation and throws on missing tenantId', () => {
  assert.throws(
    () => analyzeTenantOps(''),
    TenantIsolationError
  );
  assert.throws(
    () => analyzeTenantOps(null),
    TenantIsolationError
  );
  assert.throws(
    () => analyzeTenantOps('   '),
    TenantIsolationError
  );

  // Ingest data for tenant Alpha
  ingestSingle({
    payloadId: 'alpha-p1',
    tenantId: 'tenant-Alpha',
    region: 'us-east-1',
    sourceAlias: 'alpha-node',
    eventTimestampUtc: '2026-11-20T17:00:00Z',
    category: 'infra',
    severity: 'critical',
    metrics: { cpuUsage: 98 },
  });

  // Query tenant Beta (which has 0 events)
  const betaReport = analyzeTenantOps('tenant-Beta');
  assert.equal(betaReport.tenantId, 'tenant-Beta');
  assert.equal(betaReport.summary.totalEventsAnalyzed, 0);
  assert.equal(betaReport.healthScore, 100);
  assert.equal(betaReport.healthStatus, HEALTH_STATUS.UNKNOWN);
  assert.equal(betaReport.incidents.length, 0);

  // Query tenant Alpha
  const alphaReport = analyzeTenantOps('tenant-Alpha');
  assert.equal(alphaReport.tenantId, 'tenant-Alpha');
  assert.equal(alphaReport.summary.totalEventsAnalyzed, 1);
  assert.ok(alphaReport.healthScore < 80);
  assert.equal(alphaReport.incidents.length, 1);
});

test('10. End-to-end integration: Ingest batch -> analyzeTenantOps returns comprehensive report', () => {
  const tenantId = 'tenant-full-aiops';

  ingestSingle({
    payloadId: 'full-p1',
    tenantId,
    region: 'us-west-1',
    sourceAlias: 'db-shard-1',
    eventTimestampUtc: '2026-11-20T18:00:00Z',
    category: 'infra',
    severity: 'critical',
    metrics: { memoryUsage: 99, cpuUsage: 95 },
  });

  ingestSingle({
    payloadId: 'full-p2',
    tenantId,
    region: 'us-west-1',
    sourceAlias: 'api-service',
    eventTimestampUtc: '2026-11-20T18:02:00Z',
    category: 'network',
    severity: 'high',
    metrics: { latencyMs: 2400, errorRate: 0.12 },
  });

  const report = analyzeTenantOps(tenantId);

  assert.equal(report.tenantId, tenantId);
  assert.equal(report.summary.totalEventsAnalyzed, 2);
  assert.ok(report.anomalies.length > 0);
  assert.equal(report.incidents.length, 1);
  assert.ok(report.incidents[0].rca.probableRootCause.includes('db-shard-1'));
  assert.ok(report.recommendations.length > 0);
});

test('11. queryTenantAiops exported from saasEngine returns full AIOps analysis report', async () => {
  const tenantId = 'tenant-saasengine-export';
  ingestSingle({
    payloadId: 'saas-p1',
    tenantId,
    region: 'us-east-1',
    sourceAlias: 'worker-node',
    eventTimestampUtc: '2026-11-20T19:00:00Z',
    category: 'infra',
    severity: 'low',
  });

  const report = await queryTenantAiops(tenantId);
  assert.equal(report.tenantId, tenantId);
  assert.equal(report.summary.totalEventsAnalyzed, 1);
  assert.ok(report.healthScore >= 95);
});
