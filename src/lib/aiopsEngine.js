/**
 * @file aiopsEngine.js
 * @description Built-in AIOps Intelligence Engine for Multi-Tenant SaaS Telemetry
 * 
 * Features:
 * 1. Health Scoring & Health Status:
 *    - Real-time 0-100 health score computation with time-decay recency weighting.
 *    - Category health breakdowns (infra, network, security, collector).
 *    - Status states: HEALTHY, DEGRADED, CRITICAL, STALE, UNKNOWN.
 * 2. Anomaly Detection:
 *    - Statistical Z-score anomaly detection across numeric telemetry metrics.
 *    - Alert storm & high-frequency burst detection.
 *    - Dynamic baseline calculation (mean & standard deviation).
 * 3. Intelligent Incident Correlation:
 *    - Automated clustering of raw telemetry events into unified incidents.
 *    - Temporal sliding window correlation (default 10 mins).
 *    - Cascading dependency correlation (infra -> network -> collector).
 * 4. Root Cause Analysis (RCA):
 *    - Temporal first-mover diagnosis to identify the triggering root cause event.
 *    - Cross-category dependency propagation tracing.
 *    - Confidence scoring (0.0 to 1.0) and step-by-step causal chain construction.
 * 5. Actionable Prescriptive Runbooks:
 *    - Automatic remediation recommendations based on diagnosed RCA.
 *    - Prioritized action runbooks with execution commands.
 * 6. Multi-Tenant Segregation:
 *    - Strict partition isolation preserving zero cross-tenant contamination.
 */

import {
  tenantStore,
  TenantIsolationError,
  STALENESS_THRESHOLD_MS,
  VALID_CATEGORIES,
  VALID_SEVERITIES,
} from './saasEngine.js';

export const HEALTH_STATUS = Object.freeze({
  HEALTHY: 'HEALTHY',
  DEGRADED: 'DEGRADED',
  CRITICAL: 'CRITICAL',
  STALE: 'STALE',
  UNKNOWN: 'UNKNOWN',
});

export const SEVERITY_PENALTIES = Object.freeze({
  critical: 36,
  high: 18,
  medium: 7,
  low: 1.5,
});

export const CATEGORY_WEIGHTS = Object.freeze({
  infra: 1.25,     // Infrastructure issues typically trigger cascading outages
  network: 1.15,   // Network degradation propagates across services
  security: 1.20,  // Security alerts require immediate operational attention
  collector: 0.90, // Collector issues impact observability pipeline
});

export const CORRELATION_WINDOW_MS = 10 * 60 * 1000; // 10 minutes

/**
 * Calculates a recency decay factor [0.15, 1.0] based on event age.
 * Recent events impact current health much more significantly than older events.
 * 
 * @param {number} eventTimeMs 
 * @param {number} nowMs 
 * @returns {number} Decay weight
 */
export function getRecencyWeight(eventTimeMs, nowMs = Date.now()) {
  const ageMs = Math.max(0, nowMs - eventTimeMs);
  const fiveMinutes = 5 * 60 * 1000;
  const fifteenMinutes = 15 * 60 * 1000;
  const oneHour = 60 * 60 * 1000;

  if (ageMs <= fiveMinutes) return 1.0;
  if (ageMs <= fifteenMinutes) return 0.75;
  if (ageMs <= oneHour) return 0.45;
  return 0.15;
}

/**
 * Computes health score (0-100) and health status for an array of telemetry events.
 * 
 * @param {Array<object>} events 
 * @param {object} options
 * @param {boolean} [options.isStale=false]
 * @param {number|null} [options.now=null]
 * @returns {{
 *   healthScore: number,
 *   healthStatus: string,
 *   categoryHealth: Record<string, { score: number, status: string, eventCount: number, criticalCount: number }>,
 *   healthTrend: 'HEALTHY' | 'DEGRADING' | 'CRITICAL' | 'STABLE'
 * }}
 */
export function calculateHealthScore(events = [], { isStale = false, now = null } = {}) {
  // Determine effective time baseline: anchor to latest event if evaluating historical logs
  let effectiveNow = now;
  if (effectiveNow === null || effectiveNow === undefined) {
    if (events && events.length > 0) {
      const timestamps = events
        .map((e) => new Date(e.eventTimestampUtc).getTime())
        .filter((t) => !Number.isNaN(t));
      const maxTimestamp = timestamps.length > 0 ? Math.max(...timestamps) : Date.now();
      if (Date.now() - maxTimestamp > 60 * 60 * 1000) {
        effectiveNow = maxTimestamp;
      } else {
        effectiveNow = Date.now();
      }
    } else {
      effectiveNow = Date.now();
    }
  }

  if (!events || events.length === 0) {
    return {
      healthScore: 100.0,
      healthStatus: HEALTH_STATUS.UNKNOWN,
      categoryHealth: {
        infra: { score: 100, status: HEALTH_STATUS.UNKNOWN, eventCount: 0, criticalCount: 0 },
        network: { score: 100, status: HEALTH_STATUS.UNKNOWN, eventCount: 0, criticalCount: 0 },
        security: { score: 100, status: HEALTH_STATUS.UNKNOWN, eventCount: 0, criticalCount: 0 },
        collector: { score: 100, status: HEALTH_STATUS.UNKNOWN, eventCount: 0, criticalCount: 0 },
      },
      healthTrend: 'STABLE',
    };
  }

  // Base score
  let totalPenalty = 0;
  const categoryStats = {
    infra: { penalty: 0, eventCount: 0, criticalCount: 0 },
    network: { penalty: 0, eventCount: 0, criticalCount: 0 },
    security: { penalty: 0, eventCount: 0, criticalCount: 0 },
    collector: { penalty: 0, eventCount: 0, criticalCount: 0 },
  };

  for (const event of events) {
    const category = event.category || 'infra';
    const severity = event.severity || 'low';
    const timestampMs = new Date(event.eventTimestampUtc).getTime();
    const recency = !Number.isNaN(timestampMs) ? getRecencyWeight(timestampMs, effectiveNow) : 1.0;

    const basePenalty = SEVERITY_PENALTIES[severity] || 1.5;
    const catWeight = CATEGORY_WEIGHTS[category] || 1.0;

    // Metrics degradation check (e.g. errorRate > 0.05, latency > 1000ms, cpu > 90%)
    let metricPenalty = 0;
    if (event.metrics && typeof event.metrics === 'object') {
      const m = event.metrics;
      if (typeof m.errorRate === 'number' && m.errorRate > 0.05) {
        metricPenalty += Math.min(25, (m.errorRate / 0.05) * 5);
      }
      if (typeof m.latencyMs === 'number' && m.latencyMs > 1000) {
        metricPenalty += Math.min(20, (m.latencyMs - 1000) / 100);
      }
      if (typeof m.cpuUsage === 'number' && m.cpuUsage > 90) {
        metricPenalty += (m.cpuUsage - 90) * 1.5;
      }
      if (typeof m.memoryUsage === 'number' && m.memoryUsage > 90) {
        metricPenalty += (m.memoryUsage - 90) * 1.5;
      }
    }

    const eventPenalty = (basePenalty * catWeight + metricPenalty) * recency;
    totalPenalty += eventPenalty;

    if (categoryStats[category]) {
      categoryStats[category].penalty += eventPenalty;
      categoryStats[category].eventCount++;
      if (severity === 'critical') {
        categoryStats[category].criticalCount++;
      }
    }
  }

  // Staleness penalty
  if (isStale) {
    totalPenalty += 18.0;
  }

  const rawScore = Math.max(0, Math.min(100, 100 - totalPenalty));
  const healthScore = Math.round(rawScore * 10) / 10;

  // Determine health status
  let healthStatus;
  if (isStale && healthScore >= 80) {
    healthStatus = HEALTH_STATUS.STALE;
  } else if (healthScore >= 80) {
    healthStatus = HEALTH_STATUS.HEALTHY;
  } else if (healthScore >= 50) {
    healthStatus = HEALTH_STATUS.DEGRADED;
  } else {
    healthStatus = HEALTH_STATUS.CRITICAL;
  }

  // Category health sub-scores
  const categoryHealth = {};
  for (const cat of VALID_CATEGORIES) {
    const stats = categoryStats[cat];
    const catScore = Math.round(Math.max(0, Math.min(100, 100 - stats.penalty)) * 10) / 10;
    let catStatus = HEALTH_STATUS.HEALTHY;
    if (stats.eventCount === 0) {
      catStatus = HEALTH_STATUS.HEALTHY;
    } else if (catScore < 50) {
      catStatus = HEALTH_STATUS.CRITICAL;
    } else if (catScore < 80) {
      catStatus = HEALTH_STATUS.DEGRADED;
    }

    categoryHealth[cat] = {
      score: catScore,
      status: catStatus,
      eventCount: stats.eventCount,
      criticalCount: stats.criticalCount,
    };
  }

  let healthTrend = 'STABLE';
  if (healthScore < 50) {
    healthTrend = 'CRITICAL';
  } else if (healthScore < 80) {
    healthTrend = 'DEGRADING';
  } else {
    healthTrend = 'HEALTHY';
  }

  return {
    healthScore,
    healthStatus,
    categoryHealth,
    healthTrend,
  };
}

/**
 * Computes mean and sample standard deviation of an array of numbers.
 * 
 * @param {Array<number>} values 
 * @returns {{ mean: number, stdDev: number, min: number, max: number }}
 */
export function calculateStats(values) {
  if (!values || values.length === 0) {
    return { mean: 0, stdDev: 0, min: 0, max: 0 };
  }
  const count = values.length;
  const mean = values.reduce((acc, v) => acc + v, 0) / count;
  const variance = count > 1
    ? values.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / (count - 1)
    : 0;
  const stdDev = Math.sqrt(variance);

  return {
    mean: Math.round(mean * 100) / 100,
    stdDev: Math.round(stdDev * 100) / 100,
    min: Math.min(...values),
    max: Math.max(...values),
  };
}

/**
 * Statistical and behavioral anomaly detection engine across telemetry events.
 * 
 * @param {Array<object>} events 
 * @param {object} [options]
 * @param {number} [options.zThreshold=2.0] Z-score threshold to flag anomaly
 * @returns {Array<object>} Detected anomalies
 */
export function detectAnomalies(events = [], { zThreshold = 2.0 } = {}) {
  if (!events || events.length === 0) {
    return [];
  }

  const anomalies = [];

  // 1. Group metric values by metric key to establish baselines
  const metricValuesByKey = new Map();

  for (const event of events) {
    if (event.metrics && typeof event.metrics === 'object') {
      for (const [key, val] of Object.entries(event.metrics)) {
        if (typeof val === 'number' && !Number.isNaN(val)) {
          if (!metricValuesByKey.has(key)) {
            metricValuesByKey.set(key, []);
          }
          metricValuesByKey.get(key).push(val);
        }
      }
    }
  }

  // Compute baseline stats per metric key
  const metricBaselines = new Map();
  for (const [key, values] of metricValuesByKey.entries()) {
    metricBaselines.set(key, calculateStats(values));
  }

  // 2. Evaluate individual events for metric anomalies
  for (const event of events) {
    const eventReasons = [];
    let maxMetricZScore = 0;

    if (event.metrics && typeof event.metrics === 'object') {
      for (const [key, val] of Object.entries(event.metrics)) {
        if (typeof val === 'number' && !Number.isNaN(val)) {
          const stats = metricBaselines.get(key);
          const valuesForKey = metricValuesByKey.get(key) || [];
          const effectiveZ = valuesForKey.length <= 5 ? 1.4 : zThreshold;
          if (stats && stats.stdDev > 0) {
            const zScore = (val - stats.mean) / stats.stdDev;
            if (zScore >= effectiveZ) {
              eventReasons.push(
                `Metric '${key}' value ${val} significantly exceeds baseline (mean: ${stats.mean}, stdDev: ${stats.stdDev}, z-score: ${zScore.toFixed(2)})`
              );
              if (zScore > maxMetricZScore) {
                maxMetricZScore = zScore;
              }
            }
          }

          // Hard thresholds for critical indicators
          if (key === 'latencyMs' && val >= 1000) {
            eventReasons.push(`Latency ${val}ms breaches critical operational SLA (>=1000ms)`);
          } else if (key === 'errorRate' && val >= 0.15) {
            eventReasons.push(`Error rate ${val * 100}% breaches critical threshold (15%)`);
          } else if (key === 'cpuUsage' && val >= 95) {
            eventReasons.push(`CPU utilization ${val}% indicates resource starvation (>=95%)`);
          } else if (key === 'memoryUsage' && val >= 95) {
            eventReasons.push(`Memory utilization ${val}% indicates critical memory pressure (>=95%)`);
          } else if (key === 'packetLoss' && val >= 5) {
            eventReasons.push(`Packet loss ${val}% breaches operational tolerance (>=5%)`);
          }
        }
      }
    }

    // Critical severity flag
    if (event.severity === 'critical') {
      eventReasons.push(`Critical severity alert logged by source '${event.sourceAlias}'`);
    }

    if (eventReasons.length > 0) {
      const anomalyScore = Math.min(
        1.0,
        Math.round((0.4 + (maxMetricZScore > 0 ? maxMetricZScore * 0.15 : 0.3) + (event.severity === 'critical' ? 0.3 : 0.1)) * 100) / 100
      );

      anomalies.push({
        payloadId: event.payloadId,
        sourceAlias: event.sourceAlias,
        region: event.region,
        category: event.category,
        severity: event.severity,
        eventTimestampUtc: event.eventTimestampUtc,
        anomalyScore,
        reasons: eventReasons,
        metrics: event.metrics || {},
      });
    }
  }

  // 3. Frequency burst anomaly detection: detect alert storm (>=3 high/critical events in 2 min window)
  const severeEvents = events.filter((e) => e.severity === 'high' || e.severity === 'critical');
  if (severeEvents.length >= 3) {
    const twoMinutesMs = 2 * 60 * 1000;
    for (let i = 0; i < severeEvents.length - 2; i++) {
      const t1 = new Date(severeEvents[i].eventTimestampUtc).getTime();
      const t3 = new Date(severeEvents[i + 2].eventTimestampUtc).getTime();
      if (!Number.isNaN(t1) && !Number.isNaN(t3) && (t3 - t1) <= twoMinutesMs) {
        // Tag an alert burst anomaly
        const burstPayloadId = severeEvents[i + 2].payloadId;
        const existing = anomalies.find((a) => a.payloadId === burstPayloadId);
        const burstReason = `Alert storm detected: ${3} severe alerts within ${Math.round((t3 - t1) / 1000)}s window`;
        if (existing) {
          if (!existing.reasons.includes(burstReason)) {
            existing.reasons.push(burstReason);
            existing.anomalyScore = Math.min(1.0, existing.anomalyScore + 0.2);
          }
        } else {
          anomalies.push({
            payloadId: burstPayloadId,
            sourceAlias: severeEvents[i + 2].sourceAlias,
            region: severeEvents[i + 2].region,
            category: severeEvents[i + 2].category,
            severity: severeEvents[i + 2].severity,
            eventTimestampUtc: severeEvents[i + 2].eventTimestampUtc,
            anomalyScore: 0.85,
            reasons: [burstReason],
            metrics: severeEvents[i + 2].metrics || {},
          });
        }
      }
    }
  }

  return anomalies;
}

/**
 * Compares severity ranking for sorting.
 * critical > high > medium > low
 */
const SEVERITY_RANK = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
});

export function getMaxSeverity(severities = []) {
  let highest = 'low';
  let highestRank = 0;
  for (const s of severities) {
    const rank = SEVERITY_RANK[s] || 0;
    if (rank > highestRank) {
      highestRank = rank;
      highest = s;
    }
  }
  return highest;
}

/**
 * Correlates raw telemetry events into unified, actionable Incident clusters.
 * Groups events by temporal proximity (10-minute sliding window), category, and region.
 * 
 * @param {Array<object>} events 
 * @param {object} [options]
 * @param {number} [options.windowMs=CORRELATION_WINDOW_MS]
 * @returns {Array<object>} Array of correlated Incident objects
 */
export function correlateIncidents(events = [], { windowMs = CORRELATION_WINDOW_MS, now = null } = {}) {
  if (!events || events.length === 0) {
    return [];
  }

  // Filter events that have high/critical severity or medium severity with adverse metrics
  const impactEvents = events.filter((e) => {
    if (e.severity === 'critical' || e.severity === 'high') return true;
    if (e.severity === 'medium' && e.metrics) {
      const m = e.metrics;
      if (m.errorRate > 0.05 || m.latencyMs > 800 || m.cpuUsage > 85 || m.memoryUsage > 85) return true;
    }
    return false;
  });

  if (impactEvents.length === 0) {
    return [];
  }

  // Sort impact events chronologically ascending
  const sorted = [...impactEvents].sort(
    (a, b) => new Date(a.eventTimestampUtc).getTime() - new Date(b.eventTimestampUtc).getTime()
  );

  const incidentClusters = [];
  let currentCluster = [sorted[0]];

  for (let i = 1; i < sorted.length; i++) {
    const prev = currentCluster[currentCluster.length - 1];
    const curr = sorted[i];

    const prevTime = new Date(prev.eventTimestampUtc).getTime();
    const currTime = new Date(curr.eventTimestampUtc).getTime();
    const timeDelta = currTime - prevTime;

    // Same region or same category within time window correlates into same incident
    const isWithinWindow = timeDelta <= windowMs;
    const isRelated = curr.region === prev.region || curr.category === prev.category || curr.sourceAlias === prev.sourceAlias;

    if (isWithinWindow && isRelated) {
      currentCluster.push(curr);
    } else {
      incidentClusters.push(currentCluster);
      currentCluster = [curr];
    }
  }
  if (currentCluster.length > 0) {
    incidentClusters.push(currentCluster);
  }

  // Build Incident objects
  return incidentClusters.map((cluster, idx) => {
    const firstEvent = cluster[0];
    const lastEvent = cluster[cluster.length - 1];
    const tenantId = firstEvent.tenantId;

    const severities = cluster.map((e) => e.severity);
    const maxSeverity = getMaxSeverity(severities);
    const categories = [...new Set(cluster.map((e) => e.category))];
    const regions = [...new Set(cluster.map((e) => e.region))];
    const sources = [...new Set(cluster.map((e) => e.sourceAlias))];
    const payloadIds = cluster.map((e) => e.payloadId);

    const firstTimeMs = new Date(firstEvent.eventTimestampUtc).getTime();
    const lastTimeMs = new Date(lastEvent.eventTimestampUtc).getTime();
    const durationSeconds = Math.max(0, Math.round((lastTimeMs - firstTimeMs) / 1000));

    // Determine status: ACTIVE if last event is within 15 minutes of effective time, else RESOLVED
    const effectiveTime = now ?? (Date.now() - lastTimeMs > 60 * 60 * 1000 ? lastTimeMs : Date.now());
    const ageFromNow = Math.max(0, effectiveTime - lastTimeMs);
    const status = ageFromNow <= 15 * 60 * 1000 ? 'ACTIVE' : 'RESOLVED';

    const incidentId = `inc-${tenantId}-${categories[0]}-${firstTimeMs}-${idx + 1}`;
    const title = `${maxSeverity.toUpperCase()} ${categories.join('/')} degradation across ${sources.join(', ')} (${regions.join(', ')})`;

    return {
      incidentId,
      title,
      severity: maxSeverity,
      category: categories[0],
      categories,
      regions,
      affectedSources: sources,
      eventCount: cluster.length,
      firstSeenUtc: firstEvent.eventTimestampUtc,
      lastSeenUtc: lastEvent.eventTimestampUtc,
      durationSeconds,
      status,
      correlatedPayloadIds: payloadIds,
      events: cluster,
    };
  });
}

/**
 * Root Cause Analysis (RCA) Engine.
 * Identifies the triggering first-mover event, cross-tier dependency propagation,
 * causal chain, and diagnostic confidence.
 * 
 * @param {object} incident 
 * @param {Array<object>} allEvents 
 * @returns {object} Detailed RCA diagnosis
 */
export function performRootCauseAnalysis(incident, allEvents = []) {
  if (!incident || !incident.events || incident.events.length === 0) {
    return {
      probableRootCause: 'No incident events available for root cause diagnosis',
      rootCauseEvent: null,
      confidence: 0.0,
      causalChain: [],
      contributingFactors: [],
    };
  }

  const incidentEvents = [...incident.events].sort(
    (a, b) => new Date(a.eventTimestampUtc).getTime() - new Date(b.eventTimestampUtc).getTime()
  );

  // 1. Dependency priority order: infra failures trigger network & collector cascades
  const CATEGORY_PRECEDENCE = {
    infra: 1,
    network: 2,
    security: 3,
    collector: 4,
  };

  // Find candidate root cause:
  // Earliest event with the highest architectural dependency and severity
  let rootCauseCandidate = incidentEvents[0];
  let highestPrecedenceScore = -1;

  for (const event of incidentEvents) {
    const depScore = (5 - (CATEGORY_PRECEDENCE[event.category] || 5)) * 10;
    const sevScore = (SEVERITY_RANK[event.severity] || 1) * 15;
    const score = depScore + sevScore;

    if (score > highestPrecedenceScore) {
      highestPrecedenceScore = score;
      rootCauseCandidate = event;
    }
  }

  // 2. Identify anomalous metrics on root cause candidate
  const metricAnomalies = [];
  if (rootCauseCandidate.metrics && typeof rootCauseCandidate.metrics === 'object') {
    for (const [k, v] of Object.entries(rootCauseCandidate.metrics)) {
      if (k === 'cpuUsage' && v > 85) metricAnomalies.push(`CPU saturation at ${v}%`);
      if (k === 'memoryUsage' && v > 85) metricAnomalies.push(`Memory exhaustion at ${v}%`);
      if (k === 'errorRate' && v > 0.05) metricAnomalies.push(`Error rate surge to ${(v * 100).toFixed(1)}%`);
      if (k === 'latencyMs' && v > 1000) metricAnomalies.push(`High latency of ${v}ms`);
      if (k === 'packetLoss' && v > 2) metricAnomalies.push(`Packet loss of ${v}%`);
    }
  }

  // 3. Build step-by-step causal chain
  const causalChain = [];
  const triggerSummary = metricAnomalies.length > 0 ? metricAnomalies.join(', ') : `${rootCauseCandidate.severity} alert`;
  causalChain.push(
    `[Origin: ${rootCauseCandidate.category}] Triggered on source '${rootCauseCandidate.sourceAlias}' (${rootCauseCandidate.region}) with ${triggerSummary} at ${rootCauseCandidate.eventTimestampUtc}`
  );

  for (const ev of incidentEvents) {
    if (ev.payloadId !== rootCauseCandidate.payloadId) {
      causalChain.push(
        `[Cascade: ${ev.category}] Impacted source '${ev.sourceAlias}' with severity '${ev.severity}' at ${ev.eventTimestampUtc}`
      );
    }
  }

  // 4. Formulate probable root cause description
  let probableRootCause = `Root cause identified as ${rootCauseCandidate.category.toUpperCase()} failure on source '${rootCauseCandidate.sourceAlias}' in region '${rootCauseCandidate.region}'`;
  if (metricAnomalies.length > 0) {
    probableRootCause += ` due to ${metricAnomalies.join(' and ')}`;
  }
  if (incidentEvents.length > 1) {
    probableRootCause += `, propagating cascading alerts to ${incident.affectedSources.length - 1} downstream component(s).`;
  } else {
    probableRootCause += '.';
  }

  // 5. Calculate diagnostic confidence score
  let confidence = 0.70;
  if (rootCauseCandidate.severity === 'critical') confidence += 0.15;
  if (metricAnomalies.length > 0) confidence += 0.10;
  if (rootCauseCandidate.category === 'infra') confidence += 0.05;
  confidence = Math.min(0.98, Math.round(confidence * 100) / 100);

  const contributingFactors = [
    `Affected components: ${incident.affectedSources.join(', ')}`,
    `Regions impacted: ${incident.regions.join(', ')}`,
    ...metricAnomalies,
  ];

  return {
    probableRootCause,
    rootCauseEvent: {
      payloadId: rootCauseCandidate.payloadId,
      sourceAlias: rootCauseCandidate.sourceAlias,
      region: rootCauseCandidate.region,
      category: rootCauseCandidate.category,
      severity: rootCauseCandidate.severity,
      eventTimestampUtc: rootCauseCandidate.eventTimestampUtc,
      metrics: rootCauseCandidate.metrics || {},
    },
    confidence,
    causalChain,
    contributingFactors,
  };
}

/**
 * Generates prescriptive operational remediation runbooks based on incident RCA.
 * 
 * @param {object} incident 
 * @param {object} rca 
 * @returns {Array<object>} Prioritized actionable recommendations
 */
export function generateRecommendations(incident, rca) {
  const recommendations = [];
  const category = incident.category || 'infra';
  const severity = incident.severity || 'medium';
  const rootEvent = rca.rootCauseEvent || {};
  const source = rootEvent.sourceAlias || 'affected-node';
  const region = rootEvent.region || 'primary-region';

  if (category === 'infra' || rca?.probableRootCause?.includes('CPU') || rca?.probableRootCause?.includes('Memory')) {
    const isMemory = rca?.probableRootCause?.includes('Memory');
    const isCpu = rca?.probableRootCause?.includes('CPU');

    recommendations.push({
      id: 'rec-infra-scale-01',
      action: 'HORIZONTAL_AUTOSCALE',
      priority: severity === 'critical' ? 'P1_CRITICAL' : 'P2_HIGH',
      title: `Scale container compute resources for ${source}`,
      description: `Immediately trigger horizontal scale-out or vertical memory/CPU pod upgrade in ${region} to relieve resource exhaustion.`,
      automatedRemediationPossible: true,
      command: `kubectl scale deployment/${source} --replicas=5 -n production`,
    });

    if (isMemory || isCpu) {
      recommendations.push({
        id: 'rec-infra-drain-02',
        action: 'DRAIN_AND_RESTART_NODE',
        priority: 'P2_HIGH',
        title: `Graceful workload migration and node restart for ${source}`,
        description: `Drain pending connections and restart the degraded host container to clear memory leaks.`,
        automatedRemediationPossible: true,
        command: `kubectl cordon ${source} && kubectl drain ${source} --ignore-daemonsets --delete-emptydir-data`,
      });
    }
  } else if (category === 'network') {
    recommendations.push({
      id: 'rec-net-reroute-01',
      action: 'TRAFFIC_SHED_AND_REROUTE',
      priority: 'P1_CRITICAL',
      title: `Reroute ingress traffic away from ${region}`,
      description: `Shift DNS/global load balancer traffic to alternate healthy availability zones to bypass network packet drops.`,
      automatedRemediationPossible: true,
      command: `aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch file://failover-${region}.json`,
    });

    recommendations.push({
      id: 'rec-net-inspect-02',
      action: 'CHECK_VPC_PEERING_AND_SECURITY_GROUPS',
      priority: 'P3_MEDIUM',
      title: `Audit network connectivity and MTU latency`,
      description: `Verify gateway route tables and egress NAT throughput limits in ${region}.`,
      automatedRemediationPossible: false,
    });
  } else if (category === 'security') {
    recommendations.push({
      id: 'rec-sec-ratelimit-01',
      action: 'APPLY_EDGE_RATE_LIMIT',
      priority: 'P1_CRITICAL',
      title: `Enforce edge rate-limiting and WAF drop rules on ${source}`,
      description: `Block suspicious origin IPs and throttle unauthenticated API bursts at edge proxies.`,
      automatedRemediationPossible: true,
      command: `waf-cli rules add --zone ${region} --action BLOCK --threshold 100/min`,
    });

    recommendations.push({
      id: 'rec-sec-token-revocation-02',
      action: 'ROTATE_CREDENTIALS',
      priority: 'P2_HIGH',
      title: `Rotate compromised collector API access tokens`,
      description: `Immediately revoke current collector-token and issue rotated HMAC credentials.`,
      automatedRemediationPossible: false,
    });
  } else if (category === 'collector') {
    recommendations.push({
      id: 'rec-col-restart-01',
      action: 'RESTART_COLLECTOR_DAEMON',
      priority: 'P2_HIGH',
      title: `Restart edge collector agent daemon on ${source}`,
      description: `Flush local SQLite ring buffer and restart telemetry daemon process with batch recovery enabled.`,
      automatedRemediationPossible: true,
      command: `systemctl restart cicada-telemetry-collector.service`,
    });
  }

  // Universal fallback recommendation
  recommendations.push({
    id: 'rec-general-snapshot-09',
    action: 'CAPTURE_DIAGNOSTIC_SNAPSHOT',
    priority: 'P3_MEDIUM',
    title: `Capture heap dump and kernel diagnostic snapshot`,
    description: `Persist system telemetry snapshot for post-mortem analysis before cluster recovery.`,
    automatedRemediationPossible: true,
    command: `collect-sys-dump --target ${source} --region ${region}`,
  });

  return recommendations;
}

/**
 * End-to-end AIOps operational intelligence analysis for a multi-tenant partition.
 * 
 * @param {string} tenantId 
 * @param {object} [options]
 * @param {string|null} [options.region=null]
 * @param {Array<object>|null} [options.customEvents=null]
 * @param {number} [options.now=Date.now()]
 * @returns {object} Complete AIOps intelligence report
 */
export function analyzeTenantOps(tenantId, { region = null, customEvents = null, now = null } = {}) {
  if (!tenantId || typeof tenantId !== 'string' || tenantId.trim() === '') {
    throw new TenantIsolationError(
      'Tenant isolation error: tenantId is required and cannot be empty'
    );
  }

  const normalizedTenantId = tenantId.trim();
  const partition = tenantStore.get(normalizedTenantId) || {
    events: [],
    seenPayloadIds: new Set(),
    auditLog: [],
    stats: {
      totalIngested: 0,
      duplicatesBlocked: 0,
      fieldsStrippedCount: 0,
      outOfOrderCorrected: 0,
      rejectedCount: 0,
      lastSeenUtc: null,
    },
  };

  // Select events to analyze
  let sourceEvents = customEvents && Array.isArray(customEvents) ? customEvents : partition.events;

  // Filter by region if requested
  if (region !== null && region !== undefined && region !== '' && region !== 'all') {
    sourceEvents = sourceEvents.filter((e) => e.region === region);
  }

  // Anchor effective time reference
  let effectiveNow = now;
  if (effectiveNow === null || effectiveNow === undefined) {
    if (sourceEvents && sourceEvents.length > 0) {
      const timestamps = sourceEvents
        .map((e) => new Date(e.eventTimestampUtc).getTime())
        .filter((t) => !Number.isNaN(t));
      const maxTimestamp = timestamps.length > 0 ? Math.max(...timestamps) : Date.now();
      if (Date.now() - maxTimestamp > 60 * 60 * 1000) {
        effectiveNow = maxTimestamp;
      } else {
        effectiveNow = Date.now();
      }
    } else {
      effectiveNow = Date.now();
    }
  }

  // Staleness check
  let isStale = true;
  if (customEvents && Array.isArray(customEvents) && customEvents.length > 0) {
    isStale = false;
  } else if (partition.stats.lastSeenUtc) {
    const lastSeenTime = new Date(partition.stats.lastSeenUtc).getTime();
    if (!Number.isNaN(lastSeenTime)) {
      const baseStalenessTime = Math.max(Date.now(), effectiveNow);
      isStale = (baseStalenessTime - lastSeenTime) > STALENESS_THRESHOLD_MS;
    }
  }

  // 1. Health Scoring
  const health = calculateHealthScore(sourceEvents, { isStale, now: effectiveNow });

  // 2. Anomaly Detection
  const anomalies = detectAnomalies(sourceEvents);

  // 3. Incident Correlation
  const rawIncidents = correlateIncidents(sourceEvents, { now: effectiveNow });

  // 4. Root Cause Analysis & Prescriptive Recommendations per Incident
  const incidents = rawIncidents.map((incident) => {
    const rca = performRootCauseAnalysis(incident, sourceEvents);
    const recommendations = generateRecommendations(incident, rca);
    return {
      incidentId: incident.incidentId,
      title: incident.title,
      severity: incident.severity,
      category: incident.category,
      categories: incident.categories,
      regions: incident.regions,
      affectedSources: incident.affectedSources,
      eventCount: incident.eventCount,
      firstSeenUtc: incident.firstSeenUtc,
      lastSeenUtc: incident.lastSeenUtc,
      durationSeconds: incident.durationSeconds,
      status: incident.status,
      correlatedPayloadIds: incident.correlatedPayloadIds,
      rca,
      recommendations,
    };
  });

  // Top system-wide recommendations across all incidents
  const allRecommendations = [];
  const seenRecIds = new Set();
  for (const inc of incidents) {
    for (const rec of inc.recommendations) {
      if (!seenRecIds.has(rec.id)) {
        seenRecIds.add(rec.id);
        allRecommendations.push(rec);
      }
    }
  }

  return {
    tenantId: normalizedTenantId,
    region: region || 'all',
    healthScore: health.healthScore,
    healthStatus: health.healthStatus,
    categoryHealth: health.categoryHealth,
    isStale,
    summary: {
      totalEventsAnalyzed: sourceEvents.length,
      anomaliesCount: anomalies.length,
      activeIncidentsCount: incidents.filter((i) => i.status === 'ACTIVE').length,
      resolvedIncidentsCount: incidents.filter((i) => i.status === 'RESOLVED').length,
      healthTrend: health.healthTrend,
    },
    anomalies,
    incidents,
    recommendations: allRecommendations,
  };
}

export default {
  HEALTH_STATUS,
  SEVERITY_PENALTIES,
  CATEGORY_WEIGHTS,
  CORRELATION_WINDOW_MS,
  getRecencyWeight,
  calculateHealthScore,
  calculateStats,
  detectAnomalies,
  correlateIncidents,
  performRootCauseAnalysis,
  generateRecommendations,
  analyzeTenantOps,
};
