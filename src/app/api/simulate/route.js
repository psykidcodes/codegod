import { NextResponse } from 'next/server.js';
import { defaultDatabase, SCENARIO_TYPES } from '../../../lib/telemetryDatabase.js';

const VALID_SCENARIOS = new Set([
  SCENARIO_TYPES.SPIKES,
  SCENARIO_TYPES.OUTAGES,
  SCENARIO_TYPES.FAILED_LOGINS,
]);

/**
 * POST /api/simulate
 * Executes a simulated telemetry scenario ('spikes', 'outages', 'failed_logins'):
 * - Generates and persists realistic telemetry streams in the database.
 * - Executes dynamic baseline anomaly detection.
 * - Correlates multiple alerts into one unified Incident record.
 * - Produces transparent, explainable Root Cause Analysis (RCA) and prioritized recommendations.
 * 
 * Body:
 * - scenario (required): 'spikes' | 'outages' | 'failed_logins'
 * - tenantId (required): Target tenant identifier
 * - region (optional): Origin region (default 'us-east-1')
 */
export async function POST(request) {
  try {
    let body;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: 'Invalid JSON payload' },
        { status: 400 }
      );
    }

    if (!body || typeof body !== 'object') {
      return NextResponse.json(
        { error: 'Request body must be a JSON object' },
        { status: 400 }
      );
    }

    const rawTenantId = body.tenantId;
    if (!rawTenantId || typeof rawTenantId !== 'string' || rawTenantId.trim() === '') {
      return NextResponse.json(
        { error: 'tenantId is required for strict tenant isolation' },
        { status: 400 }
      );
    }

    const tenantId = rawTenantId.trim();
    const scenario = body.scenario || body.scenarioType;

    if (!scenario || !VALID_SCENARIOS.has(scenario)) {
      return NextResponse.json(
        {
          error: `Invalid or missing scenario. Must be one of: ${Array.from(VALID_SCENARIOS).join(', ')}`,
        },
        { status: 400 }
      );
    }

    const region = body.region && typeof body.region === 'string' ? body.region.trim() : 'us-east-1';

    // Execute database-backed simulation with integrated AI analysis
    const simulationResult = defaultDatabase.simulateScenario(scenario, tenantId, { region });

    return NextResponse.json(simulationResult, { status: 200 });
  } catch (error) {
    return NextResponse.json(
      {
        error: 'Simulation execution error',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}

/**
 * GET /api/simulate
 * Retrieves past simulations, correlated incidents, and anomalies for a tenant.
 * 
 * Query parameters:
 * - tenantId (required): Target tenant identifier
 */
export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const rawTenantId = searchParams.get('tenantId');

    if (!rawTenantId || rawTenantId.trim() === '') {
      return NextResponse.json(
        { error: 'tenantId query parameter is required' },
        { status: 400 }
      );
    }

    const tenantId = rawTenantId.trim();
    const incidents = defaultDatabase.getIncidents(tenantId);
    const anomalies = defaultDatabase.getAnomalies(tenantId);
    const baselines = defaultDatabase.getBaselines(tenantId);
    const attacks = defaultDatabase.getAttacks(tenantId);

    return NextResponse.json(
      {
        tenantId,
        incidentsCount: incidents.length,
        anomaliesCount: anomalies.length,
        incidents,
        anomalies,
        baselines,
        attacks,
      },
      { status: 200 }
    );
  } catch (error) {
    return NextResponse.json(
      {
        error: 'Failed to retrieve simulation history',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}
