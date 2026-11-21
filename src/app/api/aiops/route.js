import { NextResponse } from 'next/server.js';
import { TenantIsolationError, tenantStore } from '../../../lib/saasEngine.js';
import { analyzeTenantOps } from '../../../lib/aiopsEngine.js';
import { defaultDatabase } from '../../../lib/telemetryDatabase.js';

/**
 * GET /api/aiops
 * AIOps intelligence endpoint delivering real-time health score, anomaly detection,
 * incident correlation, root cause analysis (RCA), and prescriptive runbook recommendations.
 * 
 * Query parameters:
 * - tenantId (required): Target tenant identifier
 * - region (optional): Origin region filter
 */
export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const rawTenantId = searchParams.get('tenantId');
    const regionParam = searchParams.get('region');

    // 1. Enforce strict tenant isolation
    if (!rawTenantId || rawTenantId.trim() === '') {
      return NextResponse.json(
        { error: 'tenantId query parameter is required for strict tenant isolation' },
        { status: 400 }
      );
    }

    const tenantId = rawTenantId.trim();
    const region = regionParam && regionParam.trim() !== '' ? regionParam.trim() : null;

    // 2. Query in-memory partition; if empty, check canonical database events
    const partition = tenantStore.get(tenantId);
    let customEvents = null;
    if (!partition || !partition.events || partition.events.length === 0) {
      const dbEvents = defaultDatabase.getEvents(tenantId, { region });
      if (dbEvents && dbEvents.length > 0) {
        customEvents = dbEvents;
      }
    }

    // 3. Run end-to-end AIOps intelligence analysis
    const aiopsReport = analyzeTenantOps(tenantId, { region, customEvents });

    return NextResponse.json(aiopsReport, { status: 200 });
  } catch (error) {
    if (error instanceof TenantIsolationError || error.name === 'TenantIsolationError') {
      return NextResponse.json(
        { error: error.message },
        { status: 400 }
      );
    }

    return NextResponse.json(
      {
        error: 'Internal server error',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}

/**
 * POST /api/aiops
 * On-demand AIOps operational intelligence analysis for ad-hoc event batches or simulations.
 * 
 * Body:
 * - tenantId (required): Target tenant identifier
 * - events (optional): Array of telemetry events to evaluate ad-hoc
 * - region (optional): Target region
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
    const region = body.region && typeof body.region === 'string' ? body.region.trim() : null;
    const customEvents = Array.isArray(body.events) ? body.events : null;

    const aiopsReport = analyzeTenantOps(tenantId, {
      region,
      customEvents,
    });

    return NextResponse.json(aiopsReport, { status: 200 });
  } catch (error) {
    if (error instanceof TenantIsolationError || error.name === 'TenantIsolationError') {
      return NextResponse.json(
        { error: error.message },
        { status: 400 }
      );
    }

    return NextResponse.json(
      {
        error: 'Internal server error',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}
