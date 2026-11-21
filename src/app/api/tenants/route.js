import { NextResponse } from 'next/server.js';
import { defaultDatabase } from '../../../lib/telemetryDatabase.js';
import { getOrCreateTenantPartition } from '../../../lib/saasEngine.js';
import { analyzeTenantOps } from '../../../lib/aiopsEngine.js';

export const dynamic = 'force-dynamic';

/**
 * GET /api/tenants
 * Lists all dynamic registered tenants in the platform enriched with live operational health
 * and incident counts.
 */
export async function GET() {
  try {
    const tenants = defaultDatabase.getTenants();

    // Enrich each tenant with live AIOps health status and telemetry counts
    const enriched = tenants.map((t) => {
      let healthScore = 100;
      let healthStatus = 'HEALTHY';
      let eventsCount = 0;
      let incidentsCount = 0;

      try {
        const events = defaultDatabase.getEvents(t.tenantId);
        eventsCount = events.length;

        const incidents = defaultDatabase.getIncidents(t.tenantId);
        incidentsCount = incidents.length;

        if (eventsCount > 0) {
          const aiops = analyzeTenantOps(t.tenantId, { customEvents: events });
          healthScore = aiops.healthScore;
          healthStatus = aiops.healthStatus;
        }
      } catch {
        // Fallback to default
      }

      return {
        ...t,
        healthScore,
        healthStatus,
        eventsCount,
        incidentsCount,
      };
    });

    return NextResponse.json({ total: enriched.length, tenants: enriched }, { status: 200 });
  } catch (error) {
    return NextResponse.json(
      {
        error: 'Failed to retrieve tenants registry',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}

/**
 * POST /api/tenants
 * Dynamically provisions a new tenant partition across the database and telemetry engine.
 * 
 * Body:
 * - tenantId (required): Unique alphanumeric slug
 * - name (required): Enterprise display name
 * - tier (optional): 'pro' | 'enterprise' | 'custom' (default 'enterprise')
 * - region (optional): Primary region (e.g. 'us-east-1', 'eu-west-1')
 * - slaTarget (optional): e.g. '99.99%'
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
        { error: 'tenantId is required to register a tenant' },
        { status: 400 }
      );
    }

    const tenantId = rawTenantId.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    const name = (body.name && typeof body.name === 'string' && body.name.trim())
      ? body.name.trim()
      : tenantId;
    const tier = body.tier || 'enterprise';
    const region = body.region || 'us-east-1';
    const slaTarget = body.slaTarget || '99.99%';

    // 1. Register in Database
    const registered = defaultDatabase.registerTenant({
      tenantId,
      name,
      tier,
      region,
      slaTarget,
      status: 'active',
      metadata: body.metadata || {},
    });

    // 2. Initialize in-memory partition for SaaS engine
    getOrCreateTenantPartition(tenantId);

    return NextResponse.json(
      {
        message: `Tenant '${name}' (${tenantId}) provisioned successfully`,
        tenant: registered,
      },
      { status: 201 }
    );
  } catch (error) {
    return NextResponse.json(
      {
        error: 'Failed to provision tenant',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}
