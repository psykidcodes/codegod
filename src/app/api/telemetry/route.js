import { NextResponse } from 'next/server.js';
import { queryTenant, TenantIsolationError } from '../../../lib/saasEngine.js';

/**
 * GET /api/telemetry
 * Telemetry query endpoint enforcing strict tenant isolation with optional region,
 * severity, and category filtering.
 * 
 * Query parameters:
 * - tenantId (required): Target tenant identifier
 * - region (optional): Telemetry origin region
 * - severity (optional): Severity filter ('low' | 'medium' | 'high' | 'critical')
 * - category (optional): Category filter ('infra' | 'network' | 'security' | 'collector')
 */
export async function GET(request) {
  try {
    const { searchParams } = new URL(request.url);
    const rawTenantId = searchParams.get('tenantId');
    const regionParam = searchParams.get('region');
    const severityParam = searchParams.get('severity');
    const categoryParam = searchParams.get('category');

    // 1. Enforce required tenantId
    if (!rawTenantId || rawTenantId.trim() === '') {
      return NextResponse.json(
        { error: 'tenantId query parameter is required for strict tenant isolation' },
        { status: 400 }
      );
    }

    const tenantId = rawTenantId.trim();
    const region = regionParam && regionParam.trim() !== '' ? regionParam.trim() : null;

    // 2. Query tenant partition from store
    const result = queryTenant(tenantId, region);

    // 3. Apply optional severity and category filters
    let filteredEvents = result.events;

    if (severityParam && severityParam.trim() !== '') {
      const targetSeverity = severityParam.trim();
      filteredEvents = filteredEvents.filter((event) => event.severity === targetSeverity);
    }

    if (categoryParam && categoryParam.trim() !== '') {
      const targetCategory = categoryParam.trim();
      filteredEvents = filteredEvents.filter((event) => event.category === targetCategory);
    }

    // 4. Return tenant telemetry payload
    return NextResponse.json(
      {
        tenantId,
        region: region || 'all',
        ...result,
        events: filteredEvents,
      },
      { status: 200 }
    );
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
