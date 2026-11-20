import { NextResponse } from 'next/server.js';
import { defaultCollector } from '../../../lib/localCollector.js';

/**
 * Helper to extract client IP address from standard request headers.
 */
function getClientIp(request) {
  const forwarded = request.headers.get('x-forwarded-for');
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  const realIp = request.headers.get('x-real-ip');
  if (realIp) {
    return realIp.trim();
  }
  return '127.0.0.1';
}

/**
 * POST /api/collector
 * Local collector ingestion endpoint:
 * - Accepts raw client/user data.
 * - Enforces anti-DDoS, rate limiting, payload size limits, and injection attack shielding.
 * - Detects and neutralizes sensitive credential/PII leaks (DLP).
 * - Strips all raw user data and forwards ONLY operational telemetry metadata.
 */
export async function POST(request) {
  try {
    const clientIp = getClientIp(request);

    // 1. Parse JSON safely
    let body;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: 'Invalid JSON payload' },
        { status: 400 }
      );
    }

    if (!body || (typeof body !== 'object' && !Array.isArray(body))) {
      return NextResponse.json(
        { error: 'Payload must be a JSON object or array' },
        { status: 400 }
      );
    }

    // 2. Handle batch vs single
    const isBatch = Array.isArray(body) || (body && Array.isArray(body.batch));

    if (isBatch) {
      const payloadArray = Array.isArray(body) ? body : body.batch;
      const batchResult = defaultCollector.processBatch(payloadArray, { clientIp });
      return NextResponse.json(batchResult, { status: 200 });
    }

    // Single payload processing
    const result = defaultCollector.processUserInput(body, { clientIp });

    if (result.status === 'blocked') {
      return NextResponse.json(
        {
          error: result.reason,
          attackType: result.attackType,
          status: 'blocked',
          securityEvent: result.securityEvent,
        },
        { status: result.statusCode || 403 }
      );
    }

    return NextResponse.json(
      {
        status: 'accepted',
        payloadId: result.payloadId,
        metadata: result.metadata,
        leaksPrevented: result.leaksPrevented,
        leaksDetails: result.leaksDetails,
        upstreamResult: result.upstreamResult,
      },
      { status: 201 }
    );
  } catch (error) {
    return NextResponse.json(
      {
        error: 'Collector internal processing error',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}

/**
 * GET /api/collector
 * Retrieves local collector health, buffer capacity, and real-time security statistics
 * (DDoS mitigation, injection attacks blocked, PII/credential leaks neutralized).
 */
export async function GET() {
  try {
    const stats = defaultCollector.getSecurityStats();
    return NextResponse.json(
      {
        status: 'online',
        collector: 'local-edge-collector',
        version: '1.0.0',
        timestampUtc: new Date().toISOString(),
        stats,
      },
      { status: 200 }
    );
  } catch (error) {
    return NextResponse.json(
      {
        error: 'Failed to retrieve collector statistics',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}
