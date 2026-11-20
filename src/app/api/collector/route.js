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
    let action = null;
    if (request.url) {
      try {
        const { searchParams } = new URL(request.url);
        action = searchParams.get('action');
      } catch {}
    }

    // Action 1: Toggle simulated upstream outage
    if (action === 'toggle_outage') {
      let body = {};
      try { body = await request.json(); } catch {}
      const isOutageActive = defaultCollector.setOutageMode(body.outage);
      return NextResponse.json({
        status: 'success',
        isOutageActive,
        bufferedCount: defaultCollector.metadataBuffer.length,
        message: isOutageActive
          ? 'Simulated upstream outage activated. Outbound telemetry will buffer locally in RAM.'
          : 'Upstream connection restored. Ready to retry and drain local buffer.',
      }, { status: 200 });
    }

    // Action 2: Drain & Retry local buffer after outage recovery
    if (action === 'flush_buffer' || action === 'retry_buffer') {
      const flushResult = defaultCollector.flushBufferWithRetry();
      return NextResponse.json(flushResult, { status: 200 });
    }

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

    // Action 3: Dedicated Idempotency verification test
    if (action === 'test_idempotency') {
      const result = defaultCollector.processUserInput(body, { clientIp });
      const isDuplicate = result.upstreamResult?.status === 'duplicate' || result.upstreamResult?.status === 'duplicate_blocked' || result.upstreamResult?.duplicate === true;
      return NextResponse.json({
        status: isDuplicate ? 'duplicate_blocked' : 'accepted',
        payloadId: result.payloadId,
        duplicate: isDuplicate,
        upstreamResult: result.upstreamResult,
        auditMessage: isDuplicate
          ? `Deterministic payload ${result.payloadId} blocked as duplicate. Zero duplicate database rows written.`
          : `Payload ${result.payloadId} successfully accepted and ingested.`,
      }, { status: isDuplicate ? 200 : 201 });
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
