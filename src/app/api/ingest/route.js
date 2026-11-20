import { NextResponse } from 'next/server.js';
import { ingestSingle, ingestBatch } from '../../../lib/saasEngine.js';

const AUTHORIZED_COLLECTOR_TOKENS = new Set([
  'collector-alpha-token',
  'collector-beta-token',
]);

/**
 * POST /api/ingest
 * Ingestion endpoint for single or batch telemetry payloads from authorized collectors.
 * 
 * Headers:
 * - x-collector-token: 'collector-alpha-token' | 'collector-beta-token'
 * 
 * Body:
 * - Single telemetry payload object
 * - Or Array of payloads / { batch: [...] } for buffered outage recovery
 */
export async function POST(request) {
  try {
    // 1. Authenticate collector token
    const token = request.headers.get('x-collector-token');
    if (!token || !AUTHORIZED_COLLECTOR_TOKENS.has(token)) {
      return NextResponse.json(
        { error: 'Unauthorized collector token' },
        { status: 401 }
      );
    }

    // 2. Parse JSON body safely
    let body;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: 'Invalid JSON payload' },
        { status: 400 }
      );
    }

    // 3. Process Batch vs Single
    // Batch processing: array or { batch: [...] }
    const isArrayBatch = Array.isArray(body);
    const isObjectBatch = body && typeof body === 'object' && Array.isArray(body.batch);

    if (isArrayBatch || isObjectBatch) {
      const payloadArray = isArrayBatch ? body : body.batch;
      const batchSummary = ingestBatch(payloadArray);
      return NextResponse.json(batchSummary, { status: 200 });
    }

    // Single payload processing
    const singleResult = ingestSingle(body);

    if (singleResult.status === 'accepted') {
      return NextResponse.json(singleResult, { status: 201 });
    }

    if (singleResult.status === 'duplicate') {
      return NextResponse.json(singleResult, { status: 200 });
    }

    if (singleResult.status === 'rejected') {
      return NextResponse.json(singleResult, { status: 400 });
    }

    // Fallback for unexpected status
    return NextResponse.json(singleResult, { status: 400 });
  } catch (error) {
    return NextResponse.json(
      {
        error: 'Internal server error',
        message: error instanceof Error ? error.message : String(error),
      },
      { status: 500 }
    );
  }
}
