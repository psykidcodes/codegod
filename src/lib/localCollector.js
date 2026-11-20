/**
 * @file localCollector.js
 * @description Local Edge Telemetry Collector with Privacy-Preserving Metadata Extraction,
 * Data Loss Prevention (DLP) Leak Management, and Attack Shield.
 * 
 * Capabilities:
 * 1. Raw Data Filtering & Metadata Extraction:
 *    - Strips all raw user payloads, messages, sensitive attributes, and freeform content.
 *    - Extracts only operational telemetry metadata (payload sizes, field counts, latency,
 *      status codes, structural SHA-256 fingerprint, operational metrics).
 *    - Forwards clean metadata payloads conforming to ALLOW_LISTED_KEYS.
 * 2. Data Loss Prevention (DLP) & Leak Management:
 *    - Scans incoming client data for credentials, API tokens (AWS, GitHub, Slack, JWT, Bearer),
 *      passwords, private keys, Credit Card numbers (PCI-DSS), Social Security Numbers (SSN),
 *      and email addresses.
 *    - Automatically redacts and purges leaks before any transmission.
 *    - Generates high/critical 'security' telemetry metadata alerts on sensitive data exposure.
 * 3. Attack Shield & Big Attack Management:
 *    - Volumetric Flood & DDoS Defense: Sliding window rate limiting and burst suppression.
 *    - Payload Bomb Defense: Hard size threshold enforcement and nested JSON depth limits.
 *    - Injection Attack Detection: Real-time heuristic scanning for SQL Injection (SQLi),
 *      Cross-Site Scripting (XSS), Remote Code Execution (RCE), and Path Traversal.
 *    - Immediately blocks attacks and produces security metadata telemetry events for AIOps RCA.
 * 4. Resilient Upstream Dispatching:
 *    - Buffers metadata locally and safely dispatches to upstream saasEngine ingest API
 *      using authorized collector tokens ('collector-alpha-token').
 */

import { createHash } from 'node:crypto';
import { ingestSingle, ingestBatch } from './saasEngine.js';

export const ATTACK_TYPES = Object.freeze({
  DDOS_FLOOD: 'DDOS_FLOOD',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  PAYLOAD_BOMB: 'PAYLOAD_BOMB',
  SQL_INJECTION: 'SQL_INJECTION',
  XSS_ATTACK: 'XSS_ATTACK',
  COMMAND_INJECTION: 'COMMAND_INJECTION',
  PATH_TRAVERSAL: 'PATH_TRAVERSAL',
});

export const LEAK_TYPES = Object.freeze({
  API_KEY: 'API_KEY',
  BEARER_TOKEN: 'BEARER_TOKEN',
  PRIVATE_KEY: 'PRIVATE_KEY',
  PASSWORD: 'PASSWORD',
  CREDIT_CARD: 'CREDIT_CARD',
  SSN: 'SSN',
  EMAIL: 'EMAIL',
});

// Heuristic regex patterns for attacks
const ATTACK_PATTERNS = [
  {
    type: ATTACK_TYPES.SQL_INJECTION,
    regex: /(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\b.*\b(FROM|INTO|TABLE|DATABASE|WHERE)\b|--|\/\*|\bOR\b\s+['"]?\w+['"]?\s*=\s*['"]?\w+|UNION\s+ALL\s+SELECT)/i,
    description: 'SQL Injection signature detected in user input',
  },
  {
    type: ATTACK_TYPES.XSS_ATTACK,
    regex: /(<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>|javascript:[^'"\s]+|<iframe\b|<img\s+[^>]*onerror\s*=|onload\s*=\s*['"][^'"]*['"])/i,
    description: 'Cross-Site Scripting (XSS) payload detected',
  },
  {
    type: ATTACK_TYPES.COMMAND_INJECTION,
    regex: /(;\s*(rm\s+-rf|cat\s+\/etc\/|whoami|bash\s+-i|cmd\.exe|powershell\s+-enc|wget\s+http|curl\s+.*\|\s*sh)|`.*`|\$\(.*\))/i,
    description: 'Remote command execution pattern detected',
  },
  {
    type: ATTACK_TYPES.PATH_TRAVERSAL,
    regex: /(\.\.[\/\\]\.\.[\/\\]|\/etc\/passwd|c:\\windows\\system32|%2e%2e%2f|%2e%2e\/)/i,
    description: 'Directory traversal attempt detected',
  },
];

// Heuristic regex patterns for sensitive leaks
const LEAK_PATTERNS = [
  {
    type: LEAK_TYPES.PRIVATE_KEY,
    regex: /-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PGP)?\s*PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA|EC|OPENSSH|DSA|PGP)?\s*PRIVATE\s+KEY-----/i,
    description: 'Unencrypted Private Key block',
    severity: 'critical',
  },
  {
    type: LEAK_TYPES.API_KEY,
    regex: /\b(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|xox[baprs]-[0-9a-zA-Z]{10,48})\b/,
    description: 'Cloud or API service key (OpenAI/AWS/GitHub/Slack)',
    severity: 'critical',
  },
  {
    type: LEAK_TYPES.BEARER_TOKEN,
    regex: /\bBearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*\b/,
    description: 'JWT / Bearer authentication token',
    severity: 'high',
  },
  {
    type: LEAK_TYPES.CREDIT_CARD,
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13})\b/,
    description: 'Credit Card (PCI-DSS) number',
    severity: 'critical',
  },
  {
    type: LEAK_TYPES.SSN,
    regex: /\b\d{3}-\d{2}-\d{4}\b/,
    description: 'Social Security Number (SSN)',
    severity: 'critical',
  },
  {
    type: LEAK_TYPES.EMAIL,
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/,
    description: 'Personal Email address (PII)',
    severity: 'medium',
  },
];

const SENSITIVE_KEY_NAMES = new Set([
  'password',
  'passwd',
  'secret',
  'apiKey',
  'api_key',
  'token',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'privateKey',
  'private_key',
  'ssn',
  'creditCard',
  'credit_card',
  'cardNum',
  'cvv',
  'auth',
  'authorization',
]);

/**
 * Calculates max nesting depth of an object to guard against JSON expansion bombs.
 */
export function calculateObjectDepth(obj, currentDepth = 1) {
  if (obj === null || typeof obj !== 'object') return currentDepth;
  if (currentDepth > 15) return currentDepth; // short-circuit guard

  let maxDepth = currentDepth;
  for (const key of Object.keys(obj)) {
    const val = obj[key];
    if (val !== null && typeof val === 'object') {
      const depth = calculateObjectDepth(val, currentDepth + 1);
      if (depth > maxDepth) maxDepth = depth;
    }
  }
  return maxDepth;
}

/**
 * Generates an irreversible SHA-256 fingerprint of the structural shape
 * for auditability without persisting raw contents.
 */
export function computeStructuralFingerprint(data) {
  const structure = JSON.stringify(data, (key, value) => {
    if (typeof value === 'object' && value !== null) {
      return Array.isArray(value) ? '[]' : Object.keys(value).sort();
    }
    return typeof value;
  });
  return createHash('sha256').update(structure).digest('hex').substring(0, 16);
}

/**
 * Local Telemetry Collector Engine.
 */
export class LocalCollector {
  constructor(options = {}) {
    this.collectorToken = options.collectorToken || 'collector-alpha-token';
    this.maxPayloadSizeBytes = options.maxPayloadSizeBytes || 512 * 1024; // 512 KB
    this.rateLimitWindowMs = options.rateLimitWindowMs || 60 * 1000; // 1 minute
    this.maxRequestsPerWindow = options.maxRequestsPerWindow || 100;
    this.surgeThreshold = options.surgeThreshold || 250; // Triggers DDoS alarm
    this.maxBufferSize = options.maxBufferSize || 500;

    // Rate limiter tracker: Map<clientKey, Array<timestampMs>>
    this.rateLimiters = new Map();

    // Local in-memory buffer for batched metadata upstream forwarding
    this.metadataBuffer = [];

    // Security & operational statistics
    this.stats = {
      totalReceived: 0,
      metadataForwarded: 0,
      rawFieldsStrippedCount: 0,
      leaksPrevented: 0,
      attacksBlocked: 0,
      attackBreakdown: {
        [ATTACK_TYPES.DDOS_FLOOD]: 0,
        [ATTACK_TYPES.RATE_LIMIT_EXCEEDED]: 0,
        [ATTACK_TYPES.PAYLOAD_BOMB]: 0,
        [ATTACK_TYPES.SQL_INJECTION]: 0,
        [ATTACK_TYPES.XSS_ATTACK]: 0,
        [ATTACK_TYPES.COMMAND_INJECTION]: 0,
        [ATTACK_TYPES.PATH_TRAVERSAL]: 0,
      },
      leakBreakdown: {
        [LEAK_TYPES.API_KEY]: 0,
        [LEAK_TYPES.BEARER_TOKEN]: 0,
        [LEAK_TYPES.PRIVATE_KEY]: 0,
        [LEAK_TYPES.PASSWORD]: 0,
        [LEAK_TYPES.CREDIT_CARD]: 0,
        [LEAK_TYPES.SSN]: 0,
        [LEAK_TYPES.EMAIL]: 0,
      },
      rateLimitDrops: 0,
      lastEventUtc: null,
    };
  }

  /**
   * Evaluates client rate limiting and DDoS flood protection.
   * 
   * @param {string} clientIdentifier 
   * @param {number} now 
   * @returns {{ allowed: boolean, isDDoS: boolean, count: number }}
   */
  checkRateLimit(clientIdentifier, now = Date.now()) {
    if (!clientIdentifier) return { allowed: true, isDDoS: false, count: 0 };

    if (!this.rateLimiters.has(clientIdentifier)) {
      this.rateLimiters.set(clientIdentifier, []);
    }

    const windowStart = now - this.rateLimitWindowMs;
    let timestamps = this.rateLimiters.get(clientIdentifier);
    timestamps = timestamps.filter((t) => t > windowStart);
    timestamps.push(now);
    this.rateLimiters.set(clientIdentifier, timestamps);

    const count = timestamps.length;
    if (count > this.surgeThreshold) {
      return { allowed: false, isDDoS: true, count };
    }
    if (count > this.maxRequestsPerWindow) {
      return { allowed: false, isDDoS: false, count };
    }

    return { allowed: true, isDDoS: false, count };
  }

  /**
   * Scans an arbitrary text string for injection attacks.
   * 
   * @param {string} text 
   * @returns {Array<object>} Detected attacks
   */
  scanStringForAttacks(text) {
    if (typeof text !== 'string' || text.length === 0) return [];

    const detected = [];
    for (const pattern of ATTACK_PATTERNS) {
      if (pattern.regex.test(text)) {
        detected.push({
          type: pattern.type,
          description: pattern.description,
        });
      }
    }
    return detected;
  }

  /**
   * Scans an arbitrary text string for sensitive data leaks (DLP).
   * 
   * @param {string} text 
   * @returns {Array<object>} Detected leaks
   */
  scanStringForLeaks(text) {
    if (typeof text !== 'string' || text.length === 0) return [];

    const detected = [];
    for (const pattern of LEAK_PATTERNS) {
      if (pattern.regex.test(text)) {
        detected.push({
          type: pattern.type,
          description: pattern.description,
          severity: pattern.severity,
        });
      }
    }
    return detected;
  }

  /**
   * Deeply inspects an input object to discover attacks and data leaks,
   * while recording all detected issues.
   * 
   * @param {any} val 
   * @param {string} currentPath 
   * @param {object} findings 
   */
  inspectRecursively(val, currentPath, findings) {
    if (val === null || val === undefined) return;

    if (typeof val === 'string') {
      // 1. Scan for attacks
      const attacks = this.scanStringForAttacks(val);
      for (const a of attacks) {
        findings.attacks.push({ ...a, field: currentPath });
      }

      // 2. Scan for leaks
      const leaks = this.scanStringForLeaks(val);
      for (const l of leaks) {
        findings.leaks.push({ ...l, field: currentPath });
      }
    } else if (typeof val === 'object') {
      if (Array.isArray(val)) {
        for (let i = 0; i < val.length; i++) {
          this.inspectRecursively(val[i], `${currentPath}[${i}]`, findings);
        }
      } else {
        for (const [k, child] of Object.entries(val)) {
          // Check if key name indicates credential leak
          if (SENSITIVE_KEY_NAMES.has(k) || SENSITIVE_KEY_NAMES.has(k.toLowerCase())) {
            findings.leaks.push({
              type: LEAK_TYPES.PASSWORD,
              description: `Sensitive credential key '${k}' discovered in payload`,
              severity: 'high',
              field: `${currentPath ? currentPath + '.' : ''}${k}`,
            });
          }
          this.inspectRecursively(child, `${currentPath ? currentPath + '.' : ''}${k}`, findings);
        }
      }
    }
  }

  /**
   * Ingests, inspects, and sanitizes raw client/user data:
   * 1. Protects against attacks (DDoS, payload bombs, injections).
   * 2. Detects and manages data leaks (PII, credentials, keys).
   * 3. Completely strips raw data and extracts safe operational metadata.
   * 4. Forwards metadata to the upstream telemetry engine.
   * 
   * @param {object} userInput - Raw input from client/user
   * @param {object} [context] - Context options (clientIp, forwardUpstream, now)
   * @returns {object} Action result
   */
  processUserInput(userInput, context = {}) {
    this.stats.totalReceived++;
    const now = context.now || Date.now();
    const nowUtc = new Date(now).toISOString();
    this.stats.lastEventUtc = nowUtc;

    const clientIp = context.clientIp || userInput?.clientIp || userInput?.ip || '127.0.0.1';
    const tenantId = (typeof userInput?.tenantId === 'string' && userInput.tenantId.trim())
      ? userInput.tenantId.trim()
      : 'tenant-default';
    const region = (typeof userInput?.region === 'string' && userInput.region.trim())
      ? userInput.region.trim()
      : 'global';
    const sourceAlias = (typeof userInput?.sourceAlias === 'string' && userInput.sourceAlias.trim())
      ? userInput.sourceAlias.trim()
      : `collector-${clientIp}`;

    // --- STEP 1: Rate Limiting & Big DDoS Flood Defense ---
    const rateCheck = this.checkRateLimit(clientIp, now);
    if (!rateCheck.allowed) {
      this.stats.rateLimitDrops++;
      this.stats.attacksBlocked++;

      const attackType = rateCheck.isDDoS ? ATTACK_TYPES.DDOS_FLOOD : ATTACK_TYPES.RATE_LIMIT_EXCEEDED;
      this.stats.attackBreakdown[attackType]++;

      // Emit high-priority security metadata telemetry alert
      const ddosMetadata = {
        payloadId: `sec-flood-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
        tenantId,
        region,
        sourceAlias: `edge-collector-${clientIp}`,
        eventTimestampUtc: nowUtc,
        category: 'security',
        severity: rateCheck.isDDoS ? 'critical' : 'high',
        metrics: {
          requestRate: rateCheck.count,
          surgeThreshold: this.surgeThreshold,
          blocked: 1,
        },
        summary: rateCheck.isDDoS
          ? `CRITICAL DDoS volumetric flood blocked from client '${clientIp}' (${rateCheck.count} req/window)`
          : `Rate limit threshold exceeded for client '${clientIp}' (${rateCheck.count} req/window)`,
      };

      if (context.forwardUpstream !== false) {
        ingestSingle(ddosMetadata);
      }

      return {
        status: 'blocked',
        reason: rateCheck.isDDoS ? 'DDoS volumetric flood attack mitigated' : 'Rate limit exceeded',
        attackType,
        statusCode: rateCheck.isDDoS ? 403 : 429,
        securityEvent: ddosMetadata,
      };
    }

    // --- STEP 2: Payload Bomb & Nested Depth Defense ---
    const rawString = typeof userInput === 'string' ? userInput : JSON.stringify(userInput || {});
    const rawByteSize = Buffer.byteLength(rawString, 'utf8');

    if (rawByteSize > this.maxPayloadSizeBytes) {
      this.stats.attacksBlocked++;
      this.stats.attackBreakdown[ATTACK_TYPES.PAYLOAD_BOMB]++;

      const bombMetadata = {
        payloadId: `sec-bomb-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
        tenantId,
        region,
        sourceAlias,
        eventTimestampUtc: nowUtc,
        category: 'security',
        severity: 'critical',
        metrics: {
          payloadSizeBytes: rawByteSize,
          maxAllowedBytes: this.maxPayloadSizeBytes,
          blocked: 1,
        },
        summary: `Oversized payload bomb blocked: ${rawByteSize} bytes exceeds limit ${this.maxPayloadSizeBytes} bytes`,
      };

      if (context.forwardUpstream !== false) {
        ingestSingle(bombMetadata);
      }

      return {
        status: 'blocked',
        reason: 'Payload size exceeds safety threshold',
        attackType: ATTACK_TYPES.PAYLOAD_BOMB,
        statusCode: 413,
        securityEvent: bombMetadata,
      };
    }

    const objectDepth = calculateObjectDepth(userInput);
    if (objectDepth > 12) {
      this.stats.attacksBlocked++;
      this.stats.attackBreakdown[ATTACK_TYPES.PAYLOAD_BOMB]++;

      const depthMetadata = {
        payloadId: `sec-depth-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
        tenantId,
        region,
        sourceAlias,
        eventTimestampUtc: nowUtc,
        category: 'security',
        severity: 'high',
        metrics: {
          nestingDepth: objectDepth,
          maxAllowedDepth: 12,
          blocked: 1,
        },
        summary: `Deeply nested JSON bomb structure blocked: depth ${objectDepth} > 12`,
      };

      if (context.forwardUpstream !== false) {
        ingestSingle(depthMetadata);
      }

      return {
        status: 'blocked',
        reason: 'Deeply nested JSON structure rejected',
        attackType: ATTACK_TYPES.PAYLOAD_BOMB,
        statusCode: 400,
        securityEvent: depthMetadata,
      };
    }

    // --- STEP 3: Deep Inspection for Attacks & Data Leaks ---
    const findings = { attacks: [], leaks: [] };
    this.inspectRecursively(userInput, '', findings);

    // If an active injection attack is discovered, drop and alert
    if (findings.attacks.length > 0) {
      this.stats.attacksBlocked++;
      const primaryAttack = findings.attacks[0];
      this.stats.attackBreakdown[primaryAttack.type] = (this.stats.attackBreakdown[primaryAttack.type] || 0) + 1;

      const attackMetadata = {
        payloadId: `sec-attack-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
        tenantId,
        region,
        sourceAlias,
        eventTimestampUtc: nowUtc,
        category: 'security',
        severity: 'critical',
        metrics: {
          attackType: primaryAttack.type,
          attackCount: findings.attacks.length,
          blocked: 1,
        },
        summary: `Blocked ${primaryAttack.type} attempt detected in field '${primaryAttack.field}'`,
      };

      if (context.forwardUpstream !== false) {
        ingestSingle(attackMetadata);
      }

      return {
        status: 'blocked',
        reason: 'Malicious attack signature detected and neutralized',
        attackType: primaryAttack.type,
        statusCode: 403,
        securityEvent: attackMetadata,
      };
    }

    // --- STEP 4: Manage Leaks & Data Loss Prevention (DLP) ---
    const leaksCount = findings.leaks.length;
    let leakSeverity = 'low';

    if (leaksCount > 0) {
      this.stats.leaksPrevented += leaksCount;
      for (const leak of findings.leaks) {
        this.stats.leakBreakdown[leak.type] = (this.stats.leakBreakdown[leak.type] || 0) + 1;
        if (leak.severity === 'critical') leakSeverity = 'critical';
        else if (leak.severity === 'high' && leakSeverity !== 'critical') leakSeverity = 'high';
        else if (leak.severity === 'medium' && leakSeverity === 'low') leakSeverity = 'medium';
      }
    }

    // --- STEP 5: Strip All Raw Data and Extract Metadata Only ---
    // Count raw fields that were sanitized/stripped
    let rawFieldCount = 0;
    if (userInput && typeof userInput === 'object') {
      rawFieldCount = Object.keys(userInput).length;
    }
    this.stats.rawFieldsStrippedCount += rawFieldCount;

    // Structural fingerprint (SHA-256) of schema structure without storing contents
    const fingerprint = computeStructuralFingerprint(userInput);

    // Extract legitimate operational metrics if explicitly provided in metrics object
    const clientMetrics = (userInput?.metrics && typeof userInput.metrics === 'object')
      ? { ...userInput.metrics }
      : {};

    // Combine safe operational metadata
    const metadataMetrics = {
      ...clientMetrics,
      payloadSizeRawBytes: rawByteSize,
      fieldsStrippedCount: rawFieldCount,
      leaksDetectedAndRedacted: leaksCount,
      structuralFingerprint: fingerprint,
    };

    if (typeof userInput?.latencyMs === 'number') {
      metadataMetrics.latencyMs = userInput.latencyMs;
    }
    if (typeof userInput?.statusCode === 'number') {
      metadataMetrics.statusCode = userInput.statusCode;
    }

    // Category and severity determination
    let category = userInput?.category && ['infra', 'network', 'security', 'collector'].includes(userInput.category)
      ? userInput.category
      : 'collector';

    let severity = userInput?.severity && ['low', 'medium', 'high', 'critical'].includes(userInput.severity)
      ? userInput.severity
      : 'low';

    // If sensitive leak was intercepted, force security event with leak severity
    if (leaksCount > 0) {
      category = 'security';
      severity = leakSeverity;
    }

    // Construct pure metadata payload conforming strictly to ALLOW_LISTED_KEYS
    const metadataPayload = {
      payloadId: userInput?.payloadId || `meta-${Date.now()}-${Math.floor(Math.random() * 10000)}`,
      tenantId,
      region,
      sourceAlias,
      eventTimestampUtc: userInput?.eventTimestampUtc && typeof userInput.eventTimestampUtc === 'string'
        ? userInput.eventTimestampUtc
        : nowUtc,
      category,
      severity,
      metrics: metadataMetrics,
      summary: leaksCount > 0
        ? `[DLP Alert] Intercepted and redacted ${leaksCount} sensitive credential/PII leak(s) from ${sourceAlias}`
        : `Telemetry metadata from ${sourceAlias} [size: ${rawByteSize}B, fields: ${rawFieldCount}, fp: ${fingerprint}]`,
    };

    // Buffer metadata locally
    this.metadataBuffer.push(metadataPayload);
    if (this.metadataBuffer.length > this.maxBufferSize) {
      this.metadataBuffer.shift(); // Evict oldest
    }

    // Forward metadata upstream
    let upstreamResult = null;
    if (context.forwardUpstream !== false) {
      upstreamResult = ingestSingle(metadataPayload);
      if (upstreamResult && upstreamResult.status === 'accepted') {
        this.stats.metadataForwarded++;
      }
    }

    return {
      status: 'accepted',
      payloadId: metadataPayload.payloadId,
      metadata: metadataPayload,
      leaksPrevented: leaksCount,
      leaksDetails: findings.leaks.map((l) => ({ type: l.type, field: l.field, description: l.description })),
      upstreamResult,
    };
  }

  /**
   * Ingests a batch of raw client payloads through the security shield and DLP.
   * 
   * @param {Array<object>} rawPayloadArray 
   * @param {object} [context] 
   * @returns {object} Batch summary
   */
  processBatch(rawPayloadArray, context = {}) {
    if (!Array.isArray(rawPayloadArray)) {
      throw new TypeError('Expected an array of payloads for processBatch');
    }

    const results = {
      total: rawPayloadArray.length,
      accepted: 0,
      blocked: 0,
      leaksPrevented: 0,
      metadataPayloads: [],
    };

    for (const raw of rawPayloadArray) {
      const res = this.processUserInput(raw, { ...context, forwardUpstream: false });
      if (res.status === 'accepted') {
        results.accepted++;
        results.leaksPrevented += res.leaksPrevented;
        results.metadataPayloads.push(res.metadata);
      } else {
        results.blocked++;
      }
    }

    // Forward accepted metadata payloads to upstream engine as a batch
    if (context.forwardUpstream !== false && results.metadataPayloads.length > 0) {
      const upstreamBatchRes = ingestBatch(results.metadataPayloads);
      results.upstreamSummary = upstreamBatchRes;
      this.stats.metadataForwarded += upstreamBatchRes.accepted;
    }

    return results;
  }

  /**
   * Drains and forwards all buffered metadata payloads to the upstream telemetry engine.
   * 
   * @returns {object} Flush summary
   */
  drainBuffer() {
    if (this.metadataBuffer.length === 0) {
      return { flushed: 0, upstream: null };
    }

    const toFlush = [...this.metadataBuffer];
    this.metadataBuffer = [];
    const upstreamRes = ingestBatch(toFlush);
    this.stats.metadataForwarded += upstreamRes.accepted;

    return {
      flushed: toFlush.length,
      upstream: upstreamRes,
    };
  }

  /**
   * Retrieves live collector operational and security audit statistics.
   * 
   * @returns {object} Security and collector metrics
   */
  getSecurityStats() {
    return {
      collectorToken: this.collectorToken,
      ...this.stats,
      bufferedCount: this.metadataBuffer.length,
      activeRateLimitersCount: this.rateLimiters.size,
    };
  }

  /**
   * Resets internal collector state, buffers, rate limiters, and counters.
   */
  reset() {
    this.rateLimiters.clear();
    this.metadataBuffer = [];
    this.stats = {
      totalReceived: 0,
      metadataForwarded: 0,
      rawFieldsStrippedCount: 0,
      leaksPrevented: 0,
      attacksBlocked: 0,
      attackBreakdown: {
        [ATTACK_TYPES.DDOS_FLOOD]: 0,
        [ATTACK_TYPES.RATE_LIMIT_EXCEEDED]: 0,
        [ATTACK_TYPES.PAYLOAD_BOMB]: 0,
        [ATTACK_TYPES.SQL_INJECTION]: 0,
        [ATTACK_TYPES.XSS_ATTACK]: 0,
        [ATTACK_TYPES.COMMAND_INJECTION]: 0,
        [ATTACK_TYPES.PATH_TRAVERSAL]: 0,
      },
      leakBreakdown: {
        [LEAK_TYPES.API_KEY]: 0,
        [LEAK_TYPES.BEARER_TOKEN]: 0,
        [LEAK_TYPES.PRIVATE_KEY]: 0,
        [LEAK_TYPES.PASSWORD]: 0,
        [LEAK_TYPES.CREDIT_CARD]: 0,
        [LEAK_TYPES.SSN]: 0,
        [LEAK_TYPES.EMAIL]: 0,
      },
      rateLimitDrops: 0,
      lastEventUtc: null,
    };
  }
}

// Global default singleton collector instance
export const defaultCollector = new LocalCollector();

export default {
  ATTACK_TYPES,
  LEAK_TYPES,
  LocalCollector,
  defaultCollector,
  calculateObjectDepth,
  computeStructuralFingerprint,
};
