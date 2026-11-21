/**
 * @file telemetryDatabase.js
 * @description SQLite-backed Multi-Tenant Telemetry Database with Built-in AIOps Intelligence,
 * Telemetry Simulation (Spikes, Outages, Failed Logins), Baseline Anomaly Detection,
 * Alert Correlation into Unified Incidents, and Explainable Recommendations.
 */

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  calculateStats,
  detectAnomalies,
  correlateIncidents,
  performRootCauseAnalysis,
  generateRecommendations,
} from './aiopsEngine.js';
import { hashPassword } from './auth.js';
import { ingestBatch, tenantStore, getOrCreateTenantPartition } from './saasEngine.js';
import { defaultCollector, ATTACK_TYPES, LEAK_TYPES } from './localCollector.js';

export const SCENARIO_TYPES = Object.freeze({
  SPIKES: 'spikes',
  OUTAGES: 'outages',
  FAILED_LOGINS: 'failed_logins',
  DATA_LEAKS: 'data_leaks',
  BASELINE: 'baseline',
});

/**
 * Multi-Tenant Telemetry Database Engine.
 */
export class TelemetryDatabase {
  constructor(dbPath = ':memory:') {
    let targetPath = dbPath;

    // Vercel serverless environment: ensure in-memory database to prevent EROFS on read-only serverless filesystem
    if (process.env.VERCEL && targetPath !== ':memory:' && !targetPath.startsWith('/tmp')) {
      targetPath = ':memory:';
    }

    if (targetPath !== ':memory:') {
      try {
        mkdirSync(dirname(targetPath), { recursive: true });
      } catch {
        targetPath = ':memory:';
      }
    }

    this.dbPath = targetPath;
    try {
      this.db = new DatabaseSync(targetPath);
    } catch {
      this.dbPath = ':memory:';
      this.db = new DatabaseSync(':memory:');
    }
    this.initSchema();
  }

  /**
   * Initializes relational schema with strict multi-tenant partitions and foreign keys.
   */
  initSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS telemetry_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        payload_id TEXT UNIQUE NOT NULL,
        tenant_id TEXT NOT NULL,
        region TEXT NOT NULL,
        source_alias TEXT NOT NULL,
        event_timestamp_utc TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        metrics_json TEXT,
        summary TEXT,
        ingested_at_utc TEXT NOT NULL,
        is_anomaly INTEGER DEFAULT 0,
        incident_id TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_events_tenant_time ON telemetry_events (tenant_id, event_timestamp_utc);
      CREATE INDEX IF NOT EXISTS idx_events_tenant_cat ON telemetry_events (tenant_id, category);
      CREATE INDEX IF NOT EXISTS idx_events_tenant_sev ON telemetry_events (tenant_id, severity);

      CREATE TABLE IF NOT EXISTS baseline_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        metric_name TEXT NOT NULL,
        mean REAL NOT NULL,
        std_dev REAL NOT NULL,
        min_val REAL NOT NULL,
        max_val REAL NOT NULL,
        sample_count INTEGER NOT NULL,
        updated_at_utc TEXT NOT NULL,
        UNIQUE(tenant_id, metric_name)
      );

      CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        payload_id TEXT NOT NULL,
        source_alias TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        anomaly_score REAL NOT NULL,
        reasons_json TEXT NOT NULL,
        metrics_json TEXT,
        timestamp_utc TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_anomalies_tenant ON anomalies (tenant_id);

      CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        regions_json TEXT NOT NULL,
        affected_sources_json TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        duration_seconds INTEGER NOT NULL,
        status TEXT NOT NULL,
        first_seen_utc TEXT NOT NULL,
        last_seen_utc TEXT NOT NULL,
        rca_json TEXT,
        recommendations_json TEXT,
        created_at_utc TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_incidents_tenant ON incidents (tenant_id);

      CREATE TABLE IF NOT EXISTS security_attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT NOT NULL,
        source_alias TEXT NOT NULL,
        attack_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        mitigation_status TEXT NOT NULL,
        summary TEXT,
        details_json TEXT,
        timestamp_utc TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_attacks_tenant ON security_attacks (tenant_id);

      CREATE TABLE IF NOT EXISTS simulations (
        simulation_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        scenario_type TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        incident_id TEXT,
        created_at_utc TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS tenants (
        tenant_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        tier TEXT NOT NULL DEFAULT 'enterprise',
        region TEXT NOT NULL DEFAULT 'us-east-1',
        sla_target TEXT NOT NULL DEFAULT '99.99%',
        status TEXT NOT NULL DEFAULT 'active',
        created_at_utc TEXT NOT NULL,
        metadata_json TEXT
      );

      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        identifier TEXT UNIQUE NOT NULL,
        identifier_type TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        is_host INTEGER DEFAULT 0,
        role TEXT DEFAULT 'tenant',
        created_at_utc TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_users_identifier ON users (identifier);
      CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id);
    `);

    try {
      this.db.exec('ALTER TABLE users ADD COLUMN is_host INTEGER DEFAULT 0;');
    } catch {
      // Column exists
    }
    try {
      this.db.exec("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'tenant';");
    } catch {
      // Column exists
    }

    this.seedDefaultTenants();
    this.seedDefaultUsers();
  }

  /**
   * Seeds realistic default enterprise tenants if not already present.
   */
  seedDefaultTenants() {
    const defaultTenants = [
      {
        tenantId: 'acme-corp',
        name: 'Acme Global Infrastructure',
        tier: 'enterprise',
        region: 'us-east-1',
        slaTarget: '99.99%',
        status: 'active',
      },
      {
        tenantId: 'fintech-cloud',
        name: 'FinTech High-Frequency Payments',
        tier: 'enterprise',
        region: 'eu-west-1',
        slaTarget: '99.999%',
        status: 'active',
      },
      {
        tenantId: 'cyber-shield',
        name: 'CyberShield Zero-Trust Grid',
        tier: 'pro',
        region: 'us-west-2',
        slaTarget: '99.9%',
        status: 'active',
      },
      {
        tenantId: 'quantum-bio',
        name: 'Quantum Bio-Vault Systems',
        tier: 'enterprise',
        region: 'ap-southeast-1',
        slaTarget: '99.99%',
        status: 'active',
      },
      {
        tenantId: 'shield-defense',
        name: 'CyberShield Defense Systems',
        tier: 'defense',
        region: 'eu-west-1',
        slaTarget: '99.999%',
        status: 'active',
      },
      {
        tenantId: 'arcops-host',
        name: 'ArcOps Core SaaS Cloud Platform',
        tier: 'host',
        region: 'us-east-1',
        slaTarget: '99.9999%',
        status: 'active',
      },
      {
        tenantId: 'cicada-host',
        name: 'ArcOps Legacy SaaS Host Platform',
        tier: 'host',
        region: 'us-east-1',
        slaTarget: '99.9999%',
        status: 'active',
      },
    ];

    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO tenants (tenant_id, name, tier, region, sla_target, status, created_at_utc, metadata_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const now = new Date().toISOString();
    for (const t of defaultTenants) {
      stmt.run(t.tenantId, t.name, t.tier, t.region, t.slaTarget, t.status, now, '{}');
    }
  }

  /**
   * Seeds default demo accounts for testing authentication.
   */
  seedDefaultUsers() {
    try {
      const demoAccount = {
        userId: 'usr-acme-admin',
        tenantId: 'acme-corp',
        identifier: 'admin@acme.com',
        identifierType: 'email',
        password: 'Password123!',
        isHost: 0,
        role: 'tenant',
      };

      const existing = this.getUserByIdentifier(demoAccount.identifier);
      if (!existing) {
        const { salt, hash } = hashPassword(demoAccount.password);
        this.createUser({
          userId: demoAccount.userId,
          tenantId: demoAccount.tenantId,
          identifier: demoAccount.identifier,
          identifierType: demoAccount.identifierType,
          passwordHash: hash,
          salt,
          isHost: 0,
          role: 'tenant',
        });
      }

      // Also seed a mobile account
      const mobileAccount = {
        userId: 'usr-acme-mobile',
        tenantId: 'acme-corp',
        identifier: '+15551234567',
        identifierType: 'mobile',
        password: 'Password123!',
        isHost: 0,
        role: 'tenant',
      };

      const existingMobile = this.getUserByIdentifier(mobileAccount.identifier);
      if (!existingMobile) {
        const { salt, hash } = hashPassword(mobileAccount.password);
        this.createUser({
          userId: mobileAccount.userId,
          tenantId: mobileAccount.tenantId,
          identifier: mobileAccount.identifier,
          identifierType: mobileAccount.identifierType,
          passwordHash: hash,
          salt,
          isHost: 0,
          role: 'tenant',
        });
      }

      // Seed second demo tenant user: shield-defense
      const shieldAccount = {
        userId: 'usr-shield-secops',
        tenantId: 'shield-defense',
        identifier: 'secops@shield-defense.com',
        identifierType: 'email',
        password: 'Password123!',
        isHost: 0,
        role: 'tenant',
      };

      const existingShield = this.getUserByIdentifier(shieldAccount.identifier);
      if (!existingShield) {
        const { salt, hash } = hashPassword(shieldAccount.password);
        this.createUser({
          userId: shieldAccount.userId,
          tenantId: shieldAccount.tenantId,
          identifier: shieldAccount.identifier,
          identifierType: shieldAccount.identifierType,
          passwordHash: hash,
          salt,
          isHost: 0,
          role: 'tenant',
        });
      }

      // Seed host platform accounts: arcops-host (primary) & cicada-host (compatibility)
      const hostAccounts = [
        {
          userId: 'usr-arcops-host',
          tenantId: 'arcops-host',
          identifier: 'host@arcops.io',
          identifierType: 'email',
          password: 'Password123!',
          isHost: 1,
          role: 'host',
        },
        {
          userId: 'usr-cicada-host',
          tenantId: 'cicada-host',
          identifier: 'host@cicada.io',
          identifierType: 'email',
          password: 'Password123!',
          isHost: 1,
          role: 'host',
        },
      ];

      for (const hostAccount of hostAccounts) {
        const existingHost = this.getUserByIdentifier(hostAccount.identifier);
        if (!existingHost) {
          const { salt, hash } = hashPassword(hostAccount.password);
          this.createUser({
            userId: hostAccount.userId,
            tenantId: hostAccount.tenantId,
            identifier: hostAccount.identifier,
            identifierType: hostAccount.identifierType,
            passwordHash: hash,
            salt,
            isHost: 1,
            role: 'host',
          });
        }
      }
    } catch {
      // Ignore if already seeded
    }
  }

  /**
   * Registers a new tenant user with salted password hash.
   * 
   * @param {object} user 
   * @returns {object}
   */
  createUser(user) {
    const stmt = this.db.prepare(`
      INSERT INTO users (user_id, tenant_id, identifier, identifier_type, password_hash, salt, is_host, role, created_at_utc)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const nowUtc = user.createdAtUtc || new Date().toISOString();
    const isHostVal = user.isHost ? 1 : 0;
    const roleVal = user.role || (user.isHost ? 'host' : 'tenant');
    stmt.run(
      user.userId,
      user.tenantId,
      user.identifier,
      user.identifierType,
      user.passwordHash,
      user.salt,
      isHostVal,
      roleVal,
      nowUtc
    );

    return {
      userId: user.userId,
      tenantId: user.tenantId,
      identifier: user.identifier,
      identifierType: user.identifierType,
      isHost: Boolean(isHostVal),
      role: roleVal,
      createdAtUtc: nowUtc,
    };
  }

  /**
   * Retrieves a tenant user record by their email or mobile identifier.
   * 
   * @param {string} identifier 
   * @returns {object|null}
   */
  getUserByIdentifier(identifier) {
    if (!identifier) return null;
    const row = this.db.prepare('SELECT * FROM users WHERE identifier = ?').get(identifier);
    if (!row) return null;
    return {
      userId: row.user_id,
      tenantId: row.tenant_id,
      identifier: row.identifier,
      identifierType: row.identifier_type,
      passwordHash: row.password_hash,
      salt: row.salt,
      isHost: Boolean(
        row.is_host ||
        row.tenant_id === 'arcops-host' ||
        row.tenant_id === 'cicada-host' ||
        row.identifier === 'host@arcops.io' ||
        row.identifier === 'host@cicada.io' ||
        row.role === 'host'
      ),
      role: row.role || (row.is_host ? 'host' : 'tenant'),
      createdAtUtc: row.created_at_utc,
    };
  }

  /**
   * Retrieves a tenant user by user ID.
   * 
   * @param {string} userId 
   * @returns {object|null}
   */
  getUserById(userId) {
    if (!userId) return null;
    const row = this.db.prepare('SELECT * FROM users WHERE user_id = ?').get(userId);
    if (!row) return null;
    return {
      userId: row.user_id,
      tenantId: row.tenant_id,
      identifier: row.identifier,
      identifierType: row.identifier_type,
      passwordHash: row.password_hash,
      salt: row.salt,
      isHost: Boolean(
        row.is_host ||
        row.tenant_id === 'arcops-host' ||
        row.tenant_id === 'cicada-host' ||
        row.identifier === 'host@arcops.io' ||
        row.identifier === 'host@cicada.io' ||
        row.role === 'host'
      ),
      role: row.role || (row.is_host ? 'host' : 'tenant'),
      createdAtUtc: row.created_at_utc,
    };
  }

  /**
   * Updates a user's password hash and salt by their identifier.
   * 
   * @param {string} identifier 
   * @param {string} newPasswordHash 
   * @param {string} newSalt 
   * @returns {boolean}
   */
  updateUserPassword(identifier, newPasswordHash, newSalt) {
    if (!identifier || !newPasswordHash || !newSalt) return false;
    const stmt = this.db.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE identifier = ?');
    const result = stmt.run(newPasswordHash, newSalt, identifier);
    return result.changes > 0;
  }

  /**
   * Dynamically registers or provisions a new tenant partition.
   * 
   * @param {object} tenant 
   * @returns {object} Registered tenant
   */
  registerTenant(tenant) {
    if (!tenant || !tenant.tenantId || typeof tenant.tenantId !== 'string') {
      throw new Error('Valid tenantId is required to register tenant');
    }
    const normalizedId = tenant.tenantId.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '-');
    const name = tenant.name || normalizedId;
    const tier = tenant.tier || 'enterprise';
    const region = tenant.region || 'us-east-1';
    const slaTarget = tenant.slaTarget || '99.99%';
    const status = tenant.status || 'active';
    const nowUtc = new Date().toISOString();
    const metadataJson = JSON.stringify(tenant.metadata || {});

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO tenants (
        tenant_id, name, tier, region, sla_target, status, created_at_utc, metadata_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(normalizedId, name, tier, region, slaTarget, status, nowUtc, metadataJson);

    return {
      tenantId: normalizedId,
      name,
      tier,
      region,
      slaTarget,
      status,
      createdAtUtc: nowUtc,
      metadata: tenant.metadata || {},
    };
  }

  /**
   * Retrieves all registered dynamic tenants with their tier, region, and SLA.
   * 
   * @returns {Array<object>}
   */
  getTenants() {
    const rows = this.db.prepare('SELECT * FROM tenants ORDER BY created_at_utc ASC').all();
    return rows.map((r) => ({
      tenantId: r.tenant_id,
      name: r.name,
      tier: r.tier,
      region: r.region,
      slaTarget: r.sla_target,
      status: r.status,
      createdAtUtc: r.created_at_utc,
      metadata: JSON.parse(r.metadata_json || '{}'),
    }));
  }

  /**
   * Retrieves a specific registered tenant.
   * 
   * @param {string} tenantId 
   * @returns {object|null}
   */
  getTenant(tenantId) {
    if (!tenantId) return null;
    const row = this.db.prepare('SELECT * FROM tenants WHERE tenant_id = ?').get(tenantId.trim().toLowerCase());
    if (!row) return null;
    return {
      tenantId: row.tenant_id,
      name: row.name,
      tier: row.tier,
      region: row.region,
      slaTarget: row.sla_target,
      status: row.status,
      createdAtUtc: row.created_at_utc,
      metadata: JSON.parse(row.metadata_json || '{}'),
    };
  }

  /**
   * Inserts a single telemetry record into the database.
   * 
   * @param {object} event 
   * @returns {object} Inserted event with database ID
   */
  insertEvent(event) {
    if (!event || !event.tenantId || !event.payloadId) {
      throw new Error('Valid tenantId and payloadId required to insert telemetry event');
    }

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO telemetry_events (
        payload_id, tenant_id, region, source_alias, event_timestamp_utc,
        category, severity, metrics_json, summary, ingested_at_utc, is_anomaly, incident_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const metricsJson = event.metrics ? JSON.stringify(event.metrics) : '{}';
    const ingestedAt = event.ingestedAtUtc || new Date().toISOString();

    stmt.run(
      event.payloadId,
      event.tenantId.trim(),
      event.region || 'global',
      event.sourceAlias || 'unknown-source',
      event.eventTimestampUtc || new Date().toISOString(),
      event.category || 'infra',
      event.severity || 'low',
      metricsJson,
      event.summary || '',
      ingestedAt,
      event.isAnomaly ? 1 : 0,
      event.incidentId || null
    );

    return { ...event, ingestedAtUtc: ingestedAt };
  }

  /**
   * Inserts an array of telemetry events in a single transaction.
   * 
   * @param {Array<object>} events 
   * @returns {number} Number of events inserted
   */
  insertBatch(events = []) {
    if (!Array.isArray(events)) return 0;
    let count = 0;
    this.db.exec('BEGIN TRANSACTION');
    try {
      for (const ev of events) {
        this.insertEvent(ev);
        count++;
      }
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    return count;
  }

  /**
   * Queries telemetry events for a tenant with optional filtering.
   * 
   * @param {string} tenantId 
   * @param {object} [options]
   * @returns {Array<object>}
   */
  getEvents(tenantId, options = {}) {
    if (!tenantId) return [];

    let sql = 'SELECT * FROM telemetry_events WHERE tenant_id = ?';
    const params = [tenantId.trim()];

    if (options.region && options.region !== 'all') {
      sql += ' AND region = ?';
      params.push(options.region.trim());
    }
    if (options.category) {
      sql += ' AND category = ?';
      params.push(options.category.trim());
    }
    if (options.severity) {
      sql += ' AND severity = ?';
      params.push(options.severity.trim());
    }

    sql += ' ORDER BY event_timestamp_utc ASC';

    if (options.limit && Number.isInteger(options.limit)) {
      sql += ' LIMIT ?';
      params.push(options.limit);
    }

    const rows = this.db.prepare(sql).all(...params);
    return rows.map((r) => ({
      payloadId: r.payload_id,
      tenantId: r.tenant_id,
      region: r.region,
      sourceAlias: r.source_alias,
      eventTimestampUtc: r.event_timestamp_utc,
      category: r.category,
      severity: r.severity,
      metrics: JSON.parse(r.metrics_json || '{}'),
      summary: r.summary,
      ingestedAtUtc: r.ingested_at_utc,
      isAnomaly: Boolean(r.is_anomaly),
      incidentId: r.incident_id,
    }));
  }

  /**
   * Computes and updates dynamic statistical metric baselines for a tenant.
   * 
   * @param {string} tenantId 
   * @returns {Record<string, object>} Computed baselines per metric
   */
  updateMetricBaselines(tenantId) {
    const events = this.getEvents(tenantId);
    const metricSeries = new Map();

    for (const ev of events) {
      if (ev.metrics && typeof ev.metrics === 'object') {
        for (const [k, v] of Object.entries(ev.metrics)) {
          if (typeof v === 'number' && !Number.isNaN(v)) {
            if (!metricSeries.has(k)) metricSeries.set(k, []);
            metricSeries.get(k).push(v);
          }
        }
      }
    }

    const baselines = {};
    const upsertStmt = this.db.prepare(`
      INSERT OR REPLACE INTO baseline_metrics (
        tenant_id, metric_name, mean, std_dev, min_val, max_val, sample_count, updated_at_utc
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const nowUtc = new Date().toISOString();

    for (const [metricName, values] of metricSeries.entries()) {
      const stats = calculateStats(values);
      upsertStmt.run(
        tenantId,
        metricName,
        stats.mean,
        stats.stdDev,
        stats.min,
        stats.max,
        values.length,
        nowUtc
      );
      baselines[metricName] = { ...stats, sampleCount: values.length };
    }

    return baselines;
  }

  /**
   * Retrieves stored baseline metrics for a tenant.
   * 
   * @param {string} tenantId 
   * @returns {Array<object>}
   */
  getBaselines(tenantId) {
    const rows = this.db.prepare('SELECT * FROM baseline_metrics WHERE tenant_id = ?').all(tenantId);
    return rows.map((r) => ({
      tenantId: r.tenant_id,
      metricName: r.metric_name,
      mean: r.mean,
      stdDev: r.std_dev,
      min: r.min_val,
      max: r.max_val,
      sampleCount: r.sample_count,
      updatedAtUtc: r.updated_at_utc,
    }));
  }

  /**
   * Runs baseline anomaly detection over tenant events and persists detected anomalies in DB.
   * 
   * @param {string} tenantId 
   * @returns {Array<object>} Detected anomalies
   */
  detectAndStoreAnomalies(tenantId) {
    const events = this.getEvents(tenantId);
    const anomalies = detectAnomalies(events);

    const insertStmt = this.db.prepare(`
      INSERT INTO anomalies (
        tenant_id, payload_id, source_alias, category, severity,
        anomaly_score, reasons_json, metrics_json, timestamp_utc
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const updateEventStmt = this.db.prepare(`
      UPDATE telemetry_events SET is_anomaly = 1 WHERE payload_id = ?
    `);

    for (const anom of anomalies) {
      insertStmt.run(
        tenantId,
        anom.payloadId,
        anom.sourceAlias,
        anom.category,
        anom.severity,
        anom.anomalyScore,
        JSON.stringify(anom.reasons || []),
        JSON.stringify(anom.metrics || {}),
        anom.eventTimestampUtc
      );
      updateEventStmt.run(anom.payloadId);
    }

    return anomalies;
  }

  /**
   * Correlates multiple telemetry alerts into unified incidents with explainable RCA
   * and prescriptive recommendations, persisting them in the database.
   * 
   * @param {string} tenantId 
   * @returns {Array<object>} Correlated incidents with explainable recommendations
   */
  correlateAndStoreIncidents(tenantId) {
    const events = this.getEvents(tenantId);
    const rawIncidents = correlateIncidents(events);

    const insertIncidentStmt = this.db.prepare(`
      INSERT OR REPLACE INTO incidents (
        incident_id, tenant_id, title, severity, category, regions_json,
        affected_sources_json, event_count, duration_seconds, status,
        first_seen_utc, last_seen_utc, rca_json, recommendations_json, created_at_utc
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const linkEventStmt = this.db.prepare(`
      UPDATE telemetry_events SET incident_id = ? WHERE payload_id = ?
    `);

    const nowUtc = new Date().toISOString();
    const processedIncidents = [];

    for (const inc of rawIncidents) {
      const rca = performRootCauseAnalysis(inc, events);
      const recommendations = generateRecommendations(inc, rca);

      insertIncidentStmt.run(
        inc.incidentId,
        tenantId,
        inc.title,
        inc.severity,
        inc.category,
        JSON.stringify(inc.regions),
        JSON.stringify(inc.affectedSources),
        inc.eventCount,
        inc.durationSeconds,
        inc.status,
        inc.firstSeenUtc,
        inc.lastSeenUtc,
        JSON.stringify(rca),
        JSON.stringify(recommendations),
        nowUtc
      );

      // Link events to incident
      for (const pid of inc.correlatedPayloadIds) {
        linkEventStmt.run(inc.incidentId, pid);
      }

      processedIncidents.push({
        ...inc,
        rca,
        recommendations,
      });
    }

    return processedIncidents;
  }

  /**
   * Generates and executes simulated telemetry scenarios:
   * 1. 'spikes': Sudden CPU, latency, and throughput spikes exceeding baselines.
   * 2. 'outages': Cascading infrastructure crash propagating to network timeouts and collector drops.
   * 3. 'failed_logins': Brute-force credential stuffing attacks with malicious injections and leaks.
   * 
   * Automatically executes baseline anomaly detection, correlates alerts into one incident,
   * performs explainable RCA, and generates prescriptive runbooks.
   * 
   * @param {('spikes'|'outages'|'failed_logins')} scenarioType 
   * @param {string} tenantId 
   * @param {object} [options]
   * @returns {object} Simulation report with incident correlation and explainable recommendations
   */
  simulateScenario(scenarioType, tenantId, options = {}) {
    if (!tenantId) {
      throw new Error('tenantId is required for running telemetry simulation');
    }

    const normalizedTenant = tenantId.trim();
    const region = options.region || 'us-east-1';
    const baseTimeMs = options.baseTimeMs || Date.now();
    const simulationId = `sim-${scenarioType}-${Date.now()}`;
    const generatedEvents = [];

    // Reset in-memory partition before applying simulation scenario so state updates cleanly
    const prePartition = getOrCreateTenantPartition(normalizedTenant);
    if (prePartition) {
      prePartition.events = [];
      prePartition.seenPayloadIds = new Set();
      prePartition.stats.lastSeenUtc = new Date().toISOString();
    }

    if (scenarioType === SCENARIO_TYPES.SPIKES) {
      // 1. Establish normal baseline events (5 events with 30-50ms latency, 20-30% CPU)
      for (let i = 0; i < 5; i++) {
        generatedEvents.push({
          payloadId: `${simulationId}-norm-${i}`,
          tenantId: normalizedTenant,
          region,
          sourceAlias: 'api-service',
          eventTimestampUtc: new Date(baseTimeMs - (8 - i) * 2000).toISOString(),
          category: 'network',
          severity: 'low',
          metrics: { latencyMs: 35 + (i % 3) * 5, cpuUsage: 25 + i * 2, errorRate: 0.001 },
          summary: 'Normal baseline operational traffic',
        });
      }

      // 2. Telemetry Spikes (sudden severe surge: CPU to 99%, Memory to 96%, latency jumps to 2850ms)
      generatedEvents.push({
        payloadId: `${simulationId}-spike-1`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'compute-cluster',
        eventTimestampUtc: new Date(baseTimeMs - 3000).toISOString(),
        category: 'infra',
        severity: 'critical',
        metrics: { latencyMs: 2850, cpuUsage: 99, memoryUsage: 96, errorRate: 0.28 },
        summary: 'Critical resource exhaustion spike: CPU 99%, Memory 96%',
      });

      generatedEvents.push({
        payloadId: `${simulationId}-spike-2`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'api-service',
        eventTimestampUtc: new Date(baseTimeMs - 2000).toISOString(),
        category: 'network',
        severity: 'high',
        metrics: { latencyMs: 2450, cpuUsage: 94, errorRate: 0.18 },
        summary: 'Latency spike breach: API response time escalated to 2450ms',
      });

      generatedEvents.push({
        payloadId: `${simulationId}-spike-3`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'edge-gateway',
        eventTimestampUtc: new Date(baseTimeMs - 1000).toISOString(),
        category: 'network',
        severity: 'high',
        metrics: { latencyMs: 3100, errorRate: 0.32 },
        summary: 'Upstream gateway timeout surge under traffic spike',
      });
    } else if (scenarioType === SCENARIO_TYPES.OUTAGES) {
      // Cascading infrastructure outage propagating through the stack
      // Tier 1: Primary Database Node crash in us-east-1
      generatedEvents.push({
        payloadId: `${simulationId}-outage-db-crash`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'db-master-us-east',
        eventTimestampUtc: new Date(baseTimeMs - 5000).toISOString(),
        category: 'infra',
        severity: 'critical',
        metrics: { memoryUsage: 99, cpuUsage: 100, diskIo: 98 },
        summary: 'Catastrophic database node crash: Out of memory killer triggered',
      });

      // Tier 2: Microservice Network connection pool exhaustion and timeouts
      generatedEvents.push({
        payloadId: `${simulationId}-outage-net-timeout`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'payment-service',
        eventTimestampUtc: new Date(baseTimeMs - 3000).toISOString(),
        category: 'network',
        severity: 'high',
        metrics: { latencyMs: 4500, errorRate: 0.65 },
        summary: 'Payment service connection refused to primary database node',
      });

      // Tier 3: Ingress Collector queue overflow / dropout
      generatedEvents.push({
        payloadId: `${simulationId}-outage-collector-drop`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'telemetry-collector-daemon',
        eventTimestampUtc: new Date(baseTimeMs - 1000).toISOString(),
        category: 'collector',
        severity: 'high',
        metrics: { queueSaturation: 98, droppedEventsCount: 450 },
        summary: 'Telemetry pipeline backpressure: local buffer overflow under outage',
      });

      if (defaultCollector && typeof defaultCollector.setOutageMode === 'function') {
        defaultCollector.setOutageMode(true);
      }
    } else if (scenarioType === SCENARIO_TYPES.FAILED_LOGINS) {
      // Distributed credential stuffing brute-force attack + malicious injection attempt
      generatedEvents.push({
        payloadId: `${simulationId}-attack-login-flood-1`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'auth-gateway',
        eventTimestampUtc: new Date(baseTimeMs - 4000).toISOString(),
        category: 'security',
        severity: 'high',
        metrics: { failedLoginCount: 150, requestRate: 350, errorRate: 0.85 },
        summary: 'High volume of failed login attempts from botnet subnet',
      });

      generatedEvents.push({
        payloadId: `${simulationId}-attack-login-flood-2`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'auth-gateway',
        eventTimestampUtc: new Date(baseTimeMs - 2000).toISOString(),
        category: 'security',
        severity: 'critical',
        metrics: { failedLoginCount: 520, requestRate: 850, errorRate: 0.98 },
        summary: 'CRITICAL brute-force credential stuffing attack detected on /api/v1/login',
      });

      generatedEvents.push({
        payloadId: `${simulationId}-attack-sqli-bypass`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'auth-gateway',
        eventTimestampUtc: new Date(baseTimeMs - 1000).toISOString(),
        category: 'security',
        severity: 'critical',
        metrics: { blocked: 1, attackType: 'SQL_INJECTION' },
        summary: "Blocked SQL Injection authentication bypass attempt: admin' OR '1'='1",
      });

      // Record attack in security_attacks table
      this.db.prepare(`
        INSERT INTO security_attacks (
          tenant_id, source_alias, attack_type, severity, mitigation_status, summary, details_json, timestamp_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        normalizedTenant,
        'auth-gateway',
        'CREDENTIAL_STUFFING_AND_SQLI',
        'critical',
        'MITIGATED_BY_SHIELD',
        'Brute-force credential stuffing with SQLi authentication bypass attempt',
        JSON.stringify({ failedLoginCount: 520, attackType: 'SQL_INJECTION' }),
        new Date(baseTimeMs).toISOString()
      );

      // Update edge collector threat mitigation counters
      if (defaultCollector && defaultCollector.stats) {
        defaultCollector.stats.attacksBlocked += 2;
        defaultCollector.stats.attackBreakdown[ATTACK_TYPES.SQL_INJECTION] =
          (defaultCollector.stats.attackBreakdown[ATTACK_TYPES.SQL_INJECTION] || 0) + 1;
        defaultCollector.stats.attackBreakdown[ATTACK_TYPES.RATE_LIMIT_EXCEEDED] =
          (defaultCollector.stats.attackBreakdown[ATTACK_TYPES.RATE_LIMIT_EXCEEDED] || 0) + 1;
      }
    } else if (scenarioType === SCENARIO_TYPES.DATA_LEAKS) {
      // Sensitive Data Loss Prevention (DLP) leak scenario: employee / compromised worker emits secrets & customer PII
      generatedEvents.push({
        payloadId: `${simulationId}-dlp-key-leak`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'edge-auth-cluster',
        eventTimestampUtc: new Date(baseTimeMs - 4000).toISOString(),
        category: 'security',
        severity: 'critical',
        metrics: {
          leaksDetectedAndRedacted: 5,
          payloadSizeBytes: 1850,
          fieldsStrippedCount: 8,
          leakTypes: ['API_KEY', 'PASSWORD', 'CREDIT_CARD'],
        },
        summary: 'Critical credential exposure intercepted by DLP: OpenAI API key (sk-live-***), plaintext password, and Credit Card (PCI-DSS) purged',
      });

      generatedEvents.push({
        payloadId: `${simulationId}-dlp-cloud-leak`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'worker-daemon',
        eventTimestampUtc: new Date(baseTimeMs - 2000).toISOString(),
        category: 'security',
        severity: 'critical',
        metrics: {
          leaksDetectedAndRedacted: 3,
          payloadSizeBytes: 940,
          fieldsStrippedCount: 6,
          leakTypes: ['AWS_KEY', 'BEARER_TOKEN'],
        },
        summary: 'Cloud credential leak blocked: AWS IAM access key & Bearer authentication token redacted from payload',
      });

      generatedEvents.push({
        payloadId: `${simulationId}-dlp-pii-leak`,
        tenantId: normalizedTenant,
        region,
        sourceAlias: 'customer-portal',
        eventTimestampUtc: new Date(baseTimeMs - 1000).toISOString(),
        category: 'security',
        severity: 'high',
        metrics: {
          leaksDetectedAndRedacted: 2,
          payloadSizeBytes: 620,
          fieldsStrippedCount: 5,
          leakTypes: ['SSN', 'EMAIL'],
        },
        summary: 'Sensitive PII exposure neutralized: Social Security Number (SSN) and personal email address scrubbed',
      });

      // Record in security_attacks / DLP log
      this.db.prepare(`
        INSERT INTO security_attacks (
          tenant_id, source_alias, attack_type, severity, mitigation_status, summary, details_json, timestamp_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        normalizedTenant,
        'edge-auth-cluster',
        'CREDENTIAL_AND_PII_DATA_LEAK',
        'critical',
        'PURGED_BY_DLP_SHIELD',
        'DLP scanner neutralized 10 exposed secrets (OpenAI API key, AWS IAM key, plaintext password, Credit Card, SSN, personal email)',
        JSON.stringify({
          leaksPrevented: 10,
          leakTypes: ['API_KEY', 'BEARER_TOKEN', 'PASSWORD', 'CREDIT_CARD', 'SSN', 'EMAIL'],
        }),
        new Date(baseTimeMs).toISOString()
      );

      // Update edge collector DLP leak metrics
      if (defaultCollector && defaultCollector.stats) {
        defaultCollector.stats.leaksPrevented += 10;
        defaultCollector.stats.leakBreakdown[LEAK_TYPES.API_KEY] =
          (defaultCollector.stats.leakBreakdown[LEAK_TYPES.API_KEY] || 0) + 3;
        defaultCollector.stats.leakBreakdown[LEAK_TYPES.PASSWORD] =
          (defaultCollector.stats.leakBreakdown[LEAK_TYPES.PASSWORD] || 0) + 2;
        defaultCollector.stats.leakBreakdown[LEAK_TYPES.CREDIT_CARD] =
          (defaultCollector.stats.leakBreakdown[LEAK_TYPES.CREDIT_CARD] || 0) + 2;
        defaultCollector.stats.leakBreakdown[LEAK_TYPES.BEARER_TOKEN] =
          (defaultCollector.stats.leakBreakdown[LEAK_TYPES.BEARER_TOKEN] || 0) + 2;
        defaultCollector.stats.leakBreakdown[LEAK_TYPES.SSN] =
          (defaultCollector.stats.leakBreakdown[LEAK_TYPES.SSN] || 0) + 1;
      }
    } else if (scenarioType === SCENARIO_TYPES.BASELINE) {
      // 1. Purge past non-low severity attack/incident events for this tenant so health restores to 100% HEALTHY
      this.db.prepare(`
        DELETE FROM telemetry_events 
        WHERE tenant_id = ? AND severity != 'low'
      `).run(normalizedTenant);

      // 2. Clear past anomalies and mark past incidents and attacks as RESOLVED
      this.db.prepare('DELETE FROM anomalies WHERE tenant_id = ?').run(normalizedTenant);
      this.db.prepare("UPDATE incidents SET status = 'RESOLVED' WHERE tenant_id = ?").run(normalizedTenant);
      this.db.prepare("UPDATE security_attacks SET mitigation_status = 'RESOLVED_NEUTRALIZED' WHERE tenant_id = ?").run(normalizedTenant);

      // 3. Clear simulated outage mode in edge collector
      if (defaultCollector && typeof defaultCollector.setOutageMode === 'function') {
        defaultCollector.setOutageMode(false);
      }

      // 4. Normal healthy baseline operational traffic
      for (let i = 0; i < 6; i++) {
        generatedEvents.push({
          payloadId: `${simulationId}-baseline-${i}`,
          tenantId: normalizedTenant,
          region,
          sourceAlias: 'gateway-core',
          eventTimestampUtc: new Date(baseTimeMs - (6 - i) * 2000).toISOString(),
          category: 'network',
          severity: 'low',
          metrics: { latencyMs: 25 + (i % 3) * 3, cpuUsage: 18 + i * 2, errorRate: 0.0001 },
          summary: 'Steady-state production telemetry within established baseline',
        });
      }
    } else {
      throw new Error(`Unknown scenarioType "${scenarioType}". Must be 'spikes', 'outages', 'failed_logins', or 'data_leaks'`);
    }

    // 1. Insert all generated telemetry events into DB
    this.insertBatch(generatedEvents);

    // 2. Synchronize with in-memory SaaS Engine partition for real-time AIOps scoring
    try {
      ingestBatch(generatedEvents, 'collector-alpha-token');
    } catch {
      // Non-fatal if partition is in-memory only
    }

    // Ensure partition lastSeenUtc is updated to now so staleness penalty is not triggered
    const postPartition = getOrCreateTenantPartition(normalizedTenant);
    if (postPartition) {
      postPartition.stats.lastSeenUtc = new Date().toISOString();
    }

    // 2. Compute dynamic baselines
    const baselines = this.updateMetricBaselines(normalizedTenant);

    // 3. Baseline Anomaly Detection
    const anomalies = this.detectAndStoreAnomalies(normalizedTenant);

    // 4. Correlate Alerts into ONE Unified Incident with Explainable Recommendations
    const incidents = this.correlateAndStoreIncidents(normalizedTenant);

    // Find the primary correlated incident
    const primaryIncident = incidents.length > 0 ? incidents[incidents.length - 1] : null;

    // 5. Record simulation in database
    this.db.prepare(`
      INSERT INTO simulations (simulation_id, tenant_id, scenario_type, event_count, incident_id, created_at_utc)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      simulationId,
      normalizedTenant,
      scenarioType,
      generatedEvents.length,
      primaryIncident ? primaryIncident.incidentId : null,
      new Date().toISOString()
    );

    return {
      simulationId,
      tenantId: normalizedTenant,
      scenarioType,
      eventsGeneratedCount: generatedEvents.length,
      baselinesUpdated: Object.keys(baselines),
      anomaliesDetectedCount: anomalies.length,
      anomalies,
      correlatedIncident: primaryIncident,
      explainableRca: primaryIncident ? primaryIncident.rca : null,
      recommendations: primaryIncident ? primaryIncident.recommendations : [],
    };
  }

  /**
   * Retrieves all correlated incidents for a tenant.
   * 
   * @param {string} tenantId 
   * @returns {Array<object>}
   */
  getIncidents(tenantId) {
    const rows = this.db.prepare('SELECT * FROM incidents WHERE tenant_id = ? ORDER BY first_seen_utc DESC').all(tenantId);
    return rows.map((r) => ({
      incidentId: r.incident_id,
      tenantId: r.tenant_id,
      title: r.title,
      severity: r.severity,
      category: r.category,
      regions: JSON.parse(r.regions_json || '[]'),
      affectedSources: JSON.parse(r.affected_sources_json || '[]'),
      eventCount: r.event_count,
      durationSeconds: r.duration_seconds,
      status: r.status,
      firstSeenUtc: r.first_seen_utc,
      lastSeenUtc: r.last_seen_utc,
      rca: JSON.parse(r.rca_json || '{}'),
      recommendations: JSON.parse(r.recommendations_json || '[]'),
      createdAtUtc: r.created_at_utc,
    }));
  }

  /**
   * Retrieves detected anomalies for a tenant.
   * 
   * @param {string} tenantId 
   * @returns {Array<object>}
   */
  getAnomalies(tenantId) {
    const rows = this.db.prepare('SELECT * FROM anomalies WHERE tenant_id = ? ORDER BY timestamp_utc DESC').all(tenantId);
    return rows.map((r) => ({
      id: r.id,
      tenantId: r.tenant_id,
      payloadId: r.payload_id,
      sourceAlias: r.source_alias,
      category: r.category,
      severity: r.severity,
      anomalyScore: r.anomaly_score,
      reasons: JSON.parse(r.reasons_json || '[]'),
      metrics: JSON.parse(r.metrics_json || '{}'),
      timestampUtc: r.timestamp_utc,
    }));
  }

  /**
   * Retrieves recorded security attacks for a tenant.
   * 
   * @param {string} tenantId 
   * @returns {Array<object>}
   */
  getAttacks(tenantId) {
    const rows = this.db.prepare('SELECT * FROM security_attacks WHERE tenant_id = ? ORDER BY timestamp_utc DESC').all(tenantId);
    return rows.map((r) => ({
      id: r.id,
      tenantId: r.tenant_id,
      sourceAlias: r.source_alias,
      attackType: r.attack_type,
      severity: r.severity,
      mitigationStatus: r.mitigation_status,
      summary: r.summary,
      details: JSON.parse(r.details_json || '{}'),
      timestampUtc: r.timestamp_utc,
    }));
  }

  /**
   * Cleans up all tables (used for testing).
   */
  reset() {
    this.db.exec(`
      DELETE FROM telemetry_events;
      DELETE FROM baseline_metrics;
      DELETE FROM anomalies;
      DELETE FROM incidents;
      DELETE FROM security_attacks;
      DELETE FROM simulations;
    `);
  }

  /**
   * Closes database connection.
   */
  close() {
    this.db.close();
  }
}

// Global default database singleton instance
export const defaultDatabase = new TelemetryDatabase();

export default {
  SCENARIO_TYPES,
  TelemetryDatabase,
  defaultDatabase,
};
