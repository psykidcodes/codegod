'use client';

import { useState, useEffect, useCallback } from 'react';

// Representative raw payloads for simulations and playground testing
const SCENARIO_RAW_PAYLOADS = {
  data_leaks: {
    sourceAlias: 'edge-auth-cluster',
    region: 'us-east-1',
    userPayload: {
      rawMessage: 'Production diagnostic bundle with exposed credentials',
      contactEmail: 'security-director@cyberguard.net',
      openAiKey: 'sk-live-0982341908234091823409182',
      awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
      accountPassword: 'MasterQuantumPassword99!',
      customerCreditCard: '4532-9988-7766-5544',
      customerSsn: '987-65-4321',
    },
    latencyMs: 72,
    statusCode: 200,
  },
  failed_logins: {
    sourceAlias: 'auth-gateway',
    region: 'us-east-1',
    endpoint: '/api/v1/auth/login',
    searchQuery: "admin' OR '1'='1' UNION SELECT token, key_hash FROM system_vault --",
    failedAttempts: 520,
    headers: {
      userAgent: 'CyberStrike/4.2.0 Infiltration Botnet',
    },
  },
  spikes: {
    sourceAlias: 'compute-cluster',
    region: 'us-east-1',
    category: 'infra',
    severity: 'critical',
    latencyMs: 2850,
    statusCode: 504,
    metrics: {
      cpuUsage: 99.4,
      memoryUsage: 96.2,
      errorRate: 0.28,
    },
    summary: 'Critical compute capacity saturation & latency surge',
  },
  outages: {
    sourceAlias: 'db-master-us-east',
    region: 'us-east-1',
    category: 'infra',
    severity: 'critical',
    statusCode: 500,
    metrics: {
      cpuUsage: 100,
      memoryUsage: 99,
      diskIo: 98,
    },
    summary: 'Cascading Out-Of-Memory DB crash and connection timeout',
  },
  baseline: {
    sourceAlias: 'api-gateway',
    region: 'us-east-1',
    category: 'network',
    severity: 'low',
    latencyMs: 32,
    statusCode: 200,
    metrics: {
      cpuUsage: 22,
      memoryUsage: 38,
      errorRate: 0.0001,
    },
    summary: 'Steady-state production telemetry within established baselines',
  },
};

export default function HomePage() {
  // Theme State: 'dark' | 'light'
  const [theme, setTheme] = useState('dark');

  // Auth & Session State
  const [currentUser, setCurrentUser] = useState(null);
  const [authChecking, setAuthChecking] = useState(true);

  // Auth Form State (Sign In / Sign Up)
  const [authMode, setAuthMode] = useState('signin'); // 'signin' | 'signup'
  const [authIdentifier, setAuthIdentifier] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [authTenantName, setAuthTenantName] = useState('');
  const [authRegion, setAuthRegion] = useState('us-east-1');
  const [authTier, setAuthTier] = useState('enterprise');
  const [authError, setAuthError] = useState(null);
  const [authLoading, setAuthLoading] = useState(false);

  // Active Tab & Loading
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'collector' | 'saas' | 'playground' | 'api'
  const [loading, setLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);

  // AIOps Intelligence Data
  const [aiopsData, setAiopsData] = useState({
    healthScore: 100,
    healthStatus: 'HEALTHY',
    categoryHealth: {
      infra: { score: 100, status: 'HEALTHY', eventCount: 0, criticalCount: 0 },
      network: { score: 100, status: 'HEALTHY', eventCount: 0, criticalCount: 0 },
      security: { score: 100, status: 'HEALTHY', eventCount: 0, criticalCount: 0 },
      collector: { score: 100, status: 'HEALTHY', eventCount: 0, criticalCount: 0 },
    },
    isStale: false,
    summary: { totalEventsAnalyzed: 0, anomaliesCount: 0, activeIncidentsCount: 0, healthTrend: 'HEALTHY' },
    anomalies: [],
    incidents: [],
    recommendations: [],
  });

  // Local Edge Collector Metrics (Decoupled Tier 1)
  const [collectorStats, setCollectorStats] = useState({
    totalReceived: 0,
    metadataForwarded: 0,
    rawFieldsStrippedCount: 0,
    leaksPrevented: 0,
    attacksBlocked: 0,
    attackBreakdown: {},
    leakBreakdown: {},
  });

  // Playground State (Automated after simulations)
  const [playgroundInput, setPlaygroundInput] = useState(JSON.stringify(SCENARIO_RAW_PAYLOADS.data_leaks, null, 2));
  const [playgroundResult, setPlaygroundResult] = useState(null);
  const [playgroundRunning, setPlaygroundRunning] = useState(false);

  // AI Active Reasoning Trace (prominent during attacks)
  const [aiReasoningActive, setAiReasoningActive] = useState(false);
  const [aiReasoningSteps, setAiReasoningSteps] = useState([]);

  // Initialize Theme & Session on Mount
  useEffect(() => {
    const savedTheme = typeof window !== 'undefined' ? localStorage.getItem('cicada_theme') || 'dark' : 'dark';
    setTheme(savedTheme);
    document.documentElement.setAttribute('data-theme', savedTheme);

    const storedToken = typeof window !== 'undefined' ? localStorage.getItem('cicada_session_token') : null;
    if (storedToken) {
      fetch('/api/auth?action=me', {
        headers: { Authorization: `Bearer ${storedToken}` },
      })
        .then((res) => res.json())
        .then((data) => {
          if (data.authenticated && data.user) {
            setCurrentUser(data.user);
          } else {
            localStorage.removeItem('cicada_session_token');
            setCurrentUser(null);
          }
        })
        .catch(() => {
          setCurrentUser(null);
        })
        .finally(() => {
          setAuthChecking(false);
        });
    } else {
      setAuthChecking(false);
    }
  }, []);

  // Theme Toggle Handler
  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
    localStorage.setItem('cicada_theme', nextTheme);
  };

  // Fetch Telemetry & Collector Data strictly for Authenticated Tenant
  const refreshTenantData = useCallback(async (tenantId) => {
    if (!tenantId) return;
    setLoading(true);
    try {
      const aiopsRes = await fetch(`/api/aiops?tenantId=${encodeURIComponent(tenantId)}`);
      if (aiopsRes.ok) {
        const data = await aiopsRes.json();
        setAiopsData(data);
      }

      const collectorRes = await fetch('/api/collector');
      if (collectorRes.ok) {
        const cData = await collectorRes.json();
        if (cData.stats) setCollectorStats(cData.stats);
      }
    } catch (err) {
      console.error('Failed to refresh tenant telemetry', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // Sync data whenever currentUser changes
  useEffect(() => {
    if (currentUser?.tenantId) {
      refreshTenantData(currentUser.tenantId);
    }
  }, [currentUser, refreshTenantData]);

  // Handle Simulation Scenarios with Health Status Update & Automated Collector Playground
  const handleRunSimulation = async (scenario) => {
    if (!currentUser?.tenantId) return;
    setLoading(true);
    setAiReasoningActive(true);

    const timeStr = new Date().toISOString().substring(11, 19) + ' UTC';

    // 1. Set AI Reasoning Steps prominently
    let initialSteps = [];
    if (scenario === 'data_leaks') {
      initialSteps = [
        { time: timeStr, title: 'Deep DLP Pattern Match', desc: 'Detected 5 exposed credentials (OpenAI key sk-live-***, AWS key, plaintext password, Credit Card PCI-DSS) in raw payload.', status: 'CRITICAL' },
        { time: timeStr, title: 'Privacy Shield Redaction', desc: 'Edge collector DLP purged 100% of sensitive fields before central SaaS engine forwarding.', status: 'ACTIVE' },
        { time: timeStr, title: 'Multi-Tenant Incident Correlation', desc: 'Clustered security alerts into unified Incident INC-SEC-DLP with high confidence (96%).', status: 'ALERT' },
        { time: timeStr, title: 'Prescriptive Runbook Formulation', desc: 'Formulated KMS secret rollback and IAM key revocation commands.', status: 'DONE' },
      ];
    } else if (scenario === 'failed_logins') {
      initialSteps = [
        { time: timeStr, title: 'Heuristic Signature Match', desc: 'SQL Injection pattern "UNION SELECT token" and botnet burst (520 failed logins) identified on /api/v1/auth/login.', status: 'CRITICAL' },
        { time: timeStr, title: 'Statistical Anomaly Detected', desc: 'Failed login rate escalated Z = 5.2σ above tenant baseline.', status: 'ALERT' },
        { time: timeStr, title: 'Edge Shield Quarantine Triggered', desc: 'Edge Collector returned HTTP 403 Forbidden; origin IP rate-limited.', status: 'ACTIVE' },
        { time: timeStr, title: 'Autonomous Playbook Generation', desc: 'Prescribed waf-cli rate limiting and access token revocation.', status: 'DONE' },
      ];
    } else if (scenario === 'outages') {
      initialSteps = [
        { time: timeStr, title: 'Host Node Crash Detected', desc: 'Primary database node db-master-us-east crashed due to Memory exhaustion (99%).', status: 'CRITICAL' },
        { time: timeStr, title: 'Causal Chain Propagation Traced', desc: 'Infra failure cascaded to microservice network timeouts (4500ms) and ingress queue backpressure.', status: 'ALERT' },
        { time: timeStr, title: 'Root Cause Confidence Calculated', desc: 'AIOps diagnosed database OOM as primary root cause with 95% confidence.', status: 'DONE' },
      ];
    } else if (scenario === 'spikes') {
      initialSteps = [
        { time: timeStr, title: 'Dynamic Baseline Breach', desc: 'Compute CPU surged to 99.4% and latency escalated to 2850ms (Z = 4.1σ).', status: 'ALERT' },
        { time: timeStr, title: 'SLA Risk Assessment', desc: 'Breached 99.9% tenant SLA target; active alerting triggered.', status: 'WARNING' },
        { time: timeStr, title: 'Horizontal Autoscale Prescribed', desc: 'kubectl scale deployment/api-service --replicas=5 generated.', status: 'DONE' },
      ];
    } else {
      initialSteps = [
        { time: timeStr, title: 'Baseline Normalization', desc: 'Telemetry stream returned to steady-state baseline. All operational metrics healthy.', status: 'HEALTHY' },
      ];
    }
    setAiReasoningSteps(initialSteps);

    try {
      // 2. Execute simulation scenario on the backend
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario, tenantId: currentUser.tenantId }),
      });
      const data = await res.json();

      if (res.ok) {
        // Direct update of AIOps health data from simulation response for immediate UI reactivity
        if (data.aiopsReport) {
          setAiopsData(data.aiopsReport);
        }

        // 3. Automate Collector Playground: pass the scenario's raw payload to /api/collector
        const rawPayload = SCENARIO_RAW_PAYLOADS[scenario] || SCENARIO_RAW_PAYLOADS.data_leaks;
        setPlaygroundInput(JSON.stringify(rawPayload, null, 2));

        const collectorRes = await fetch('/api/collector', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...rawPayload, tenantId: currentUser.tenantId }),
        });
        const collectorData = await collectorRes.json();

        setPlaygroundResult({
          httpStatus: collectorRes.status,
          response: collectorData,
        });

        // 4. Automatically switch to the Playground tab to demonstrate raw vs sanitized metadata
        setActiveTab('playground');

        setActionMessage({
          type: data.aiopsReport?.healthStatus === 'HEALTHY' ? 'success' : 'warning',
          text: `[AUTOMATED WORKFLOW] Scenario '${scenario}' simulated. Health status updated to ${data.aiopsReport?.healthStatus || 'UPDATED'}. Collector Playground automated below with live raw input vs sanitized metadata.`,
        });

        // Refresh all background counts
        await refreshTenantData(currentUser.tenantId);
      } else {
        setActionMessage({ type: 'error', text: data.error || 'Simulation execution failed' });
      }
    } catch (err) {
      setActionMessage({ type: 'error', text: 'Simulation network error: ' + err.message });
    } finally {
      setLoading(false);
    }
  };

  // Auth Submission (Sign In / Sign Up)
  const handleAuthSubmit = async (e) => {
    e.preventDefault();
    setAuthError(null);
    setAuthLoading(true);

    try {
      const endpoint = `/api/auth?action=${authMode}`;
      const payload = {
        identifier: authIdentifier,
        password: authPassword,
        tenantName: authTenantName || 'Production Services',
        tier: authTier,
        region: authRegion,
      };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (res.ok && data.status === 'authenticated') {
        localStorage.setItem('cicada_session_token', data.token);
        setCurrentUser(data.user);
        setActionMessage({
          type: 'success',
          text: `Authenticated session established for tenant '${data.user.tenantId}'. Row-level partition isolation active.`,
        });
      } else {
        setAuthError(data.error || 'Authentication failed. Please verify credentials.');
      }
    } catch (err) {
      setAuthError('Connection error: ' + err.message);
    } finally {
      setAuthLoading(false);
    }
  };

  // Sign Out Handler
  const handleSignOut = () => {
    localStorage.removeItem('cicada_session_token');
    setCurrentUser(null);
    setAuthPassword('');
    setActionMessage({ type: 'info', text: 'Securely signed out. Session token cleared.' });
  };

  // Manual Playground Submit
  const handleManualPlaygroundSubmit = async () => {
    if (!currentUser?.tenantId) return;
    setPlaygroundRunning(true);
    setPlaygroundResult(null);
    try {
      let parsed;
      try {
        parsed = JSON.parse(playgroundInput);
      } catch {
        alert('Invalid JSON structure');
        setPlaygroundRunning(false);
        return;
      }

      const res = await fetch('/api/collector', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...parsed, tenantId: currentUser.tenantId }),
      });
      const data = await res.json();
      setPlaygroundResult({
        httpStatus: res.status,
        response: data,
      });
      await refreshTenantData(currentUser.tenantId);
    } catch (err) {
      setPlaygroundResult({
        httpStatus: 500,
        response: { error: err.message },
      });
    } finally {
      setPlaygroundRunning(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'HEALTHY': return 'var(--color-emerald)';
      case 'DEGRADED': return 'var(--color-amber)';
      case 'CRITICAL': return 'var(--color-rose)';
      case 'STALE': return 'var(--color-amber)';
      default: return 'var(--text-muted)';
    }
  };

  if (authChecking) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--bg-canvas)',
        color: 'var(--text-secondary)',
        fontFamily: 'var(--font-mono)',
        fontSize: '0.85rem',
      }}>
        Initializing Zero-Trust Perimeter...
      </div>
    );
  }

  // ==========================================
  // VIEW 1: UN-AUTHENTICATED LOGIN / SIGNUP
  // ==========================================
  if (!currentUser) {
    return (
      <div style={{
        minHeight: '100vh',
        background: 'var(--bg-canvas)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        padding: '32px 16px',
        position: 'relative',
      }}>
        <div style={{ position: 'absolute', top: '24px', right: '24px' }}>
          <button
            onClick={toggleTheme}
            className="btn-minimal"
            style={{ fontSize: '0.8rem', padding: '6px 12px' }}
          >
            {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
          </button>
        </div>

        <div style={{ textAlign: 'center', marginBottom: '24px', maxWidth: '440px' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '36px',
            height: '36px',
            borderRadius: '6px',
            background: 'var(--bg-surface-elevated)',
            border: '1px solid var(--border-subtle)',
            fontSize: '1.1rem',
            marginBottom: '10px',
          }}>
            ⚡
          </div>
          <h1 style={{ fontSize: '1.35rem', fontWeight: '700', letterSpacing: '-0.3px' }}>
            Cicada Telemetry & AIOps
          </h1>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Multi-Tenant Operational Observability & Threat Shield
          </p>
        </div>

        <div className="card-minimal" style={{ maxWidth: '420px', width: '100%', padding: '26px' }}>
          <div style={{
            display: 'flex',
            background: 'var(--bg-canvas)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
            padding: '3px',
            marginBottom: '18px',
          }}>
            <button
              onClick={() => { setAuthMode('signin'); setAuthError(null); }}
              style={{
                flex: 1,
                padding: '6px 12px',
                border: 'none',
                borderRadius: '4px',
                background: authMode === 'signin' ? 'var(--bg-surface)' : 'transparent',
                color: authMode === 'signin' ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontWeight: authMode === 'signin' ? '600' : '400',
                fontSize: '0.82rem',
                cursor: 'pointer',
              }}
            >
              Sign In
            </button>
            <button
              onClick={() => { setAuthMode('signup'); setAuthError(null); }}
              style={{
                flex: 1,
                padding: '6px 12px',
                border: 'none',
                borderRadius: '4px',
                background: authMode === 'signup' ? 'var(--bg-surface)' : 'transparent',
                color: authMode === 'signup' ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontWeight: authMode === 'signup' ? '600' : '400',
                fontSize: '0.82rem',
                cursor: 'pointer',
              }}
            >
              Register Tenant
            </button>
          </div>

          {authError && (
            <div style={{
              background: 'var(--color-rose-subtle)',
              border: '1px solid rgba(244, 63, 94, 0.3)',
              color: 'var(--color-rose)',
              padding: '10px 12px',
              borderRadius: '6px',
              fontSize: '0.8rem',
              marginBottom: '14px',
            }}>
              {authError}
            </div>
          )}

          <form onSubmit={handleAuthSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {authMode === 'signup' && (
              <div>
                <label style={{ display: 'block', fontSize: '0.76rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Tenant Organization Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Acme Cloud Corp"
                  value={authTenantName}
                  onChange={(e) => setAuthTenantName(e.target.value)}
                  className="input-minimal"
                />
              </div>
            )}

            <div>
              <label style={{ display: 'block', fontSize: '0.76rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                Email Address or Mobile Phone
              </label>
              <input
                type="text"
                required
                placeholder="operator@company.com or +1 555-123-4567"
                value={authIdentifier}
                onChange={(e) => setAuthIdentifier(e.target.value)}
                className="input-minimal"
              />
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                <label style={{ fontSize: '0.76rem', fontWeight: '500', color: 'var(--text-secondary)' }}>
                  Password
                </label>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--accent)', fontSize: '0.72rem', cursor: 'pointer' }}
                >
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                placeholder="Minimum 6 characters"
                value={authPassword}
                onChange={(e) => setAuthPassword(e.target.value)}
                className="input-minimal"
              />
              <span style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                🔒 Passwords remain solely with you. Derived via scrypt with 16-byte random salt.
              </span>
            </div>

            {authMode === 'signup' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.74rem', color: 'var(--text-secondary)', marginBottom: '3px' }}>Tier</label>
                  <select value={authTier} onChange={(e) => setAuthTier(e.target.value)} className="input-minimal" style={{ padding: '6px 8px', fontSize: '0.78rem' }}>
                    <option value="enterprise">Enterprise (99.99%)</option>
                    <option value="pro">Pro (99.9%)</option>
                    <option value="starter">Starter (99.5%)</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.74rem', color: 'var(--text-secondary)', marginBottom: '3px' }}>Region</label>
                  <select value={authRegion} onChange={(e) => setAuthRegion(e.target.value)} className="input-minimal" style={{ padding: '6px 8px', fontSize: '0.78rem' }}>
                    <option value="us-east-1">us-east-1</option>
                    <option value="eu-west-1">eu-west-1</option>
                    <option value="us-west-2">us-west-2</option>
                    <option value="ap-southeast-1">ap-southeast-1</option>
                  </select>
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={authLoading}
              className="btn-minimal-primary"
              style={{ marginTop: '6px', width: '100%', padding: '9px' }}
            >
              {authLoading ? 'Verifying...' : authMode === 'signin' ? 'Sign In' : 'Provision Isolated Partition'}
            </button>
          </form>

          <div style={{ marginTop: '20px', borderTop: '1px solid var(--border-subtle)', paddingTop: '14px' }}>
            <span style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
              ONE-CLICK DEMO CREDENTIALS:
            </span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
              <button
                type="button"
                onClick={() => {
                  setAuthMode('signin');
                  setAuthIdentifier('admin@acme.com');
                  setAuthPassword('Password123!');
                  setAuthError(null);
                }}
                className="btn-minimal"
                style={{ fontSize: '0.74rem', justifyContent: 'flex-start' }}
              >
                <span>🏢</span> <strong>Admin (Email):</strong> admin@acme.com / Password123!
              </button>
              <button
                type="button"
                onClick={() => {
                  setAuthMode('signin');
                  setAuthIdentifier('+1 555 123 4567');
                  setAuthPassword('Password123!');
                  setAuthError(null);
                }}
                className="btn-minimal"
                style={{ fontSize: '0.74rem', justifyContent: 'flex-start' }}
              >
                <span>📱</span> <strong>Ops (Mobile):</strong> +1 555 123 4567 / Password123!
              </button>
            </div>
          </div>
        </div>

        <div style={{ marginTop: '16px', maxWidth: '420px', textAlign: 'center', fontSize: '0.73rem', color: 'var(--text-muted)' }}>
          🛡️ <strong>Zero-Cross-Tenant Isolation:</strong> Partition boundary enforced. Credential and PII masking applied automatically across all views.
        </div>
      </div>
    );
  }

  // ==========================================
  // VIEW 2: AUTHENTICATED OBSERVABILITY SUITE
  // ==========================================
  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '18px 20px', minHeight: '100vh' }}>
      {/* Top Professional Navigation Bar */}
      <header style={{
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingBottom: '14px',
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: '16px',
        gap: '12px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '5px',
            background: 'var(--bg-surface-elevated)',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1rem',
          }}>
            ⚡
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '1.05rem', fontWeight: '700', letterSpacing: '-0.2px' }}>
                Cicada Telemetry
              </span>
              <span className="badge-minimal" style={{ background: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)', color: 'var(--text-secondary)' }}>
                prod / us-east-1
              </span>
            </div>
          </div>
        </div>

        {/* Status Pill & User Badges */}
        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
          {/* Live System Status Pill */}
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            background: 'var(--bg-surface)',
            border: `1px solid ${getStatusColor(aiopsData.healthStatus)}40`,
            borderRadius: '20px',
            padding: '4px 10px',
            fontSize: '0.76rem',
            fontWeight: '600',
            color: getStatusColor(aiopsData.healthStatus),
          }}>
            <span
              className={aiopsData.healthStatus !== 'HEALTHY' ? 'status-dot-active' : ''}
              style={{
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                background: getStatusColor(aiopsData.healthStatus),
              }}
            />
            <span>{aiopsData.healthStatus === 'HEALTHY' ? 'All Systems Operational' : `${aiopsData.healthStatus} Condition`}</span>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>({aiopsData.healthScore}/100)</span>
          </div>

          {/* Masked User Profile Badge */}
          <div style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
            padding: '4px 10px',
            fontSize: '0.78rem',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}>
            <span style={{ color: 'var(--text-muted)' }}>Tenant:</span>
            <strong>{currentUser.tenantId}</strong>
            <span style={{ color: 'var(--border-subtle)' }}>|</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{currentUser.maskedIdentifier}</span>
          </div>

          <button onClick={() => refreshTenantData(currentUser.tenantId)} disabled={loading} className="btn-minimal" style={{ padding: '5px 10px' }}>
            <span>🔄</span> {loading ? 'Syncing...' : 'Sync'}
          </button>

          <button onClick={toggleTheme} className="btn-minimal" style={{ padding: '5px 10px' }}>
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>

          <button onClick={handleSignOut} className="btn-minimal-danger" style={{ padding: '5px 10px', fontSize: '0.78rem' }}>
            Sign Out
          </button>
        </div>
      </header>

      {/* Prominent Real-Time AI Threat Response & Working Console */}
      <section style={{
        background: aiopsData.healthStatus === 'CRITICAL' ? 'var(--color-rose-subtle)' : aiopsData.healthStatus === 'DEGRADED' ? 'var(--color-amber-subtle)' : 'var(--bg-surface)',
        border: `1px solid ${aiopsData.healthStatus === 'CRITICAL' ? 'rgba(244, 63, 94, 0.35)' : aiopsData.healthStatus === 'DEGRADED' ? 'rgba(245, 158, 11, 0.35)' : 'var(--border-subtle)'}`,
        borderRadius: '8px',
        padding: '14px 18px',
        marginBottom: '16px',
      }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span
              className={aiopsData.healthStatus !== 'HEALTHY' ? 'status-dot-active' : ''}
              style={{
                width: '10px',
                height: '10px',
                borderRadius: '50%',
                background: getStatusColor(aiopsData.healthStatus),
                display: 'inline-block',
              }}
            />
            <span style={{ fontSize: '0.84rem', fontWeight: '700', letterSpacing: '0.2px' }}>
              AI THREAT RESPONSE & AUTONOMOUS REASONING CONSOLE
            </span>
            <span className="badge-minimal" style={{
              background: 'var(--accent-subtle)',
              color: 'var(--accent)',
              border: '1px solid var(--border-accent)',
            }}>
              Heuristic Classifier v2.4 · 98.4% Confidence
            </span>
          </div>

          {aiopsData.healthStatus !== 'HEALTHY' && (
            <button
              onClick={() => handleRunSimulation('baseline')}
              disabled={loading}
              className="btn-minimal-primary"
              style={{ fontSize: '0.76rem', padding: '4px 12px' }}
            >
              <span>✓</span> Apply AI Autonomous Mitigation (Restore Baseline)
            </button>
          )}
        </div>

        {/* AI Cognitive Steps / Active Reasoning Stream */}
        {aiReasoningSteps.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '8px', marginTop: '6px' }}>
            {aiReasoningSteps.map((step, idx) => (
              <div key={idx} style={{
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '8px 12px',
                fontSize: '0.76rem',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '3px' }}>
                  <span style={{ fontWeight: '600', color: step.status === 'CRITICAL' ? 'var(--color-rose)' : step.status === 'ALERT' ? 'var(--color-amber)' : 'var(--accent)' }}>
                    Step {idx + 1}: {step.title}
                  </span>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>{step.time}</span>
                </div>
                <p style={{ color: 'var(--text-secondary)', margin: 0, fontSize: '0.73rem', lineHeight: '1.4' }}>
                  {step.desc}
                </p>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
            [IDLE] AI correlation daemon monitoring ingress telemetry. Ready for threat interception. Trigger a simulation below to observe real-time AI reasoning.
          </div>
        )}
      </section>

      {/* Simulation Command Strip */}
      <section style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '6px',
        padding: '10px 14px',
        marginBottom: '16px',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '10px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '0.78rem', fontWeight: '600', color: 'var(--text-muted)' }}>
            SIMULATE OPERATIONAL EVENTS:
          </span>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
          <button
            onClick={() => handleRunSimulation('data_leaks')}
            disabled={loading}
            className="btn-minimal"
            style={{ borderColor: 'rgba(244, 63, 94, 0.4)', color: 'var(--color-rose)', fontSize: '0.76rem', padding: '5px 11px' }}
            title="Simulate employee leaking OpenAI/AWS keys and PCI card numbers, intercepted by DLP"
          >
            <span>🔒</span> Sensitive Data Leak (DLP)
          </button>

          <button
            onClick={() => handleRunSimulation('failed_logins')}
            disabled={loading}
            className="btn-minimal"
            style={{ borderColor: 'rgba(244, 63, 94, 0.4)', color: 'var(--color-rose)', fontSize: '0.76rem', padding: '5px 11px' }}
            title="Simulate botnet credential stuffing & SQL injection bypass attempt"
          >
            <span>🛡️</span> SQLi / Brute-Force Attack
          </button>

          <button
            onClick={() => handleRunSimulation('outages')}
            disabled={loading}
            className="btn-minimal"
            style={{ fontSize: '0.76rem', padding: '5px 11px' }}
            title="Simulate cascading database crash and connection pool timeout"
          >
            <span>💥</span> Cascading Service Outage
          </button>

          <button
            onClick={() => handleRunSimulation('spikes')}
            disabled={loading}
            className="btn-minimal"
            style={{ fontSize: '0.76rem', padding: '5px 11px' }}
            title="Simulate sudden compute resource saturation & latency breach"
          >
            <span>⚡</span> Latency / CPU Surge
          </button>

          <button
            onClick={() => handleRunSimulation('baseline')}
            disabled={loading}
            className="btn-minimal"
            style={{ borderColor: 'rgba(16, 185, 129, 0.4)', color: 'var(--color-emerald)', fontSize: '0.76rem', padding: '5px 11px' }}
            title="Reset telemetry partition back to clean baseline"
          >
            <span>🔄</span> Reset to Baseline
          </button>
        </div>
      </section>

      {/* Notifications */}
      {actionMessage && (
        <div style={{
          padding: '8px 14px',
          borderRadius: '6px',
          marginBottom: '16px',
          fontSize: '0.8rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          backgroundColor: actionMessage.type === 'error' ? 'var(--color-rose-subtle)' : actionMessage.type === 'warning' ? 'var(--color-amber-subtle)' : 'var(--accent-subtle)',
          border: `1px solid ${actionMessage.type === 'error' ? 'rgba(244, 63, 94, 0.3)' : actionMessage.type === 'warning' ? 'rgba(245, 158, 11, 0.3)' : 'var(--border-accent)'}`,
          color: actionMessage.type === 'error' ? 'var(--color-rose)' : actionMessage.type === 'warning' ? 'var(--color-amber)' : 'var(--text-primary)',
        }}>
          <span>{actionMessage.text}</span>
          <button onClick={() => setActionMessage(null)} style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '0.85rem' }}>✕</button>
        </div>
      )}

      {/* Navigation Tabs */}
      <nav style={{
        display: 'flex',
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: '18px',
        gap: '4px',
        overflowX: 'auto',
      }}>
        {[
          { id: 'overview', label: '📊 Incidents & Health RCA' },
          { id: 'collector', label: '🛡️ Edge Local Collector (Tier 1)' },
          { id: 'saas', label: '🏢 SaaS Telemetry Engine (Tier 2)' },
          { id: 'playground', label: '🧪 Collector Playground (Automated)' },
          { id: 'api', label: '🔌 Endpoints & Architecture' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === tab.id ? '2px solid var(--accent)' : '2px solid transparent',
              color: activeTab === tab.id ? 'var(--text-primary)' : 'var(--text-secondary)',
              padding: '8px 14px',
              fontSize: '0.82rem',
              fontWeight: activeTab === tab.id ? '600' : '400',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
            }}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* TAB 1: Incidents & Health RCA */}
      {activeTab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '16px' }}>
          {/* Domain Health Radar */}
          <div className="card-minimal" style={{ padding: '18px' }}>
            <h3 style={{ fontSize: '0.88rem', fontWeight: '600', marginBottom: '12px' }}>
              Operational Domain Status
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {Object.entries(aiopsData.categoryHealth || {}).map(([cat, stats]) => (
                <div key={cat} style={{ background: 'var(--bg-canvas)', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '5px' }}>
                    <span style={{ textTransform: 'capitalize', fontWeight: '600', fontSize: '0.8rem' }}>{cat}</span>
                    <span style={{ fontSize: '0.78rem', fontWeight: '600', color: getStatusColor(stats.status) }}>
                      {stats.score} / 100 [{stats.status}]
                    </span>
                  </div>
                  <div style={{ width: '100%', height: '4px', background: 'var(--border-subtle)', borderRadius: '2px', overflow: 'hidden' }}>
                    <div style={{
                      width: `${stats.score}%`,
                      height: '100%',
                      background: getStatusColor(stats.status),
                      transition: 'width 0.4s ease',
                    }} />
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                    <span>Events: {stats.eventCount}</span>
                    <span>Critical: {stats.criticalCount}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Anomaly Detection Radar */}
          <div className="card-minimal" style={{ padding: '18px' }}>
            <h3 style={{ fontSize: '0.88rem', fontWeight: '600', marginBottom: '12px' }}>
              Statistical Outlier Anomaly Detection (Z ≥ 2.0)
            </h3>
            {(!aiopsData.anomalies || aiopsData.anomalies.length === 0) ? (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                All metric series conform to established baselines.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '340px', overflowY: 'auto' }}>
                {aiopsData.anomalies.slice(0, 6).map((anom, idx) => (
                  <div key={idx} style={{
                    background: 'var(--bg-canvas)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '8px 12px',
                    fontSize: '0.76rem',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                      <strong style={{ color: 'var(--color-rose)' }}>{anom.sourceAlias} [{anom.category}]</strong>
                      <span style={{ color: 'var(--text-muted)' }}>Score: {anom.anomalyScore}</span>
                    </div>
                    <ul style={{ paddingLeft: '16px', color: 'var(--text-secondary)', margin: 0 }}>
                      {anom.reasons?.map((r, rIdx) => <li key={rIdx}>{r}</li>)}
                    </ul>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Correlated Incidents & Root Cause Analysis */}
          <div className="card-minimal" style={{ gridColumn: '1 / -1', padding: '18px' }}>
            <h3 style={{ fontSize: '0.92rem', fontWeight: '600', marginBottom: '14px' }}>
              Correlated Incident Records & Explainable Root Cause Analysis (RCA)
            </h3>

            {(!aiopsData.incidents || aiopsData.incidents.length === 0) ? (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                No active correlated incidents. Partition {currentUser.tenantId} is operating within nominal thresholds.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {aiopsData.incidents.map((inc) => (
                  <div key={inc.incidentId} style={{
                    background: 'var(--bg-canvas)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '16px',
                  }}>
                    <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="badge-minimal" style={{
                          background: 'var(--color-rose-subtle)',
                          color: 'var(--color-rose)',
                          border: '1px solid rgba(244, 63, 94, 0.3)',
                        }}>
                          {inc.severity}
                        </span>
                        <h4 style={{ fontSize: '0.88rem', fontWeight: '600' }}>{inc.title}</h4>
                      </div>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        Status: <strong>{inc.status}</strong> · Correlated events: {inc.eventCount}
                      </span>
                    </div>

                    {/* RCA Box */}
                    {inc.rca && (
                      <div style={{
                        background: 'var(--bg-surface)',
                        borderLeft: '3px solid var(--accent)',
                        padding: '10px 14px',
                        borderRadius: '0 6px 6px 0',
                        marginBottom: '12px',
                      }}>
                        <span style={{ fontSize: '0.7rem', fontWeight: '600', color: 'var(--accent)', textTransform: 'uppercase' }}>
                          Diagnostic Root Cause Narrative (Confidence: {Math.round((inc.rca.confidence || 0.8) * 100)}%)
                        </span>
                        <p style={{ fontSize: '0.82rem', color: 'var(--text-primary)', marginTop: '3px', marginBottom: '6px' }}>
                          {inc.rca.probableRootCause}
                        </p>
                        {inc.rca.causalChain && inc.rca.causalChain.length > 0 && (
                          <div style={{ fontSize: '0.73rem', color: 'var(--text-secondary)' }}>
                            <strong>Causal propagation:</strong> {inc.rca.causalChain.join(' → ')}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Prescriptive Remediation Runbooks */}
                    {inc.recommendations && inc.recommendations.length > 0 && (
                      <div>
                        <span style={{ fontSize: '0.72rem', fontWeight: '600', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                          Prescriptive Remediation Runbooks:
                        </span>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '8px', marginTop: '6px' }}>
                          {inc.recommendations.map((rec) => (
                            <div key={rec.id} style={{
                              background: 'var(--bg-surface)',
                              border: '1px solid var(--border-subtle)',
                              borderRadius: '4px',
                              padding: '10px 12px',
                            }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '3px' }}>
                                <strong style={{ fontSize: '0.76rem' }}>{rec.title}</strong>
                                <span style={{ fontSize: '0.68rem', color: 'var(--color-amber)', fontWeight: '600' }}>{rec.priority}</span>
                              </div>
                              <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: '5px' }}>
                                {rec.description}
                              </p>
                              {rec.command && (
                                <code style={{
                                  display: 'block',
                                  background: 'var(--code-bg)',
                                  border: '1px solid var(--border-subtle)',
                                  padding: '4px 8px',
                                  borderRadius: '4px',
                                  fontSize: '0.7rem',
                                  color: 'var(--accent)',
                                  fontFamily: 'var(--font-mono)',
                                }}>
                                  $ {rec.command}
                                </code>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Decoupled Tier 1: Edge Local Collector */}
      {activeTab === 'collector' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="card-minimal" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <div>
                <h3 style={{ fontSize: '0.95rem', fontWeight: '600' }}>
                  Edge Local Collector Agent (Client Perimeter Tier)
                </h3>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  Runs as a local edge daemon or Kubernetes sidecar. Strips 100% of raw user content, executes Data Loss Prevention (DLP) regex filters, drops malicious exploits, and forwards only clean metadata to the upstream SaaS platform.
                </p>
              </div>
              <span className="badge-minimal" style={{ background: 'var(--color-emerald-subtle)', color: 'var(--color-emerald)', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                DAEMON LISTENING: 127.0.0.1:8081
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', marginBottom: '16px' }}>
              <div style={{ background: 'var(--bg-canvas)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>RAW FIELDS STRIPPED</span>
                <div style={{ fontSize: '1.4rem', fontWeight: '700', marginTop: '2px', color: 'var(--text-primary)' }}>
                  {collectorStats.rawFieldsStrippedCount}
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--accent)' }}>Zero raw data forwarded</span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DLP LEAKS PURGED</span>
                <div style={{ fontSize: '1.4rem', fontWeight: '700', marginTop: '2px', color: 'var(--color-rose)' }}>
                  {collectorStats.leaksPrevented}
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--color-rose)' }}>Secrets scrubbed</span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>ATTACKS INTERCEPTED</span>
                <div style={{ fontSize: '1.4rem', fontWeight: '700', marginTop: '2px', color: 'var(--color-purple)' }}>
                  {collectorStats.attacksBlocked}
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--color-purple)' }}>SQLi, XSS & Floods blocked</span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>METADATA DISPATCHED</span>
                <div style={{ fontSize: '1.4rem', fontWeight: '700', marginTop: '2px', color: 'var(--color-emerald)' }}>
                  {collectorStats.metadataForwarded}
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--color-emerald)' }}>Conforming to allow-list</span>
              </div>
            </div>

            {/* Active Edge Security Inspection Policies */}
            <h4 style={{ fontSize: '0.82rem', fontWeight: '600', marginBottom: '8px' }}>
              Active Edge Inspection Policies (Regex Heuristic Rules)
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '8px', fontSize: '0.74rem' }}>
              {[
                { name: 'API Key & Cloud Secrets Scanner', pattern: 'sk-..., AKIA..., ghp_..., xoxb-...', action: 'Purged by DLP', hits: collectorStats.leakBreakdown?.API_KEY || 0 },
                { name: 'Bearer & JWT Session Tokens', pattern: 'Bearer eyJhbGciOi...', action: 'Purged by DLP', hits: collectorStats.leakBreakdown?.BEARER_TOKEN || 0 },
                { name: 'Plaintext Passwords & Auth Headers', pattern: 'password=..., authorization=...', action: 'Redacted (Tenant Only)', hits: collectorStats.leakBreakdown?.PASSWORD || 0 },
                { name: 'Payment Card (PCI-DSS) Scanner', pattern: '4xxx-xxxx-xxxx-xxxx, 5xxx-...', action: 'Purged by DLP', hits: collectorStats.leakBreakdown?.CREDIT_CARD || 0 },
                { name: 'SQL Injection Firewall Signature', pattern: "UNION SELECT, OR 1=1, DROP TABLE", action: 'HTTP 403 Dropped', hits: collectorStats.attackBreakdown?.SQL_INJECTION || 0 },
                { name: 'Volumetric Flood / DDoS Limiter', pattern: '> 250 requests / 10s sliding window', action: 'HTTP 429 Throttled', hits: collectorStats.attackBreakdown?.RATE_LIMIT_EXCEEDED || 0 },
              ].map((rule, idx) => (
                <div key={idx} style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '4px', padding: '8px 10px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                    <strong>{rule.name}</strong>
                    <span style={{ color: rule.hits > 0 ? 'var(--color-rose)' : 'var(--text-muted)', fontWeight: '600' }}>{rule.hits} Hits</span>
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.68rem' }}>Pattern: {rule.pattern}</div>
                  <div style={{ color: 'var(--accent)', fontSize: '0.68rem', marginTop: '2px' }}>Enforcement: {rule.action}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Decoupled Tier 2: Central SaaS Telemetry Engine */}
      {activeTab === 'saas' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="card-minimal" style={{ padding: '20px' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: '600', marginBottom: '4px' }}>
              Central Multi-Tenant SaaS Engine (Cloud Platform Tier)
            </h3>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '14px' }}>
              Central backend ingestion gateway receiving privacy-preserving metadata from edge collectors. Enforces strict row-level tenant partitioning, allow-list key schema validation, deduplication, and out-of-order timeline healing.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px', marginBottom: '16px' }}>
              <div style={{ background: 'var(--bg-canvas)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>ISOLATED PARTITION ID</span>
                <div style={{ fontSize: '1.05rem', fontWeight: '600', marginTop: '2px' }}>{currentUser.tenantId}</div>
                <span style={{ fontSize: '0.68rem', color: 'var(--color-emerald)' }}>● Cross-tenant visibility blocked</span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>ALLOW-LIST SCHEMA FIREWALL</span>
                <div style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', marginTop: '4px', color: 'var(--text-secondary)' }}>
                  payloadId, tenantId, region, sourceAlias, category, severity, metrics, summary
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--accent)' }}>● Unknown keys stripped to ring buffer</span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DEDUPLICATION & HEALING</span>
                <div style={{ fontSize: '1.05rem', fontWeight: '600', marginTop: '2px' }}>
                  Idempotency Active
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--color-emerald)' }}>● Chronological UTC healing enabled</span>
              </div>
            </div>

            <div style={{ background: 'var(--accent-subtle)', border: '1px solid var(--border-accent)', borderRadius: '6px', padding: '12px 16px', fontSize: '0.78rem' }}>
              <strong>Architecture Separation Guarantee:</strong> Edge collectors operate entirely autonomously and do not share in-memory state with the central SaaS store. Data transmitted across tiers contains zero raw user data, fulfilling zero-trust privacy mandates.
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: Automated Collector Playground */}
      {activeTab === 'playground' && (
        <div className="card-minimal" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px', flexWrap: 'wrap', gap: '8px' }}>
            <div>
              <h3 style={{ fontSize: '0.95rem', fontWeight: '600' }}>
                Collector Playground (Automated Verification)
              </h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                This inspector demonstrates zero-raw data leakage. Click any simulation button above or preset below to inspect the un-sanitized raw payload vs the sanitized privacy-preserving metadata forwarding.
              </p>
            </div>
            <span className="badge-minimal" style={{ background: 'var(--accent-subtle)', color: 'var(--accent)', border: '1px solid var(--border-accent)' }}>
              AUTOMATED AFTER SIMULATION
            </span>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '14px' }}>
            <button
              onClick={() => {
                setPlaygroundInput(JSON.stringify(SCENARIO_RAW_PAYLOADS.data_leaks, null, 2));
              }}
              className="btn-minimal"
              style={{ fontSize: '0.74rem' }}
            >
              Preset: Credential Leak Attempt (DLP)
            </button>
            <button
              onClick={() => {
                setPlaygroundInput(JSON.stringify(SCENARIO_RAW_PAYLOADS.failed_logins, null, 2));
              }}
              className="btn-minimal"
              style={{ fontSize: '0.74rem' }}
            >
              Preset: SQLi Injection Attack (Shield)
            </button>
            <button
              onClick={() => {
                setPlaygroundInput(JSON.stringify(SCENARIO_RAW_PAYLOADS.spikes, null, 2));
              }}
              className="btn-minimal"
              style={{ fontSize: '0.74rem' }}
            >
              Preset: Latency & CPU Spike
            </button>
            <button
              onClick={() => {
                setPlaygroundInput(JSON.stringify(SCENARIO_RAW_PAYLOADS.baseline, null, 2));
              }}
              className="btn-minimal"
              style={{ fontSize: '0.74rem' }}
            >
              Preset: Clean Baseline Telemetry
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '14px' }}>
            <div>
              <label style={{ fontSize: '0.74rem', fontWeight: '600', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                INPUT: RAW USER PAYLOAD (CONTAINING UN-SANITIZED CONTENT / CREDENTIALS)
              </label>
              <textarea
                value={playgroundInput}
                onChange={(e) => setPlaygroundInput(e.target.value)}
                rows={14}
                style={{
                  width: '100%',
                  background: 'var(--code-bg)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '12px',
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.76rem',
                  outline: 'none',
                }}
              />
              <button
                onClick={handleManualPlaygroundSubmit}
                disabled={playgroundRunning}
                className="btn-minimal-primary"
                style={{ marginTop: '8px', fontSize: '0.78rem' }}
              >
                {playgroundRunning ? 'Sanitizing...' : 'Dispatch to Edge Collector'}
              </button>
            </div>

            <div>
              <label style={{ fontSize: '0.74rem', fontWeight: '600', color: 'var(--text-secondary)', display: 'block', marginBottom: '4px' }}>
                OUTPUT: SANITIZED METADATA TELEMETRY (ZERO RAW DATA / LEAKS REDACTED)
              </label>
              <pre style={{
                background: 'var(--code-bg)',
                border: `1px solid ${playgroundResult?.httpStatus === 403 ? 'var(--color-rose)' : 'var(--border-subtle)'}`,
                borderRadius: '6px',
                padding: '12px',
                color: playgroundResult?.httpStatus === 403 ? 'var(--color-rose)' : 'var(--accent)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.76rem',
                minHeight: '280px',
                maxHeight: '400px',
                overflowY: 'auto',
                whiteSpace: 'pre-wrap',
              }}>
                {playgroundResult ? JSON.stringify(playgroundResult, null, 2) : '// Output will display here automatically after every simulation'}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: Endpoints & Architecture */}
      {activeTab === 'api' && (
        <div className="card-minimal" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: '600', marginBottom: '12px' }}>
            System Architecture & REST Endpoints
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'var(--font-mono)' }}>
            {[
              { method: 'POST', endpoint: '/api/simulate', desc: 'Simulates telemetry ("data_leaks", "failed_logins", "outages", "spikes", "baseline") with live AIOps scoring.' },
              { method: 'POST', endpoint: '/api/collector', desc: 'Edge collector: strips raw fields, DLP leak purge, threat shield, metadata forwarding.' },
              { method: 'GET', endpoint: '/api/collector', desc: 'Edge collector health, local buffer capacity, leak purge tallies, attack mitigation audits.' },
              { method: 'GET', endpoint: '/api/aiops?tenantId={id}', desc: 'Central AIOps intelligence: health score, anomaly detection, incident correlation, RCA.' },
              { method: 'POST', endpoint: '/api/auth?action=signup', desc: 'Registers isolated tenant partition with scrypt-hashed credentials and random salt.' },
              { method: 'POST', endpoint: '/api/auth?action=signin', desc: 'Constant-time authentication for email/mobile + password.' },
            ].map((api, idx) => (
              <div key={idx} style={{
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '9px 12px',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                flexWrap: 'wrap',
              }}>
                <span className="badge-minimal" style={{
                  background: api.method === 'POST' ? 'var(--accent-subtle)' : 'var(--color-emerald-subtle)',
                  color: api.method === 'POST' ? 'var(--accent)' : 'var(--color-emerald)',
                  border: `1px solid ${api.method === 'POST' ? 'var(--border-accent)' : 'rgba(16, 185, 129, 0.3)'}`,
                }}>
                  {api.method}
                </span>
                <code style={{ fontSize: '0.78rem', fontWeight: '600' }}>{api.endpoint}</code>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginLeft: 'auto', fontFamily: 'inherit' }}>
                  {api.desc}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Professional Footer */}
      <footer style={{
        marginTop: '36px',
        paddingTop: '14px',
        borderTop: '1px solid var(--border-subtle)',
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        fontSize: '0.74rem',
        color: 'var(--text-muted)',
        gap: '10px',
      }}>
        <div>Cicada Telemetry & AIOps Platform · Enterprise Multi-Tenant Observability</div>
        <div>Tier 1 Edge Collector & Tier 2 SaaS Engine Decoupled · Row-Level Partition Isolation Enforced</div>
      </footer>
    </div>
  );
}
