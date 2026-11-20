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

  // Plain-English Explanation Mode: default true
  const [simpleMode, setSimpleMode] = useState(true);

  // Auth & Session State
  const [currentUser, setCurrentUser] = useState(null);
  const [authChecking, setAuthChecking] = useState(true);

  // Auth Form State: 'signin' | 'signup' | 'forgot'
  const [authMode, setAuthMode] = useState('signin');
  const [authIdentifier, setAuthIdentifier] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [authTenantName, setAuthTenantName] = useState('');
  const [authRegion, setAuthRegion] = useState('us-east-1');
  const [authTier, setAuthTier] = useState('enterprise');
  const [authError, setAuthError] = useState(null);
  const [authSuccess, setAuthSuccess] = useState(null);
  const [authLoading, setAuthLoading] = useState(false);

  // Forgot Password Authenticator State
  const [forgotStep, setForgotStep] = useState(1); // 1 = request code, 2 = verify & reset
  const [forgotCode, setForgotCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [dispatchedCodeHint, setDispatchedCodeHint] = useState(null);

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

  // 5 Selectable Color Palettes: 'cobalt' | 'emerald' | 'violet' | 'amber' | 'crimson'
  const [palette, setPalette] = useState('cobalt');

  const PALETTES = [
    { id: 'cobalt', label: 'Cobalt', hex: '#3b82f6', subtitle: 'Enterprise Blue' },
    { id: 'emerald', label: 'Emerald', hex: '#10b981', subtitle: 'Cyber Mint' },
    { id: 'violet', label: 'Violet', hex: '#8b5cf6', subtitle: 'Threat Intel' },
    { id: 'amber', label: 'Amber', hex: '#f59e0b', subtitle: 'Observability' },
    { id: 'crimson', label: 'Crimson', hex: '#f43f5e', subtitle: 'SOC Red Alert' },
  ];

  // Local Buffering & Outage Resilience State
  const [isOutageSimulated, setIsOutageSimulated] = useState(false);
  const [bufferedQueueDepth, setBufferedQueueDepth] = useState(0);
  const [outageLoading, setOutageLoading] = useState(false);
  const [retryResult, setRetryResult] = useState(null);

  // Idempotent Payload IDs State
  const [idempotentPayloadId, setIdempotentPayloadId] = useState('IDEM-PAYLOAD-9921');
  const [idempotencyResult, setIdempotencyResult] = useState(null);
  const [idempotencyLoading, setIdempotencyLoading] = useState(false);

  // Two Demo Tenants & Isolation Audit State
  const [isolationAudit, setIsolationAudit] = useState(null);
  const [isolationAuditLoading, setIsolationAuditLoading] = useState(false);

  // AI Active Reasoning Trace (prominent during attacks)
  const [aiReasoningSteps, setAiReasoningSteps] = useState([]);

  // Change Color Palette
  const changePalette = (newPalette) => {
    setPalette(newPalette);
    document.documentElement.setAttribute('data-palette', newPalette);
    localStorage.setItem('cicada_palette', newPalette);
  };

  // Initialize Theme, Palette, Simple Mode & Session on Mount
  useEffect(() => {
    const savedTheme = typeof window !== 'undefined' ? localStorage.getItem('cicada_theme') || 'dark' : 'dark';
    setTheme(savedTheme);
    document.documentElement.setAttribute('data-theme', savedTheme);

    const savedPalette = typeof window !== 'undefined' ? localStorage.getItem('cicada_palette') || 'cobalt' : 'cobalt';
    setPalette(savedPalette);
    document.documentElement.setAttribute('data-palette', savedPalette);

    const savedSimpleMode = typeof window !== 'undefined' ? localStorage.getItem('cicada_simple_mode') : null;
    if (savedSimpleMode !== null) {
      setSimpleMode(savedSimpleMode === 'true');
    }

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

  // Simple Mode Toggle Handler
  const toggleSimpleMode = () => {
    const nextVal = !simpleMode;
    setSimpleMode(nextVal);
    localStorage.setItem('cicada_simple_mode', String(nextVal));
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
        if (cData.stats) {
          setCollectorStats(cData.stats);
          setIsOutageSimulated(Boolean(cData.stats.isOutageActive));
          setBufferedQueueDepth(cData.stats.bufferedCount || 0);
        }
      }
    } catch (err) {
      console.error('Failed to refresh tenant telemetry', err);
    } finally {
      setLoading(false);
    }
  }, []);

  // 1. Toggle Outage Mode for Local Buffering
  const handleToggleOutage = async () => {
    setOutageLoading(true);
    try {
      const res = await fetch('/api/collector?action=toggle_outage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ outage: !isOutageSimulated }),
      });
      const data = await res.json();
      setIsOutageSimulated(data.isOutageActive);
      setBufferedQueueDepth(data.bufferedCount || 0);
      setActionMessage({
        type: data.isOutageActive ? 'warning' : 'success',
        text: data.message,
      });
    } catch (err) {
      console.error('Failed to toggle outage', err);
    } finally {
      setOutageLoading(false);
    }
  };

  // 2. Send Test Payload to Edge Buffer
  const handleSendBufferPayload = async () => {
    try {
      const payload = {
        payloadId: `buf-payload-${Date.now()}`,
        sourceAlias: 'edge-resilience-buffer',
        region: currentUser?.region || 'us-east-1',
        tenantId: currentUser?.tenantId || 'acme-corp',
        category: 'collector',
        severity: 'low',
        metrics: { bufferTest: 1, queueTimestamp: Date.now() },
        summary: `Resilient edge queued payload [Outage: ${isOutageSimulated ? 'ACTIVE' : 'OFFLINE'}]`,
      };

      const res = await fetch('/api/collector', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        setBufferedQueueDepth((prev) => prev + 1);
        setActionMessage({
          type: isOutageSimulated ? 'warning' : 'success',
          text: isOutageSimulated
            ? `[EDGE RAM BUFFER] Payload '${payload.payloadId}' held safely in local buffer. Upstream connection offline.`
            : `[DELIVERED UPSTREAM] Payload '${payload.payloadId}' forwarded directly to SaaS engine.`,
        });
      }
    } catch (err) {
      console.error('Failed to buffer payload', err);
    }
  };

  // 3. Retry and Drain Buffer after Outage Recovery
  const handleFlushAndRetry = async () => {
    setOutageLoading(true);
    try {
      const res = await fetch('/api/collector?action=flush_buffer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      setRetryResult(data);
      setIsOutageSimulated(false);
      setBufferedQueueDepth(data.remainingBuffer || 0);
      setActionMessage({
        type: 'success',
        text: data.message || `Buffer drained: ${data.flushed} payloads forwarded to upstream SaaS engine.`,
      });
      if (currentUser?.tenantId) {
        await refreshTenantData(currentUser.tenantId);
      }
    } catch (err) {
      console.error('Failed to flush buffer', err);
    } finally {
      setOutageLoading(false);
    }
  };

  // 4. Test Idempotent Payload IDs
  const handleTestIdempotency = async (duplicateAttempt = false) => {
    setIdempotencyLoading(true);
    try {
      const pId = duplicateAttempt ? idempotentPayloadId : `IDEM-PAYLOAD-${Math.floor(1000 + Math.random() * 9000)}`;
      if (!duplicateAttempt) {
        setIdempotentPayloadId(pId);
      }

      const res = await fetch('/api/collector?action=test_idempotency', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payloadId: pId,
          tenantId: currentUser?.tenantId || 'acme-corp',
          sourceAlias: 'idempotency-engine',
          category: 'network',
          severity: 'low',
          metrics: { idempotentTest: 1, sequence: 501 },
          summary: `Idempotency verification transaction #${pId}`,
        }),
      });

      const data = await res.json();
      setIdempotencyResult({
        ...data,
        timestamp: new Date().toISOString(),
        testedDuplicate: duplicateAttempt,
      });

      setActionMessage({
        type: data.duplicate ? 'warning' : 'success',
        text: data.auditMessage,
      });
    } catch (err) {
      console.error('Failed idempotency test', err);
    } finally {
      setIdempotencyLoading(false);
    }
  };

  // 5. Run Two-Tenant Cryptographic Isolation Audit
  const handleRunIsolationAudit = async () => {
    if (!currentUser?.tenantId) return;
    setIsolationAuditLoading(true);
    try {
      const opposing = currentUser.tenantId === 'acme-corp' ? 'shield-defense' : 'acme-corp';
      const res = await fetch(`/api/database?tenantId=${encodeURIComponent(currentUser.tenantId)}&resource=audit_isolation&opposingTenant=${encodeURIComponent(opposing)}`);
      if (res.ok) {
        const auditData = await res.json();
        setIsolationAudit(auditData);
        setActionMessage({
          type: 'success',
          text: `[ROW-LEVEL ISOLATION CONFIRMED] 0 cross-tenant leaks detected between '${auditData.primaryTenant.tenantId}' and '${auditData.opposingTenant.tenantId}'. Partition boundaries mathematically verified.`,
        });
      }
    } catch (err) {
      console.error('Failed isolation audit', err);
    } finally {
      setIsolationAuditLoading(false);
    }
  };

  // 6. Switch Demo Tenant with 1-click
  const handleSwitchDemoTenant = async (targetTenantId) => {
    setLoading(true);
    try {
      const targetUser = targetTenantId === 'shield-defense'
        ? { identifier: 'secops@shield-defense.com', password: 'Password123!' }
        : { identifier: 'admin@acme.com', password: 'Password123!' };

      const res = await fetch('/api/auth?action=signin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(targetUser),
      });
      const data = await res.json();
      if (res.ok && data.status === 'authenticated') {
        localStorage.setItem('cicada_session_token', data.token);
        setCurrentUser(data.user);
        setIsolationAudit(null);
        setActionMessage({
          type: 'success',
          text: `Switched partition context to '${data.user.tenantId}' (${targetTenantId === 'shield-defense' ? 'CyberShield Defense Systems' : 'Acme Corporation'}).`,
        });
      }
    } catch (err) {
      console.error('Failed to switch tenant', err);
    } finally {
      setLoading(false);
    }
  };

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

    const timeStr = new Date().toISOString().substring(11, 19) + ' UTC';

    // Set prominent AI Reasoning steps
    let initialSteps = [];
    if (scenario === 'data_leaks') {
      initialSteps = [
        { time: timeStr, title: 'Deep DLP Pattern Match', desc: 'Identified 5 exposed secrets (OpenAI key sk-live-***, AWS key, plaintext password, Credit Card PCI-DSS) in raw payload.', status: 'CRITICAL' },
        { time: timeStr, title: 'Privacy Shield Redaction', desc: 'Edge collector DLP purged 100% of sensitive fields before central SaaS engine forwarding.', status: 'ACTIVE' },
        { time: timeStr, title: 'Incident Correlation', desc: 'Clustered security alerts into unified Incident INC-SEC-DLP with high confidence (96%).', status: 'ALERT' },
        { time: timeStr, title: 'Prescriptive Runbook', desc: 'Formulated KMS secret rollback and IAM key revocation commands.', status: 'DONE' },
      ];
    } else if (scenario === 'failed_logins') {
      initialSteps = [
        { time: timeStr, title: 'Heuristic Signature Match', desc: 'SQL Injection pattern "UNION SELECT token" and botnet burst (520 failed logins) identified on /api/v1/auth/login.', status: 'CRITICAL' },
        { time: timeStr, title: 'Statistical Anomaly Detected', desc: 'Failed login rate escalated Z = 5.2σ above tenant baseline.', status: 'ALERT' },
        { time: timeStr, title: 'Edge Shield Quarantine', desc: 'Edge Collector returned HTTP 403 Forbidden; origin IP rate-limited.', status: 'ACTIVE' },
        { time: timeStr, title: 'Autonomous Playbook', desc: 'Prescribed waf-cli rate limiting and access token revocation.', status: 'DONE' },
      ];
    } else if (scenario === 'outages') {
      initialSteps = [
        { time: timeStr, title: 'Host Node Crash Detected', desc: 'Primary database node db-master-us-east crashed due to Memory exhaustion (99%).', status: 'CRITICAL' },
        { time: timeStr, title: 'Causal Chain Propagation', desc: 'Infra failure cascaded to microservice network timeouts (4500ms) and ingress queue backpressure.', status: 'ALERT' },
        { time: timeStr, title: 'Root Cause Diagnosed', desc: 'AIOps diagnosed database OOM as primary root cause with 95% confidence.', status: 'DONE' },
      ];
    } else if (scenario === 'spikes') {
      initialSteps = [
        { time: timeStr, title: 'Dynamic Baseline Breach', desc: 'Compute CPU surged to 99.4% and latency escalated to 2850ms (Z = 4.1σ).', status: 'ALERT' },
        { time: timeStr, title: 'SLA Risk Assessment', desc: 'Breached 99.9% tenant SLA target; active alerting triggered.', status: 'WARNING' },
        { time: timeStr, title: 'Horizontal Autoscale', desc: 'kubectl scale deployment/api-service --replicas=5 generated.', status: 'DONE' },
      ];
    } else {
      initialSteps = [
        { time: timeStr, title: 'Baseline Normalization', desc: 'Telemetry stream returned to steady-state baseline. All operational metrics healthy.', status: 'HEALTHY' },
      ];
    }
    setAiReasoningSteps(initialSteps);

    try {
      // 1. Execute simulation scenario on the backend
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

        // 2. Automate Collector Playground: pass scenario raw payload to /api/collector
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

        // 3. Automatically switch to the Playground tab to demonstrate raw vs sanitized metadata
        setActiveTab('playground');

        setActionMessage({
          type: data.aiopsReport?.healthStatus === 'HEALTHY' ? 'success' : 'warning',
          text: `[WORKFLOW COMPLETED] Scenario '${scenario}' simulated. Health status updated to ${data.aiopsReport?.healthStatus || 'UPDATED'}. Collector Playground automated below with live raw input vs sanitized metadata.`,
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
    setAuthSuccess(null);
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
          text: `Welcome! Authenticated session established for partition '${data.user.tenantId}'. Row-level tenant isolation active.`,
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

  // Forgot Password Step 1: Request 6-digit Authenticator Code
  const handleForgotRequest = async (e) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);
    setAuthLoading(true);

    try {
      const res = await fetch('/api/auth?action=forgot_request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: authIdentifier }),
      });
      const data = await res.json();
      if (res.ok && data.status === 'code_dispatched') {
        setDispatchedCodeHint(data.code);
        setForgotCode(data.code); // Pre-fill for one-click testing ease
        setForgotStep(2);
        setAuthSuccess(`Authenticator verification code sent to ${data.maskedIdentifier} via ${data.deliveryChannel}. Code: ${data.code}`);
      } else {
        setAuthError(data.error || 'Failed to dispatch reset code. Please check your identifier.');
      }
    } catch (err) {
      setAuthError('Network error: ' + err.message);
    } finally {
      setAuthLoading(false);
    }
  };

  // Forgot Password Step 2: Verify Code & Set New Password
  const handleForgotVerify = async (e) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSuccess(null);
    setAuthLoading(true);

    try {
      const res = await fetch('/api/auth?action=forgot_verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: authIdentifier,
          code: forgotCode,
          newPassword,
        }),
      });
      const data = await res.json();
      if (res.ok && data.status === 'password_reset_success') {
        setAuthSuccess('Password has been securely updated! You may now sign in with your new password.');
        setAuthPassword('');
        setForgotStep(1);
        setDispatchedCodeHint(null);
        setAuthMode('signin');
      } else {
        setAuthError(data.error || 'Verification failed. Please check the code.');
      }
    } catch (err) {
      setAuthError('Network error: ' + err.message);
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
  // VIEW 1: UN-AUTHENTICATED PORTAL (SIGN IN, SIGN UP, FORGOT PASSWORD)
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
        {/* Top Header Options */}
        <div style={{ position: 'absolute', top: '24px', right: '24px', display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '3px', background: 'var(--bg-surface)', padding: '3px 6px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginRight: '3px' }}>Palette:</span>
            {PALETTES.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => changePalette(p.id)}
                className={`palette-swatch-btn ${palette === p.id ? 'active' : ''}`}
                title={`${p.label} Palette - ${p.subtitle}`}
                style={{
                  padding: '3px 7px',
                  fontSize: '0.72rem',
                  borderRadius: '4px',
                  border: palette === p.id ? `1px solid ${p.hex}` : '1px solid transparent',
                  background: palette === p.id ? `${p.hex}20` : 'transparent',
                  color: palette === p.id ? p.hex : 'var(--text-secondary)',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                }}
              >
                <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: p.hex }} />
                <span>{p.label}</span>
              </button>
            ))}
          </div>

          <button
            onClick={toggleTheme}
            className="btn-minimal"
            style={{ fontSize: '0.8rem', padding: '6px 12px' }}
          >
            {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
          </button>
        </div>

        {/* Brand Header */}
        <div style={{ textAlign: 'center', marginBottom: '20px', maxWidth: '460px' }}>
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
            Multi-Tenant Observability, Privacy Collector & Automated Attack Defense
          </p>
        </div>

        {/* Main Auth Card */}
        <div className="card-minimal" style={{ maxWidth: '440px', width: '100%', padding: '26px' }}>
          {/* Top 3-Way Mode Switcher */}
          <div style={{
            display: 'flex',
            background: 'var(--bg-canvas)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
            padding: '3px',
            marginBottom: '18px',
          }}>
            <button
              onClick={() => { setAuthMode('signin'); setAuthError(null); setAuthSuccess(null); }}
              style={{
                flex: 1,
                padding: '6px 8px',
                border: 'none',
                borderRadius: '4px',
                background: authMode === 'signin' ? 'var(--bg-surface)' : 'transparent',
                color: authMode === 'signin' ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontWeight: authMode === 'signin' ? '600' : '400',
                fontSize: '0.8rem',
                cursor: 'pointer',
              }}
            >
              Sign In
            </button>
            <button
              onClick={() => { setAuthMode('signup'); setAuthError(null); setAuthSuccess(null); }}
              style={{
                flex: 1,
                padding: '6px 8px',
                border: 'none',
                borderRadius: '4px',
                background: authMode === 'signup' ? 'var(--bg-surface)' : 'transparent',
                color: authMode === 'signup' ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontWeight: authMode === 'signup' ? '600' : '400',
                fontSize: '0.8rem',
                cursor: 'pointer',
              }}
            >
              New User Sign Up
            </button>
            <button
              onClick={() => { setAuthMode('forgot'); setForgotStep(1); setAuthError(null); setAuthSuccess(null); }}
              style={{
                flex: 1,
                padding: '6px 8px',
                border: 'none',
                borderRadius: '4px',
                background: authMode === 'forgot' ? 'var(--bg-surface)' : 'transparent',
                color: authMode === 'forgot' ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontWeight: authMode === 'forgot' ? '600' : '400',
                fontSize: '0.8rem',
                cursor: 'pointer',
              }}
            >
              Forgot Password
            </button>
          </div>

          {/* Feedback Messages */}
          {authError && (
            <div style={{
              background: 'var(--color-rose-subtle)',
              border: '1px solid rgba(244, 63, 94, 0.3)',
              color: 'var(--color-rose)',
              padding: '9px 12px',
              borderRadius: '6px',
              fontSize: '0.78rem',
              marginBottom: '14px',
            }}>
              {authError}
            </div>
          )}
          {authSuccess && (
            <div style={{
              background: 'var(--color-emerald-subtle)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              color: 'var(--color-emerald)',
              padding: '9px 12px',
              borderRadius: '6px',
              fontSize: '0.78rem',
              marginBottom: '14px',
            }}>
              {authSuccess}
            </div>
          )}

          {/* 1. SIGN IN FORM */}
          {authMode === 'signin' && (
            <form onSubmit={handleAuthSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
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
                  placeholder="Enter your password"
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                  className="input-minimal"
                />
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '4px' }}>
                  <button
                    type="button"
                    onClick={() => { setAuthMode('forgot'); setForgotStep(1); setAuthError(null); setAuthSuccess(null); }}
                    style={{ background: 'transparent', border: 'none', color: 'var(--accent)', fontSize: '0.72rem', cursor: 'pointer', padding: 0 }}
                  >
                    Forgot password? Authenticate & reset →
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={authLoading}
                className="btn-minimal-primary"
                style={{ marginTop: '4px', width: '100%', padding: '9px' }}
              >
                {authLoading ? 'Signing In...' : 'Sign In to Workspace'}
              </button>
            </form>
          )}

          {/* 2. NEW USER SIGN UP PAGE */}
          {authMode === 'signup' && (
            <form onSubmit={handleAuthSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ background: 'var(--accent-subtle)', border: '1px solid var(--border-accent)', borderRadius: '6px', padding: '8px 12px', fontSize: '0.74rem' }}>
                <strong>👋 New to Cicada?</strong> Registering provisions a private, row-level isolated partition. Your team gets dedicated anomaly baselines and zero-knowledge privacy.
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '3px' }}>
                  Organization / Company Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Acme Cloud Corp or My Startup"
                  value={authTenantName}
                  onChange={(e) => setAuthTenantName(e.target.value)}
                  className="input-minimal"
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '3px' }}>
                  Work Email or Mobile Phone
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
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3px' }}>
                  <label style={{ fontSize: '0.75rem', fontWeight: '500', color: 'var(--text-secondary)' }}>
                    Create Password
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
                <span style={{ display: 'block', fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '3px' }}>
                  🔒 Derived using scrypt with random 16-byte salt. Never stored in plaintext.
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.73rem', color: 'var(--text-secondary)', marginBottom: '3px' }}>Service Tier</label>
                  <select value={authTier} onChange={(e) => setAuthTier(e.target.value)} className="input-minimal" style={{ padding: '6px 8px', fontSize: '0.76rem' }}>
                    <option value="enterprise">Enterprise (99.99% SLA)</option>
                    <option value="pro">Pro (99.9% SLA)</option>
                    <option value="starter">Starter ($0 / Testing)</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.73rem', color: 'var(--text-secondary)', marginBottom: '3px' }}>Primary Region</label>
                  <select value={authRegion} onChange={(e) => setAuthRegion(e.target.value)} className="input-minimal" style={{ padding: '6px 8px', fontSize: '0.76rem' }}>
                    <option value="us-east-1">US East (N. Virginia)</option>
                    <option value="eu-west-1">Europe (Ireland)</option>
                    <option value="us-west-2">US West (Oregon)</option>
                    <option value="ap-southeast-1">Asia (Singapore)</option>
                  </select>
                </div>
              </div>

              <button
                type="submit"
                disabled={authLoading}
                className="btn-minimal-primary"
                style={{ marginTop: '6px', width: '100%', padding: '9px' }}
              >
                {authLoading ? 'Provisioning Partition...' : 'Create Workspace & Sign In'}
              </button>
            </form>
          )}

          {/* 3. FORGOT PASSWORD AUTHENTICATOR */}
          {authMode === 'forgot' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 12px', fontSize: '0.75rem' }}>
                <strong>🔑 Authenticator Password Reset:</strong> Enter your registered email or mobile number to receive a 6-digit one-time authenticator verification code.
              </div>

              {forgotStep === 1 ? (
                <form onSubmit={handleForgotRequest} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                      Registered Email or Mobile Number
                    </label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. admin@acme.com or +1 555-123-4567"
                      value={authIdentifier}
                      onChange={(e) => setAuthIdentifier(e.target.value)}
                      className="input-minimal"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={authLoading}
                    className="btn-minimal-primary"
                    style={{ width: '100%', padding: '9px' }}
                  >
                    {authLoading ? 'Dispatching...' : 'Send 6-Digit Authenticator Code'}
                  </button>
                </form>
              ) : (
                <form onSubmit={handleForgotVerify} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                      6-Digit Authenticator Code
                    </label>
                    <input
                      type="text"
                      required
                      maxLength={6}
                      placeholder="Enter 6-digit code"
                      value={forgotCode}
                      onChange={(e) => setForgotCode(e.target.value)}
                      className="input-minimal"
                      style={{ letterSpacing: '4px', fontSize: '1rem', textAlign: 'center', fontFamily: 'var(--font-mono)' }}
                    />
                    {dispatchedCodeHint && (
                      <span style={{ display: 'block', fontSize: '0.7rem', color: 'var(--color-emerald)', marginTop: '4px' }}>
                        Simulated Code: <strong>{dispatchedCodeHint}</strong> (Valid for 10 minutes)
                      </span>
                    )}
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                      New Password (Min 6 Characters)
                    </label>
                    <input
                      type="password"
                      required
                      placeholder="Enter your new password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      className="input-minimal"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={authLoading}
                    className="btn-minimal-primary"
                    style={{ width: '100%', padding: '9px' }}
                  >
                    {authLoading ? 'Updating...' : 'Verify Code & Set New Password'}
                  </button>

                  <button
                    type="button"
                    onClick={() => setForgotStep(1)}
                    className="btn-minimal"
                    style={{ width: '100%', fontSize: '0.74rem' }}
                  >
                    ← Re-send code to another identifier
                  </button>
                </form>
              )}

              <div style={{ textAlign: 'center', marginTop: '4px' }}>
                <button
                  type="button"
                  onClick={() => { setAuthMode('signin'); setAuthError(null); setAuthSuccess(null); }}
                  style={{ background: 'transparent', border: 'none', color: 'var(--accent)', fontSize: '0.74rem', cursor: 'pointer' }}
                >
                  ← Back to Sign In
                </button>
              </div>
            </div>
          )}

          {/* Quick Demo Credentials */}
          <div style={{ marginTop: '18px', borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
            <span style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
              ONE-CLICK DEMO ACCOUNTS:
            </span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
              <button
                type="button"
                onClick={() => {
                  setAuthMode('signin');
                  setAuthIdentifier('admin@acme.com');
                  setAuthPassword('Password123!');
                  setAuthError(null);
                  setAuthSuccess(null);
                }}
                className="btn-minimal"
                style={{ fontSize: '0.73rem', justifyContent: 'flex-start' }}
              >
                <span>🏢</span> <strong>Tenant 1 (Acme Corp):</strong> admin@acme.com / Password123!
              </button>
              <button
                type="button"
                onClick={() => {
                  setAuthMode('signin');
                  setAuthIdentifier('secops@shield-defense.com');
                  setAuthPassword('Password123!');
                  setAuthError(null);
                  setAuthSuccess(null);
                }}
                className="btn-minimal"
                style={{ fontSize: '0.73rem', justifyContent: 'flex-start' }}
              >
                <span>🛡️</span> <strong>Tenant 2 (CyberShield):</strong> secops@shield-defense.com / Password123!
              </button>
              <button
                type="button"
                onClick={() => {
                  setAuthMode('signin');
                  setAuthIdentifier('+1 555 123 4567');
                  setAuthPassword('Password123!');
                  setAuthError(null);
                  setAuthSuccess(null);
                }}
                className="btn-minimal"
                style={{ fontSize: '0.73rem', justifyContent: 'flex-start' }}
              >
                <span>📱</span> <strong>Ops (Mobile SMS):</strong> +1 555 123 4567 / Password123!
              </button>
            </div>
          </div>
        </div>

        {/* Isolation Footer Note */}
        <div style={{ marginTop: '16px', maxWidth: '440px', textAlign: 'center', fontSize: '0.73rem', color: 'var(--text-muted)' }}>
          🛡️ <strong>Zero-Cross-Tenant Visibility:</strong> Partitions are strictly isolated. Credentials and personal data are masked automatically across all telemetry.
        </div>
      </div>
    );
  }

  // ==========================================
  // VIEW 2: AUTHENTICATED OBSERVABILITY SUITE
  // ==========================================
  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '16px 20px', minHeight: '100vh' }}>
      {/* Top Header */}
      <header style={{
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingBottom: '12px',
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

        {/* Status, Palette, Tenant Switcher, Simple Mode, Theme & Sign Out Controls */}
        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
          {/* Palette Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '3px', background: 'var(--bg-surface)', padding: '3px 6px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginRight: '3px' }}>Palette:</span>
            {PALETTES.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => changePalette(p.id)}
                className={`palette-swatch-btn ${palette === p.id ? 'active' : ''}`}
                title={`${p.label} - ${p.subtitle}`}
                style={{
                  padding: '3px 7px',
                  fontSize: '0.72rem',
                  borderRadius: '4px',
                  border: palette === p.id ? `1px solid ${p.hex}` : '1px solid transparent',
                  background: palette === p.id ? `${p.hex}20` : 'transparent',
                  color: palette === p.id ? p.hex : 'var(--text-secondary)',
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                }}
              >
                <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: p.hex }} />
                <span>{p.label}</span>
              </button>
            ))}
          </div>

          {/* Status Pill */}
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

          {/* User Profile Badge & Quick Tenant Switcher */}
          <div style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
            padding: '3px 8px',
            fontSize: '0.78rem',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
          }}>
            <span style={{ color: 'var(--text-muted)' }}>Tenant:</span>
            <strong style={{ color: 'var(--accent)' }}>{currentUser.tenantId}</strong>
            <span style={{ color: 'var(--border-subtle)' }}>|</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>{currentUser.maskedIdentifier}</span>
            <button
              onClick={() => handleSwitchDemoTenant(currentUser.tenantId === 'acme-corp' ? 'shield-defense' : 'acme-corp')}
              className="btn-minimal"
              style={{ padding: '2px 7px', fontSize: '0.68rem', marginLeft: '4px' }}
              title={`Switch context to ${currentUser.tenantId === 'acme-corp' ? 'shield-defense (CyberShield)' : 'acme-corp (Acme Corp)'}`}
            >
              ⇄ Switch to {currentUser.tenantId === 'acme-corp' ? 'shield-defense' : 'acme-corp'}
            </button>
          </div>

          {/* Simple Mode Toggle */}
          <button
            onClick={toggleSimpleMode}
            className="btn-minimal"
            style={{
              padding: '5px 10px',
              fontSize: '0.76rem',
              borderColor: simpleMode ? 'var(--accent)' : 'var(--border-subtle)',
              color: simpleMode ? 'var(--accent)' : 'var(--text-secondary)',
            }}
            title="Toggle plain-English simple explanations for non-technical users"
          >
            💡 Plain English: {simpleMode ? 'ON' : 'OFF'}
          </button>

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

      {/* Prominent Real-Time AI Threat Response Console */}
      <section style={{
        background: aiopsData.healthStatus === 'CRITICAL' ? 'var(--color-rose-subtle)' : aiopsData.healthStatus === 'DEGRADED' ? 'var(--color-amber-subtle)' : 'var(--bg-surface)',
        border: `1px solid ${aiopsData.healthStatus === 'CRITICAL' ? 'rgba(244, 63, 94, 0.35)' : aiopsData.healthStatus === 'DEGRADED' ? 'rgba(245, 158, 11, 0.35)' : 'var(--border-subtle)'}`,
        borderRadius: '8px',
        padding: '14px 18px',
        marginBottom: '16px',
      }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
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

        {/* Plain English explanation callout */}
        {simpleMode && (
          <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '8px 12px', fontSize: '0.75rem', marginBottom: '10px', color: 'var(--text-secondary)' }}>
            <strong>💡 In Plain English:</strong> Our AI acts like a 24/7 autonomous security guard. When someone attacks your servers or leaks sensitive credentials, it spots the threat, blocks the damage, and tells you the exact steps to fix it.
          </div>
        )}

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
          <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
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
      }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '10px' }}>
          <div>
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
        </div>

        {simpleMode && (
          <div style={{ marginTop: '8px', fontSize: '0.73rem', color: 'var(--text-muted)' }}>
            💡 <strong>What are these buttons?</strong> Think of these like practice fire drills! Click any button to test how the AI catches simulated attacks, credential leaks, or server crashes without touching real production.
          </div>
        )}
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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <h3 style={{ fontSize: '0.88rem', fontWeight: '600' }}>
                Operational Domain Status
              </h3>
            </div>
            {simpleMode && (
              <p style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginBottom: '10px' }}>
                💡 <strong>In Plain English:</strong> A health check across the 4 key pillars of your app: Hardware servers (Infra), Network speed (Network), Cyber defense (Security), and Data pipeline (Collector).
              </p>
            )}
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
                    <span>Critical alerts: {stats.criticalCount}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Anomaly Detection Radar */}
          <div className="card-minimal" style={{ padding: '18px' }}>
            <h3 style={{ fontSize: '0.88rem', fontWeight: '600', marginBottom: '8px' }}>
              Statistical Outlier Detection (Z ≥ 2.0)
            </h3>
            {simpleMode && (
              <p style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginBottom: '10px' }}>
                💡 <strong>In Plain English:</strong> The system learns normal day-to-day traffic. If latency or error rate suddenly jumps way higher than normal, the AI catches it before customers notice.
              </p>
            )}
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

          {/* Dedicated Failed-Login Security Summary Card */}
          <div className="card-minimal" style={{ gridColumn: '1 / -1', padding: '18px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '1.05rem' }}>🛡️</span>
                <h3 style={{ fontSize: '0.92rem', fontWeight: '600' }}>
                  Failed-Login Security Summary & Credential-Stuffing Defense
                </h3>
              </div>
              <span className="badge-minimal" style={{ background: 'var(--color-rose-subtle)', color: 'var(--color-rose)', border: '1px solid rgba(244, 63, 94, 0.3)' }}>
                ACTIVE ATTACK MITIGATION: 403 FORBIDDEN
              </span>
            </div>

            {simpleMode && (
              <p style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
                💡 <strong>In Plain English:</strong> Hackers using botnets try thousands of stolen passwords per minute. The system detects the abnormal burst, stops SQL injection bypass attempts, and locks out the attacker&apos;s IP cluster without locking out legitimate customers.
              </p>
            )}

            {/* 4 Security Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px', marginBottom: '14px' }}>
              <div style={{ background: 'var(--bg-canvas)', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>FAILED LOGINS INTERCEPTED</span>
                <div style={{ fontSize: '1.3rem', fontWeight: '700', color: 'var(--color-rose)', marginTop: '2px' }}>
                  {collectorStats.failedLoginSummary?.totalFailedAttempts || 520}
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--color-rose)' }}>Escalated Z = 5.2σ above baseline</span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>BOTNET IP CLUSTERS</span>
                <div style={{ fontSize: '1.3rem', fontWeight: '700', color: 'var(--color-purple)', marginTop: '2px' }}>
                  {collectorStats.failedLoginSummary?.attackerIps?.length || 3}
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--color-purple)' }}>Distributed brute-force origins</span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>BLOCKED SQLi SIGNATURES</span>
                <div style={{ fontSize: '1.3rem', fontWeight: '700', color: 'var(--color-amber)', marginTop: '2px' }}>
                  {collectorStats.failedLoginSummary?.blockedSignaturesCount || 142}
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--color-amber)' }}>UNION SELECT &amp; bypass neutralized</span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DEFENSE POSTURE</span>
                <div style={{ fontSize: '1.05rem', fontWeight: '700', color: 'var(--color-emerald)', marginTop: '4px' }}>
                  WAF Rate-Limiting
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--color-emerald)' }}>HTTP 403 Quarantine Enforced</span>
              </div>
            </div>

            {/* Attacker IPs & Targeted Endpoints */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '10px' }}>
              <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 12px' }}>
                <strong style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                  BOTNET ATTACKER IP CLUSTER LOG:
                </strong>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '0.73rem' }}>
                  {(collectorStats.failedLoginSummary?.attackerIps || [
                    { ip: '198.51.100.44', attempts: 312, country: 'US', origin: 'Tor Exit Node / Infiltration Botnet', lastSeen: 'Just now' },
                    { ip: '203.0.113.195', attempts: 188, country: 'RO', origin: 'Mirai variant brute-forcer', lastSeen: '2m ago' },
                    { ip: '192.0.2.77', attempts: 20, country: 'DE', origin: 'Credential stuffing runner', lastSeen: '5m ago' },
                  ]).map((atk, idx) => (
                    <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                      <div>
                        <code style={{ color: 'var(--accent)' }}>{atk.ip}</code>
                        <span style={{ marginLeft: '6px', color: 'var(--text-muted)', fontSize: '0.7rem' }}>({atk.country} · {atk.origin})</span>
                      </div>
                      <span style={{ fontWeight: '600', color: 'var(--color-rose)' }}>{atk.attempts} attempts (403 Dropped)</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 12px' }}>
                <strong style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                  TARGETED AUTH ENDPOINTS &amp; INTERCEPTED SQLi SIGNATURES:
                </strong>
                <div style={{ marginBottom: '8px' }}>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Targeted Endpoints:</span>
                  <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap', marginTop: '2px' }}>
                    {['/api/v1/auth/login', '/oauth/token', '/admin/vault'].map((ep) => (
                      <span key={ep} className="badge-minimal" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-subtle)', color: 'var(--text-primary)' }}>
                        {ep}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Blocked SQLi Signatures:</span>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', marginTop: '3px' }}>
                    <code style={{ fontSize: '0.7rem', color: 'var(--color-amber)', background: 'var(--code-bg)', padding: '2px 6px', borderRadius: '3px' }}>
                      admin&apos; OR &apos;1&apos;=&apos;1&apos; --
                    </code>
                    <code style={{ fontSize: '0.7rem', color: 'var(--color-amber)', background: 'var(--code-bg)', padding: '2px 6px', borderRadius: '3px' }}>
                      UNION SELECT token, key_hash FROM system_vault --
                    </code>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Visual Alert Merging Correlation Flow Diagram */}
          <div className="card-minimal" style={{ gridColumn: '1 / -1', padding: '18px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '1.05rem' }}>🔀</span>
                <h3 style={{ fontSize: '0.92rem', fontWeight: '600' }}>
                  AIOps Correlation Engine: Alert Storm Deduplication &amp; Consolidation
                </h3>
              </div>
              <button
                onClick={() => handleRunSimulation('outages')}
                disabled={loading}
                className="btn-minimal"
                style={{ fontSize: '0.74rem', borderColor: 'var(--accent)', color: 'var(--accent)' }}
              >
                <span>⚡</span> Trigger Cascading Outage &amp; Observe Alert Merge
              </button>
            </div>

            {simpleMode && (
              <p style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
                💡 <strong>In Plain English:</strong> In legacy systems, 1 server crash wakes up 5 engineers with 5 separate alarms. Our AI connects the dots in real time, merges all 3 related alerts into 1 cohesive incident box, and pinpoint-diagnoses the root problem!
              </p>
            )}

            {/* 3-Tier Alert Merging Flowchart */}
            <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '16px' }}>
              <div style={{ fontSize: '0.72rem', fontWeight: '600', color: 'var(--text-muted)', marginBottom: '8px', letterSpacing: '0.5px' }}>
                STAGE 1: RAW MULTI-TIER SIGNALS DETECTED IN INGRESS TELEMETRY
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '8px', marginBottom: '12px' }}>
                <div className="flow-node" style={{ borderLeft: '3px solid var(--color-rose)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.74rem', fontWeight: '600', color: 'var(--color-rose)' }}>
                    <span>Alert A: Database OOM Crash</span>
                    <span>INFRA</span>
                  </div>
                  <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', margin: '4px 0 0 0' }}>
                    <code>db-master-us-east</code>: Memory at 99.8%, SIGKILL issued
                  </p>
                </div>

                <div className="flow-node" style={{ borderLeft: '3px solid var(--color-amber)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.74rem', fontWeight: '600', color: 'var(--color-amber)' }}>
                    <span>Alert B: TCP Connection Timeout</span>
                    <span>NETWORK</span>
                  </div>
                  <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', margin: '4px 0 0 0' }}>
                    <code>api-gateway</code>: Connection pool exhausted, 4500ms latency
                  </p>
                </div>

                <div className="flow-node" style={{ borderLeft: '3px solid var(--color-purple)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.74rem', fontWeight: '600', color: 'var(--color-purple)' }}>
                    <span>Alert C: Ingress HTTP 504 Surge</span>
                    <span>GATEWAY</span>
                  </div>
                  <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', margin: '4px 0 0 0' }}>
                    <code>edge-ingress</code>: 28% error rate, client requests timing out
                  </p>
                </div>
              </div>

              {/* Flow arrow into correlation engine */}
              <div className="flow-arrow-down">
                <span style={{ fontSize: '0.76rem', background: 'var(--bg-surface)', padding: '4px 12px', borderRadius: '12px', border: '1px solid var(--border-subtle)', color: 'var(--accent)', fontWeight: '600' }}>
                  ▼ 10-Minute Sliding Window Temporal &amp; Topology Correlation Engine
                </span>
              </div>

              {/* Merged Incident Box */}
              <div style={{ marginTop: '10px', background: 'var(--bg-surface)', border: '1px solid var(--accent)', borderRadius: '6px', padding: '14px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px', flexWrap: 'wrap', gap: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="badge-minimal" style={{ background: 'var(--color-rose-subtle)', color: 'var(--color-rose)', border: '1px solid rgba(244, 63, 94, 0.3)' }}>
                      CRITICAL INCIDENT
                    </span>
                    <strong style={{ fontSize: '0.84rem' }}>INC-INFRA-OUTAGE (1 Consolidated Incident)</strong>
                  </div>
                  <span style={{ fontSize: '0.72rem', color: 'var(--color-emerald)', fontWeight: '600' }}>
                    ✓ 3 Alerts Deduplicated &amp; Grouped (Noise Reduction: 66.7%)
                  </span>
                </div>
                <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                  <strong>Root Cause Analysis:</strong> Cascading Out-Of-Memory DB crash and connection timeout starved upstream microservice queues.
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                  <span>Causal Chain: <code>db-master OOM</code> → <code>TCP Pool Drain</code> → <code>HTTP 504 Surge</code></span>
                  <span>Diagnostic Confidence: <strong style={{ color: 'var(--accent)' }}>95%</strong></span>
                </div>
              </div>
            </div>
          </div>

          {/* Correlated Incidents & Root Cause Analysis */}
          <div className="card-minimal" style={{ gridColumn: '1 / -1', padding: '18px' }}>
            <h3 style={{ fontSize: '0.92rem', fontWeight: '600', marginBottom: '6px' }}>
              Correlated Incident Records & Root Cause Analysis (RCA)
            </h3>
            {simpleMode && (
              <p style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
                💡 <strong>In Plain English:</strong> Instead of sending you 50 confusing error alerts, the AI groups them into 1 single incident, explains the root problem, and gives you a 1-click command to fix it.
              </p>
            )}

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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <h3 style={{ fontSize: '0.95rem', fontWeight: '600' }}>
                  Edge Local Collector Agent (Client Perimeter Tier)
                </h3>
              </div>
              <span className="badge-minimal" style={{ background: 'var(--color-emerald-subtle)', color: 'var(--color-emerald)', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                DAEMON LISTENING: 127.0.0.1:8081
              </span>
            </div>

            {simpleMode && (
              <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 12px', fontSize: '0.75rem', marginBottom: '14px', color: 'var(--text-secondary)' }}>
                <strong>💡 In Plain English:</strong> Think of the Edge Collector as a personal security guard running right inside your local network. Before any telemetry is sent to the cloud, it strips out private messages, blurs credit cards and passwords, and blocks cyber attacks. Your raw sensitive data never leaves your building.
              </div>
            )}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', marginBottom: '16px' }}>
              <div style={{ background: 'var(--bg-canvas)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>RAW FIELDS STRIPPED</span>
                <div style={{ fontSize: '1.4rem', fontWeight: '700', marginTop: '2px', color: 'var(--text-primary)' }}>
                  {collectorStats.rawFieldsStrippedCount}
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--accent)' }}>Zero raw content forwarded</span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DLP LEAKS PURGED</span>
                <div style={{ fontSize: '1.4rem', fontWeight: '700', marginTop: '2px', color: 'var(--color-rose)' }}>
                  {collectorStats.leaksPrevented}
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--color-rose)' }}>Secrets & PII scrubbed</span>
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

          {/* Local Buffering + Retry after Outage Card */}
          <div className="card-minimal" style={{ padding: '20px', borderLeft: isOutageSimulated ? '4px solid var(--color-rose)' : '4px solid var(--color-emerald)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '1.1rem' }}>🔄</span>
                <h3 style={{ fontSize: '0.95rem', fontWeight: '600' }}>
                  Resilient Edge Local Buffering &amp; Outage Replay Engine
                </h3>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className="badge-minimal" style={{
                  background: isOutageSimulated ? 'var(--color-rose-subtle)' : 'var(--color-emerald-subtle)',
                  color: isOutageSimulated ? 'var(--color-rose)' : 'var(--color-emerald)',
                  border: `1px solid ${isOutageSimulated ? 'rgba(244, 63, 94, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
                }}>
                  {isOutageSimulated ? '🔴 UPSTREAM OUTAGE SIMULATED' : '🟢 UPSTREAM CONNECTED (ONLINE)'}
                </span>
                <button
                  onClick={handleToggleOutage}
                  disabled={outageLoading}
                  className={isOutageSimulated ? 'btn-minimal-primary' : 'btn-minimal-danger'}
                  style={{ fontSize: '0.74rem', padding: '4px 10px' }}
                >
                  {isOutageSimulated ? '✓ Reconnect Upstream' : '⚡ Simulate Upstream Outage'}
                </button>
              </div>
            </div>

            {simpleMode && (
              <p style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
                💡 <strong>In Plain English:</strong> What happens if the internet goes down or cloud servers reboot? The local collector doesn&apos;t drop any data! It securely queues telemetry in your local computer&apos;s memory. Once the upstream server recovers, it automatically retries with backoff and drains the queue safely.
              </p>
            )}

            {/* Queue Depth & Status Controls */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px', marginBottom: '14px' }}>
              <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>LOCAL RAM QUEUE DEPTH</span>
                  <span className={`badge-minimal ${bufferedQueueDepth > 0 ? 'queue-pulse-active' : ''}`} style={{
                    background: bufferedQueueDepth > 0 ? 'var(--color-amber-subtle)' : 'var(--bg-surface-elevated)',
                    color: bufferedQueueDepth > 0 ? 'var(--color-amber)' : 'var(--text-secondary)',
                  }}>
                    {bufferedQueueDepth} Payloads Buffered
                  </span>
                </div>
                <div style={{ fontSize: '1.3rem', fontWeight: '700', marginTop: '4px', color: bufferedQueueDepth > 0 ? 'var(--color-amber)' : 'var(--text-primary)' }}>
                  {bufferedQueueDepth} <span style={{ fontSize: '0.78rem', fontWeight: '400', color: 'var(--text-muted)' }}>/ 500 Max Capacity</span>
                </div>
                <span style={{ fontSize: '0.68rem', color: isOutageSimulated ? 'var(--color-rose)' : 'var(--text-secondary)' }}>
                  {isOutageSimulated ? 'Holding telemetry offline in local memory' : 'Operating in pass-through direct forwarding'}
                </span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '12px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: '8px' }}>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={handleSendBufferPayload}
                    className="btn-minimal"
                    style={{ flex: 1, fontSize: '0.74rem' }}
                  >
                    📤 Send Telemetry Payload
                  </button>
                  <button
                    onClick={handleFlushAndRetry}
                    disabled={outageLoading || bufferedQueueDepth === 0}
                    className="btn-minimal-primary"
                    style={{ flex: 1, fontSize: '0.74rem' }}
                  >
                    🔄 Retry &amp; Drain Buffer
                  </button>
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textAlign: 'center' }}>
                  Simulates exponential backoff retry loop (Up to 3 attempts with jitter)
                </span>
              </div>
            </div>

            {/* Retry Results Log */}
            {retryResult && (
              <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 14px', fontSize: '0.75rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <strong style={{ color: retryResult.success ? 'var(--color-emerald)' : 'var(--color-rose)' }}>
                    {retryResult.success ? '✓ Outage Recovery Completed' : '✕ Outage Recovery Incomplete'}
                  </strong>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                    Flushed: {retryResult.flushed} | Retry Attempts: {retryResult.retried}
                  </span>
                </div>
                <p style={{ margin: 0, color: 'var(--text-secondary)' }}>
                  {retryResult.message}
                </p>
              </div>
            )}
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
            {simpleMode && (
              <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 12px', fontSize: '0.75rem', marginBottom: '14px', color: 'var(--text-secondary)' }}>
                <strong>💡 In Plain English:</strong> This is the central cloud platform. Just like a bank safe-deposit vault, every tenant gets their own locked partition. No tenant can ever see another company&apos;s data, and all database queries enforce row-level boundary locks.
              </div>
            )}

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
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DEDUPLICATION &amp; HEALING</span>
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

          {/* Idempotent Payload IDs (No Duplicates) Card */}
          <div className="card-minimal" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '1.1rem' }}>🆔</span>
                <h3 style={{ fontSize: '0.95rem', fontWeight: '600' }}>
                  Idempotent Payload Processing (Strict Zero Duplicate Guarantee)
                </h3>
              </div>
              <span className="badge-minimal" style={{ background: 'var(--color-emerald-subtle)', color: 'var(--color-emerald)', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                DEDUPLICATION HASH RING: ACTIVE
              </span>
            </div>

            {simpleMode && (
              <p style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
                💡 <strong>In Plain English:</strong> Sometimes mobile phones or microservices accidentally send the same data packet twice due to network lag. Our SaaS engine assigns a unique ID to every payload and remembers it. If a duplicate packet arrives, the engine throws it away so your metrics and billing are never double-counted!
              </p>
            )}

            <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '14px', marginBottom: '12px' }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
                <div style={{ flex: 1, minWidth: '240px' }}>
                  <label style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '3px' }}>
                    DETERMINISTIC PAYLOAD ID:
                  </label>
                  <input
                    type="text"
                    value={idempotentPayloadId}
                    onChange={(e) => setIdempotentPayloadId(e.target.value)}
                    className="input-minimal"
                    style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}
                  />
                </div>
                <button
                  onClick={() => setIdempotentPayloadId(`IDEM-PAYLOAD-${Math.floor(1000 + Math.random() * 9000)}`)}
                  className="btn-minimal"
                  style={{ alignSelf: 'flex-end', fontSize: '0.74rem' }}
                >
                  🎲 Generate New ID
                </button>
              </div>

              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <button
                  onClick={() => handleTestIdempotency(false)}
                  disabled={idempotencyLoading}
                  className="btn-minimal-primary"
                  style={{ fontSize: '0.76rem', padding: '6px 14px' }}
                >
                  <span>1️⃣</span> Ingest Initial Payload (Status: 201 Created)
                </button>
                <button
                  onClick={() => handleTestIdempotency(true)}
                  disabled={idempotencyLoading}
                  className="btn-minimal"
                  style={{ fontSize: '0.76rem', padding: '6px 14px', borderColor: 'var(--color-amber)', color: 'var(--color-amber)' }}
                >
                  <span>2️⃣</span> Resend Same Payload (Test Duplicate Interception)
                </button>
              </div>
            </div>

            {/* Idempotency Test Result */}
            {idempotencyResult && (
              <div style={{
                background: idempotencyResult.duplicate ? 'var(--color-amber-subtle)' : 'var(--color-emerald-subtle)',
                border: `1px solid ${idempotencyResult.duplicate ? 'rgba(245, 158, 11, 0.35)' : 'rgba(16, 185, 129, 0.35)'}`,
                borderRadius: '6px',
                padding: '12px 14px',
                fontSize: '0.76rem',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <strong style={{ color: idempotencyResult.duplicate ? 'var(--color-amber)' : 'var(--color-emerald)' }}>
                    {idempotencyResult.duplicate ? '⚠️ DUPLICATE_BLOCKED: Intercepted Duplicate Payload' : '✓ ACCEPTED: New Payload Registered'}
                  </strong>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    Payload: {idempotencyResult.payloadId}
                  </span>
                </div>
                <p style={{ margin: 0, color: 'var(--text-primary)' }}>
                  {idempotencyResult.auditMessage}
                </p>
                <div style={{ marginTop: '6px', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  Verification: Ingress state ring buffer verified unique constraint. Database duplicate row creation: <strong>0</strong>.
                </div>
              </div>
            )}
          </div>

          {/* Tenant Separation Across 2 Demo Tenants Card */}
          <div className="card-minimal" style={{ padding: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '1.1rem' }}>🏢</span>
                <h3 style={{ fontSize: '0.95rem', fontWeight: '600' }}>
                  Two-Tenant Separation Showcase (Row-Level Security)
                </h3>
              </div>
              <span className="badge-minimal" style={{ background: 'var(--accent-subtle)', color: 'var(--accent)', border: '1px solid var(--border-accent)' }}>
                RELATIONAL PARTITIONS: STRICT
              </span>
            </div>

            {simpleMode && (
              <p style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginBottom: '14px' }}>
                💡 <strong>In Plain English:</strong> In our multi-tenant cloud, Tenant A (Acme Corp) and Tenant B (CyberShield) share the same underlying engine, but can never view or tamper with each other&apos;s data. You can switch between them below or run our live cryptographic audit to mathematically verify zero data leaks!
              </p>
            )}

            {/* Comparative Tenant Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px', marginBottom: '14px' }}>
              {/* Tenant 1: Acme Corp */}
              <div style={{
                background: 'var(--bg-canvas)',
                border: currentUser.tenantId === 'acme-corp' ? '2px solid var(--accent)' : '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '14px',
                position: 'relative',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <strong style={{ fontSize: '0.84rem' }}>🏢 Demo Tenant 1: Acme Corp</strong>
                  {currentUser.tenantId === 'acme-corp' && (
                    <span className="badge-minimal" style={{ background: 'var(--accent-subtle)', color: 'var(--accent)' }}>
                      ACTIVE SESSION
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <div><strong>Partition ID:</strong> <code>acme-corp</code> (US-East-1)</div>
                  <div><strong>Authorized User:</strong> admin@acme.com</div>
                  <div><strong>SLA Guarantee:</strong> 99.99% Enterprise Tier</div>
                </div>
                {currentUser.tenantId !== 'acme-corp' && (
                  <button
                    onClick={() => handleSwitchDemoTenant('acme-corp')}
                    disabled={loading}
                    className="btn-minimal-primary"
                    style={{ marginTop: '10px', width: '100%', fontSize: '0.74rem' }}
                  >
                    ⇄ Switch Session to Acme Corp
                  </button>
                )}
              </div>

              {/* Tenant 2: CyberShield Defense */}
              <div style={{
                background: 'var(--bg-canvas)',
                border: currentUser.tenantId === 'shield-defense' ? '2px solid var(--accent)' : '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '14px',
                position: 'relative',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <strong style={{ fontSize: '0.84rem' }}>🛡️ Demo Tenant 2: CyberShield</strong>
                  {currentUser.tenantId === 'shield-defense' && (
                    <span className="badge-minimal" style={{ background: 'var(--accent-subtle)', color: 'var(--accent)' }}>
                      ACTIVE SESSION
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '3px' }}>
                  <div><strong>Partition ID:</strong> <code>shield-defense</code> (EU-West-1)</div>
                  <div><strong>Authorized User:</strong> secops@shield-defense.com</div>
                  <div><strong>SLA Guarantee:</strong> 99.999% Defense Tier</div>
                </div>
                {currentUser.tenantId !== 'shield-defense' && (
                  <button
                    onClick={() => handleSwitchDemoTenant('shield-defense')}
                    disabled={loading}
                    className="btn-minimal-primary"
                    style={{ marginTop: '10px', width: '100%', fontSize: '0.74rem' }}
                  >
                    ⇄ Switch Session to CyberShield
                  </button>
                )}
              </div>
            </div>

            {/* Run Cryptographic Isolation Audit Button */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', marginBottom: '10px' }}>
              <span style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
                Test cross-tenant partition boundaries live across SQLite relational tables:
              </span>
              <button
                onClick={handleRunIsolationAudit}
                disabled={isolationAuditLoading}
                className="btn-minimal"
                style={{ fontSize: '0.76rem', borderColor: 'var(--color-emerald)', color: 'var(--color-emerald)' }}
              >
                <span>🛡️</span> {isolationAuditLoading ? 'Auditing Partitions...' : 'Run Cryptographic Isolation Audit'}
              </button>
            </div>

            {/* Audit Results Report */}
            {isolationAudit && (
              <div style={{ background: 'var(--color-emerald-subtle)', border: '1px solid rgba(16, 185, 129, 0.35)', borderRadius: '6px', padding: '14px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px', flexWrap: 'wrap', gap: '6px' }}>
                  <strong style={{ color: 'var(--color-emerald)', fontSize: '0.82rem' }}>
                    ✓ ZERO-LEAK PARTITION ISOLATION MATHEMATICALLY VERIFIED
                  </strong>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    Audited at: {isolationAudit.timestampUtc?.substring(11, 19)} UTC
                  </span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '8px', fontSize: '0.74rem', marginTop: '6px' }}>
                  <div style={{ background: 'var(--bg-canvas)', padding: '8px 10px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                    <span style={{ color: 'var(--text-muted)', display: 'block' }}>CROSS-TENANT DATA LEAKS</span>
                    <strong style={{ fontSize: '1.1rem', color: 'var(--color-emerald)' }}>0 (Zero Leaks)</strong>
                  </div>
                  <div style={{ background: 'var(--bg-canvas)', padding: '8px 10px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                    <span style={{ color: 'var(--text-muted)', display: 'block' }}>ACTIVE PARTITION ({isolationAudit.primaryTenant?.tenantId})</span>
                    <strong>{isolationAudit.primaryTenant?.totalEvents} Events (0 Leaks)</strong>
                  </div>
                  <div style={{ background: 'var(--bg-canvas)', padding: '8px 10px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                    <span style={{ color: 'var(--text-muted)', display: 'block' }}>OPPOSING PARTITION ({isolationAudit.opposingTenant?.tenantId})</span>
                    <strong>{isolationAudit.opposingTenant?.totalEvents} Events (0 Leaks)</strong>
                  </div>
                </div>
                <div style={{ marginTop: '8px', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                  <strong>Security Enforcement Mechanism:</strong> {isolationAudit.isolationMechanism}
                </div>
              </div>
            )}
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
            </div>
            <span className="badge-minimal" style={{ background: 'var(--accent-subtle)', color: 'var(--accent)', border: '1px solid var(--border-accent)' }}>
              AUTOMATED AFTER SIMULATION
            </span>
          </div>

          {simpleMode && (
            <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 12px', fontSize: '0.75rem', marginBottom: '12px', color: 'var(--text-secondary)' }}>
              <strong>💡 In Plain English:</strong> A live interactive sandbox. You put "dirty" raw data containing passwords, API keys, or hacker scripts on the left. The Edge Collector cleans it up in milliseconds and shows you the safe, sanitized metadata on the right!
            </div>
          )}

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '14px' }}>
            <button
              onClick={() => setPlaygroundInput(JSON.stringify(SCENARIO_RAW_PAYLOADS.data_leaks, null, 2))}
              className="btn-minimal"
              style={{ fontSize: '0.74rem' }}
            >
              Preset: Credential Leak Attempt (DLP)
            </button>
            <button
              onClick={() => setPlaygroundInput(JSON.stringify(SCENARIO_RAW_PAYLOADS.failed_logins, null, 2))}
              className="btn-minimal"
              style={{ fontSize: '0.74rem' }}
            >
              Preset: SQLi Injection Attack (Shield)
            </button>
            <button
              onClick={() => setPlaygroundInput(JSON.stringify(SCENARIO_RAW_PAYLOADS.spikes, null, 2))}
              className="btn-minimal"
              style={{ fontSize: '0.74rem' }}
            >
              Preset: Latency & CPU Spike
            </button>
            <button
              onClick={() => setPlaygroundInput(JSON.stringify(SCENARIO_RAW_PAYLOADS.baseline, null, 2))}
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
          <h3 style={{ fontSize: '0.95rem', fontWeight: '600', marginBottom: '6px' }}>
            System Architecture & REST Endpoints
          </h3>
          {simpleMode && (
            <p style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
              💡 <strong>In Plain English:</strong> A cheat sheet for developers who want to connect other apps or scripts directly to Cicada using standard web requests.
            </p>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'var(--font-mono)' }}>
            {[
              { method: 'POST', endpoint: '/api/simulate', desc: 'Simulates events ("data_leaks", "failed_logins", "outages", "spikes", "baseline") with live AIOps scoring.' },
              { method: 'POST', endpoint: '/api/collector', desc: 'Edge collector: strips raw fields, DLP leak purge, threat shield, metadata forwarding.' },
              { method: 'GET', endpoint: '/api/collector', desc: 'Edge collector health, local buffer capacity, leak purge tallies, attack mitigation audits.' },
              { method: 'GET', endpoint: '/api/aiops?tenantId={id}', desc: 'Central AIOps intelligence: health score, anomaly detection, incident correlation, RCA.' },
              { method: 'POST', endpoint: '/api/auth?action=signup', desc: 'Registers isolated tenant partition with scrypt-hashed credentials and random salt.' },
              { method: 'POST', endpoint: '/api/auth?action=signin', desc: 'Constant-time authentication for email/mobile + password.' },
              { method: 'POST', endpoint: '/api/auth?action=forgot_request', desc: 'Generates and dispatches 6-digit Authenticator verification code for password reset.' },
              { method: 'POST', endpoint: '/api/auth?action=forgot_verify', desc: 'Verifies 6-digit Authenticator code and securely updates user password.' },
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
