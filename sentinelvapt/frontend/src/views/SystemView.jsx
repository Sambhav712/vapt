import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  Database, 
  Shield, 
  Server, 
  RefreshCw, 
  Lock, 
  Unlock, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Key, 
  Zap, 
  Globe, 
  Activity,
  Layers
} from 'lucide-react';

export default function SystemView() {
  const [health, setHealth] = useState(null);
  const [config, setConfig] = useState(null);
  const [privileges, setPrivileges] = useState(null);
  const [apis, setApis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [checkingApis, setCheckingApis] = useState(false);

  const fetchSystemInfo = async () => {
    setLoading(true);
    try {
      const [hResp, cResp, pResp, aResp] = await Promise.all([
        fetch('/api/system/health'),
        fetch('/api/system/config'),
        fetch('/api/system/privileges'),
        fetch('/api/system/apis'),
      ]);
      if (hResp.ok) setHealth(await hResp.json());
      if (cResp.ok) setConfig(await cResp.json());
      if (pResp.ok) setPrivileges(await pResp.json());
      if (aResp.ok) setApis(await aResp.json());
    } catch (err) {
      console.error('Failed to load system diagnostics:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRunApiHealthChecks = async () => {
    setCheckingApis(true);
    try {
      const resp = await fetch('/api/system/apis/health-check', { method: 'POST' });
      if (resp.ok) {
        // Re-fetch APIs after check
        const aResp = await fetch('/api/system/apis');
        if (aResp.ok) setApis(await aResp.json());
      }
    } catch (err) {
      console.error('Failed to run API health checks:', err);
    } finally {
      setCheckingApis(false);
    }
  };

  useEffect(() => {
    fetchSystemInfo();
  }, []);

  const isRootOrAdmin = privileges?.level === 'root' || privileges?.is_admin;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner Card */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--cyber-cyan)', fontWeight: '700', fontSize: '0.85rem' }}>
              <Cpu size={18} />
              <span>CORE ARCHITECTURE, PRIVILEGES &amp; API ECOSYSTEM</span>
            </div>
            <h2 style={{ fontSize: '1.5rem', marginTop: '4px', fontWeight: '800' }}>System Diagnostics &amp; Capabilities</h2>
          </div>

          <div style={{ display: 'flex', gap: '12px' }}>
            <button 
              className="btn btn-secondary" 
              onClick={handleRunApiHealthChecks}
              disabled={checkingApis}
              title="Ping external APIs to verify credentials and connectivity"
            >
              <Activity size={15} className={checkingApis ? 'spin' : ''} />
              <span>{checkingApis ? 'Checking APIs...' : 'Check API Status'}</span>
            </button>
            <button className="btn btn-secondary" onClick={fetchSystemInfo} disabled={loading}>
              <RefreshCw size={15} className={loading ? 'spin' : ''} />
              <span>Refresh</span>
            </button>
          </div>
        </div>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
          Probing system state, root privileges, and API tiers...
        </div>
      ) : (
        <>
          {/* Privilege & Elevation Status (Top Alert / Highlight Card) */}
          <div className="card" style={{
            borderLeft: `4px solid ${isRootOrAdmin ? 'var(--cyber-emerald)' : 'var(--sev-high)'}`,
            background: isRootOrAdmin ? 'rgba(16, 185, 129, 0.05)' : 'rgba(245, 158, 11, 0.05)',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {isRootOrAdmin ? (
                    <Unlock size={22} color="var(--cyber-emerald)" />
                  ) : (
                    <Lock size={22} color="var(--sev-high)" />
                  )}
                  <h3 style={{ fontSize: '1.2rem', fontWeight: '700', margin: 0 }}>
                    Privilege Execution Mode: {' '}
                    <span style={{ 
                      color: isRootOrAdmin ? 'var(--cyber-emerald)' : 'var(--sev-high)',
                      textTransform: 'uppercase'
                    }}>
                      {privileges?.level || 'UNKNOWN'} {isRootOrAdmin ? '(FULL ACCESS)' : '(STANDARD USER)'}
                    </span>
                  </h3>
                </div>
                <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginTop: '8px', maxWidth: '850px' }}>
                  {isRootOrAdmin 
                    ? 'SentinelVAPT is running with elevated privileges (Root/Admin). All raw packet socket operations (Nmap SYN scan -sS, OS fingerprinting -O, Masscan, raw packet crafting) are 100% operational.'
                    : 'Running as a standard non-root user. SentinelVAPT will automatically auto-elevate commands with sudo where permitted or gracefully fall back to TCP connect scans (-sT) so scans never fail.'}
                </p>
                {privileges?.warnings && privileges.warnings.length > 0 && (
                  <div style={{ marginTop: '10px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {privileges.warnings.map((w, idx) => (
                      <div key={idx} style={{ fontSize: '0.82rem', color: 'var(--sev-high)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <AlertTriangle size={14} />
                        <span>{w}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Quick status pill box */}
              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                <div style={{
                  padding: '8px 14px',
                  borderRadius: '6px',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '0.8rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '2px'
                }}>
                  <span style={{ color: 'var(--text-muted)' }}>User / UID</span>
                  <b>{privileges?.username} (UID: {privileges?.uid ?? 'Windows'})</b>
                </div>
                <div style={{
                  padding: '8px 14px',
                  borderRadius: '6px',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '0.8rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '2px'
                }}>
                  <span style={{ color: 'var(--text-muted)' }}>Sudo Access</span>
                  <b style={{ color: privileges?.has_sudo ? 'var(--cyber-emerald)' : 'var(--text-muted)' }}>
                    {privileges?.has_sudo ? (privileges.sudo_passwordless ? 'Passwordless (NOPASSWD)' : 'Password-Required') : 'No Sudo'}
                  </b>
                </div>
                <div style={{
                  padding: '8px 14px',
                  borderRadius: '6px',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '0.8rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '2px'
                }}>
                  <span style={{ color: 'var(--text-muted)' }}>Raw Sockets</span>
                  <b style={{ color: privileges?.can_raw_socket ? 'var(--cyber-emerald)' : 'var(--sev-high)' }}>
                    {privileges?.can_raw_socket ? 'Permitted' : 'Restricted'}
                  </b>
                </div>
              </div>
            </div>

            {/* Tool Root Dependency Table */}
            {privileges?.tool_privileges && (
              <div style={{ marginTop: '20px' }}>
                <div style={{ fontSize: '0.82rem', fontWeight: '700', color: 'var(--text-secondary)', marginBottom: '8px', textTransform: 'uppercase' }}>
                  Root-Requiring Tool Matrix &amp; Elevation Capability:
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '8px' }}>
                  {Object.entries(privileges.tool_privileges).map(([tName, tInfo]) => (
                    <div key={tName} style={{
                      padding: '8px 12px',
                      borderRadius: '6px',
                      background: 'rgba(0, 0, 0, 0.3)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      fontSize: '0.82rem',
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <code style={{ color: 'var(--cyber-cyan)', fontWeight: 'bold' }}>{tName}</code>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          {tInfo.installed ? 'Installed' : 'Missing'}
                        </span>
                      </div>
                      <span style={{
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontSize: '0.72rem',
                        fontWeight: '700',
                        background: tInfo.can_run_elevated ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                        color: tInfo.can_run_elevated ? 'var(--cyber-emerald)' : 'var(--sev-critical)',
                      }}>
                        {tInfo.can_run_elevated ? 'ELEVATION OK' : 'NEEDS ROOT'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* External API Management & Free Tier Quotas */}
          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <div className="card-title" style={{ marginBottom: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Globe size={18} color="var(--cyber-cyan)" />
                    <span>External Security APIs &amp; Free Tier Management</span>
                  </div>
                </div>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0 }}>
                  All APIs used by SentinelVAPT are completely free or have generous free community tiers. Zero cost, no credit card required.
                </p>
              </div>

              <div style={{
                background: 'rgba(56, 189, 248, 0.1)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                padding: '6px 12px',
                borderRadius: '6px',
                color: 'var(--cyber-cyan)',
                fontSize: '0.8rem',
                fontWeight: '600'
              }}>
                100% Free / Community Friendly
              </div>
            </div>

            {/* APIs Table */}
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.88rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '10px' }}>Service Name</th>
                    <th style={{ padding: '10px' }}>Tier / Cost</th>
                    <th style={{ padding: '10px' }}>Health Status</th>
                    <th style={{ padding: '10px' }}>Free Tier Quotas &amp; Limits</th>
                    <th style={{ padding: '10px' }}>Auth / Key Requirement</th>
                  </tr>
                </thead>
                <tbody>
                  {apis?.apis && Object.entries(apis.apis).map(([key, api]) => {
                    const isHealthy = api.health === 'healthy';
                    const isNoKey = api.health === 'no_key';
                    const isDegraded = api.health === 'degraded';

                    return (
                      <tr key={key} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                        <td style={{ padding: '12px 10px' }}>
                          <b style={{ color: 'var(--text-primary)' }}>{api.name}</b>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{key}</div>
                        </td>
                        <td style={{ padding: '12px 10px' }}>
                          <span style={{
                            padding: '3px 8px',
                            borderRadius: '4px',
                            fontSize: '0.75rem',
                            fontWeight: '600',
                            background: api.tier === 'free' ? 'rgba(16, 185, 129, 0.15)' : 
                                        api.tier === 'local' ? 'rgba(168, 85, 247, 0.15)' : 
                                        'rgba(56, 189, 248, 0.15)',
                            color: api.tier === 'free' ? 'var(--cyber-emerald)' : 
                                   api.tier === 'local' ? 'var(--cyber-purple)' : 
                                   'var(--cyber-cyan)',
                            textTransform: 'uppercase',
                          }}>
                            {api.tier.replace('_', ' ')}
                          </span>
                        </td>
                        <td style={{ padding: '12px 10px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            {isHealthy && <CheckCircle2 size={16} color="var(--cyber-emerald)" />}
                            {isNoKey && <Key size={16} color="var(--text-muted)" />}
                            {isDegraded && <AlertTriangle size={16} color="var(--sev-high)" />}
                            {!isHealthy && !isNoKey && !isDegraded && <XCircle size={16} color="var(--sev-critical)" />}
                            <span style={{
                              color: isHealthy ? 'var(--cyber-emerald)' : 
                                     isNoKey ? 'var(--text-muted)' : 
                                     isDegraded ? 'var(--sev-high)' : 'var(--sev-critical)',
                              fontWeight: '600',
                              fontSize: '0.82rem',
                              textTransform: 'uppercase',
                            }}>
                              {api.health.replace('_', ' ')}
                            </span>
                          </div>
                        </td>
                        <td style={{ padding: '12px 10px', color: 'var(--text-secondary)', fontSize: '0.82rem' }}>
                          {api.free_tier_limits || 'No strict limit / local daemon'}
                        </td>
                        <td style={{ padding: '12px 10px' }}>
                          <span style={{
                            fontSize: '0.8rem',
                            color: api.is_configured ? 'var(--cyber-emerald)' : 'var(--text-muted)',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '4px'
                          }}>
                            {api.requires_key ? (
                              api.is_configured ? '✓ Configured' : 'Optional (Free Key)'
                            ) : (
                              '✓ No Key Needed'
                            )}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Platform Information & Core Diagnostics Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '16px' }}>
            {/* Host Platform */}
            <div className="card">
              <div className="card-title">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Server size={18} color="var(--cyber-cyan)" />
                  <span>Host Platform</span>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.88rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Operating System:</span>
                  <b>{health?.platform?.system} ({health?.platform?.release})</b>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Architecture:</span>
                  <code>{health?.platform?.machine}</code>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Python Runtime:</span>
                  <code>{health?.platform?.python}</code>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Database Status:</span>
                  <span style={{ color: health?.database_connected ? 'var(--cyber-emerald)' : 'var(--sev-critical)', fontWeight: '600' }}>
                    {health?.database_connected ? 'Connected' : 'Degraded'}
                  </span>
                </div>
              </div>
            </div>

            {/* AI LLM Settings */}
            <div className="card">
              <div className="card-title">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Zap size={18} color="var(--cyber-purple)" />
                  <span>AI Reasoning Core</span>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.88rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Active Provider:</span>
                  <b style={{ color: 'var(--cyber-purple)', textTransform: 'uppercase' }}>{config?.llm_provider}</b>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Groq Primary Model (Free):</span>
                  <code>{config?.groq_model}</code>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Ollama Fallback Base (Local):</span>
                  <code>{config?.ollama_base_url}</code>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Ollama Fallback Model:</span>
                  <code>{config?.ollama_model}</code>
                </div>
              </div>
            </div>

            {/* Safety & Lab Boundaries */}
            <div className="card" style={{ gridColumn: '1 / -1' }}>
              <div className="card-title">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Shield size={18} color="var(--cyber-emerald)" />
                  <span>Safety Boundaries &amp; Lab Allowlist</span>
                </div>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '12px' }}>
                Active exploitation verification is strictly governed by the configured CIDR allowlist.
                Attempts to target external production networks will be blocked by the server kernel.
              </p>
              <div style={{
                background: '#040711',
                padding: '12px 16px',
                borderRadius: '8px',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.82rem',
                color: 'var(--cyber-cyan)',
                border: '1px solid var(--border-subtle)',
              }}>
                EXPLOIT_ALLOWLIST = {config?.exploit_allowlist}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
