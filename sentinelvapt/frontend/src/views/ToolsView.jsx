import React, { useState, useEffect } from 'react';
import { 
  Wrench, 
  CheckCircle2, 
  XCircle, 
  Download, 
  RefreshCw, 
  Terminal, 
  Layers, 
  ShieldAlert, 
  Shield, 
  Copy, 
  Check, 
  Filter 
} from 'lucide-react';

export default function ToolsView({ tools, onRefreshTools }) {
  const [catalog, setCatalog] = useState([]);
  const [viewMode, setViewMode] = useState('detected'); // 'detected' | 'catalog'
  const [filterTier, setFilterTier] = useState('all');
  const [filterCat, setFilterCat] = useState('all');
  const [installingTool, setInstallingTool] = useState(null);
  const [installMsg, setInstallMsg] = useState(null);
  const [missingPackages, setMissingPackages] = useState(null);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const fetchCatalogData = async () => {
    try {
      const [catResp, pkgResp] = await Promise.all([
        fetch('/api/tools/catalog'),
        fetch('/api/tools/missing-packages'),
      ]);
      if (catResp.ok) setCatalog(await catResp.json());
      if (pkgResp.ok) setMissingPackages(await pkgResp.json());
    } catch (err) {
      console.error('Failed to load tool catalog:', err);
    }
  };

  useEffect(() => {
    fetchCatalogData();
  }, [tools]);

  const handleToggleTool = async (toolName, currentEnabled) => {
    try {
      const resp = await fetch(`/api/tools/toggle/${toolName}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !currentEnabled }),
      });
      if (resp.ok) {
        setCatalog((prev) =>
          prev.map((t) =>
            t.name === toolName ? { ...t, enabled: !currentEnabled } : t
          )
        );
      }
    } catch (err) {
      alert('Failed to toggle tool: ' + err.message);
    }
  };

  const handleInstallSingle = async (toolName) => {
    setInstallingTool(toolName);
    setInstallMsg(null);
    try {
      const resp = await fetch(`/api/tools/install/${toolName}`, { method: 'POST' });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.detail || 'Install failed');
      }
      setInstallMsg(`Installation initiated for ${toolName}`);
      onRefreshTools();
      fetchCatalogData();
    } catch (err) {
      setInstallMsg(`Error: ${err.message}`);
    } finally {
      setInstallingTool(null);
    }
  };

  const handleInstallAll = async () => {
    setInstallingTool('all');
    setInstallMsg(null);
    try {
      const resp = await fetch('/api/tools/install-all', { method: 'POST' });
      const data = await resp.json();
      setInstallMsg(data.message);
      setTimeout(() => {
        onRefreshTools();
        fetchCatalogData();
      }, 5000);
    } catch (err) {
      setInstallMsg(`Error: ${err.message}`);
    } finally {
      setInstallingTool(null);
    }
  };

  const copyAptCmd = () => {
    if (missingPackages?.apt_command) {
      navigator.clipboard.writeText(missingPackages.apt_command);
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 2000);
    }
  };

  const displayedTools = catalog.filter((t) => {
    if (viewMode === 'detected' && !t.installed) return false;
    if (filterTier !== 'all' && String(t.tier) !== filterTier) return false;
    if (filterCat !== 'all' && t.category !== filterCat) return false;
    return true;
  });

  const categories = Array.from(new Set(catalog.map((t) => t.category)));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* ── Header ────────────────────────────────────────────── */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--cyber-cyan)', fontWeight: '700', fontSize: '0.85rem' }}>
              <Wrench size={18} />
              <span>EXTENSIBLE KALI & LINUX TOOL REGISTRY</span>
            </div>
            <h2 style={{ fontSize: '1.45rem', marginTop: '4px' }}>Plugin-Based Tool Detection Engine</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginTop: '4px' }}>
              Automatically detects installed security tools, categorizes by risk tier, and dynamically queues assessments based on recon.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '10px' }}>
            <button className="btn btn-secondary" onClick={() => { onRefreshTools(); fetchCatalogData(); }}>
              <RefreshCw size={15} />
              <span>Rescan System</span>
            </button>
            <button className="btn btn-primary" onClick={handleInstallAll} disabled={installingTool !== null}>
              <Download size={15} />
              <span>{installingTool === 'all' ? 'Installing...' : 'Install Missing Tools'}</span>
            </button>
          </div>
        </div>

        {installMsg && (
          <div style={{
            marginTop: '14px',
            padding: '10px 14px',
            borderRadius: '8px',
            background: 'rgba(0, 242, 254, 0.08)',
            border: '1px solid rgba(0, 242, 254, 0.25)',
            fontSize: '0.82rem',
            color: 'var(--cyber-cyan)'
          }}>
            {installMsg}
          </div>
        )}
      </div>

      {/* ── Kali Batch Install Banner ──────────────────────────── */}
      {missingPackages?.packages?.length > 0 && (
        <div style={{
          background: 'rgba(15, 23, 42, 0.85)',
          border: '1px solid rgba(0, 242, 254, 0.2)',
          borderRadius: '12px',
          padding: '16px 20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '16px',
        }}>
          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: '700', color: '#fff' }}>
              📦 Kali/Debian Batch Tool Installation Available ({missingPackages.missing_count} missing catalog tools)
            </div>
            <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
              {missingPackages.apt_command}
            </div>
          </div>

          <button className="btn btn-secondary" onClick={copyAptCmd} style={{ fontSize: '0.8rem', padding: '6px 14px' }}>
            {copiedCmd ? <Check size={14} color="var(--cyber-emerald)" /> : <Copy size={14} />}
            <span>{copiedCmd ? 'Command Copied' : 'Copy Apt Command'}</span>
          </button>
        </div>
      )}

      {/* ── View Controls & Filter Bar ─────────────────────────── */}
      <div className="card" style={{ padding: '14px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
          {/* View mode toggle */}
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className={`btn btn-secondary ${viewMode === 'detected' ? 'btn-primary' : ''}`}
              style={{ fontSize: '0.8rem', padding: '6px 14px' }}
              onClick={() => setViewMode('detected')}
            >
              <CheckCircle2 size={15} />
              <span>Detected On Host ({catalog.filter((t) => t.installed).length})</span>
            </button>

            <button
              className={`btn btn-secondary ${viewMode === 'catalog' ? 'btn-primary' : ''}`}
              style={{ fontSize: '0.8rem', padding: '6px 14px' }}
              onClick={() => setViewMode('catalog')}
            >
              <Layers size={15} />
              <span>Full Tool Catalog ({catalog.length})</span>
            </button>
          </div>

          {/* Tier & Category Filters */}
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
            <select
              className="form-select"
              style={{ padding: '6px 10px', fontSize: '0.8rem', width: 'auto' }}
              value={filterTier}
              onChange={(e) => setFilterTier(e.target.value)}
            >
              <option value="all">All Risk Tiers</option>
              <option value="1">Tier 1: Non-intrusive / Passive</option>
              <option value="2">Tier 2: Active Scanning</option>
              <option value="3">Tier 3: Exploitation / Gated</option>
            </select>

            <select
              className="form-select"
              style={{ padding: '6px 10px', fontSize: '0.8rem', width: 'auto' }}
              value={filterCat}
              onChange={(e) => setFilterCat(e.target.value)}
            >
              <option value="all">All Categories</option>
              {categories.map((c) => (
                <option key={c} value={c}>{c.toUpperCase()}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* ── Tools Grid ─────────────────────────────────────────── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
        gap: '16px',
      }}>
        {displayedTools.map((t) => {
          const isInstalled = t.installed;
          const isEnabled = t.enabled !== false;
          const isBusy = installingTool === t.name;

          const tierColor = t.tier === 1 ? 'var(--cyber-emerald)' : t.tier === 2 ? 'var(--sev-medium)' : 'var(--sev-critical)';
          const tierLabel = t.tier === 1 ? 'TIER 1 (SAFE)' : t.tier === 2 ? 'TIER 2 (ACTIVE)' : 'TIER 3 (GATED)';

          return (
            <div key={t.name} className="card" style={{
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: '14px',
              borderLeft: `4px solid ${tierColor}`,
            }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <h3 style={{ fontSize: '1.05rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                        {t.name}
                      </h3>
                      <span className="badge badge-info" style={{ fontSize: '0.65rem' }}>
                        {t.category}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                      {t.description}
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '6px' }}>
                    <span className="badge" style={{
                      color: tierColor,
                      background: 'rgba(255, 255, 255, 0.05)',
                      fontSize: '0.68rem',
                      border: `1px solid ${tierColor}`
                    }}>
                      {tierLabel}
                    </span>

                    <span style={{
                      fontSize: '0.72rem',
                      fontWeight: '700',
                      color: isInstalled ? 'var(--cyber-emerald)' : 'var(--sev-critical)'
                    }}>
                      {isInstalled ? '● INSTALLED' : '○ MISSING'}
                    </span>
                  </div>
                </div>

                <div style={{ marginTop: '14px', fontSize: '0.78rem', display: 'flex', flexDirection: 'column', gap: '5px' }}>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Binary: </span>
                    <code>{t.binary}</code>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Path: </span>
                    <code style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                      {t.path || 'Not located'}
                    </code>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Output Format: </span>
                    <span style={{ color: 'var(--cyber-cyan)' }}>{t.output_format?.toUpperCase()} ({t.parser_type})</span>
                  </div>
                </div>
              </div>

              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                paddingTop: '10px',
                borderTop: '1px solid var(--border-subtle)',
              }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '0.78rem' }}>
                  <input
                    type="checkbox"
                    checked={isEnabled}
                    onChange={() => handleToggleTool(t.name, isEnabled)}
                    style={{ accentColor: 'var(--cyber-cyan)', cursor: 'pointer' }}
                  />
                  <span>Auto-Selection Enabled</span>
                </label>

                {!isInstalled && (
                  <button
                    className="btn btn-secondary"
                    style={{ fontSize: '0.74rem', padding: '5px 10px' }}
                    onClick={() => handleInstallSingle(t.name)}
                    disabled={isBusy}
                  >
                    <Download size={13} />
                    <span>{isBusy ? 'Installing...' : 'Install'}</span>
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
