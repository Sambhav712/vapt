import React, { useState, useEffect } from 'react';
import { X, Play, ShieldAlert, AlertTriangle, ChevronDown, ChevronUp, Wrench, Check } from 'lucide-react';

export default function NewScanModal({ isOpen, onClose, onScanCreated }) {
  const [target, setTarget] = useState('');
  const [scopeType, setScopeType] = useState('web');
  const [authorizedExploit, setAuthorizedExploit] = useState(false);
  const [availableTools, setAvailableTools] = useState([]);
  const [selectedTools, setSelectedTools] = useState(new Set());
  const [showToolSelect, setShowToolSelect] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (isOpen) {
      fetch('/api/tools/catalog')
        .then((r) => r.json())
        .then((data) => {
          setAvailableTools(data);
          // By default, enable all installed Tier 1 & Tier 2 tools
          const defaultSet = new Set(
            data
              .filter((t) => t.installed && (t.tier <= 2 || authorizedExploit))
              .map((t) => t.name)
          );
          setSelectedTools(defaultSet);
        })
        .catch((err) => console.error('Failed to load tools catalog:', err));
    }
  }, [isOpen, authorizedExploit]);

  if (!isOpen) return null;

  const toggleTool = (toolName) => {
    const next = new Set(selectedTools);
    if (next.has(toolName)) {
      next.delete(toolName);
    } else {
      next.add(toolName);
    }
    setSelectedTools(next);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    const cleanTarget = target.trim();
    if (!cleanTarget) {
      setError('Please provide a target domain, URL, or IP address.');
      return;
    }

    setLoading(true);
    try {
      const resp = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: cleanTarget,
          scope_type: scopeType,
          authorized_exploitation: authorizedExploit,
          enabled_tools: Array.from(selectedTools),
        }),
      });

      let data = {};
      const contentType = resp.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        data = await resp.json();
      } else {
        const errorText = await resp.text();
        throw new Error(errorText || `Backend responded with HTTP ${resp.status}`);
      }

      if (!resp.ok) {
        throw new Error(data.detail || `Scan creation failed (HTTP ${resp.status})`);
      }

      onScanCreated(data.job_id);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" style={{ maxWidth: '680px' }} onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <ShieldAlert size={20} color="var(--cyber-cyan)" />
            <h3 style={{ fontSize: '1.15rem' }}>Launch Authorized Security Scan</h3>
          </div>
          <button className="btn-icon" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            {error && (
              <div style={{
                background: 'var(--sev-critical-bg)',
                border: '1px solid var(--sev-critical-border)',
                color: 'var(--sev-critical)',
                padding: '12px 14px',
                borderRadius: '8px',
                fontSize: '0.85rem',
                marginBottom: '16px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}>
                <AlertTriangle size={18} style={{ flexShrink: 0 }} />
                <span>{error}</span>
              </div>
            )}

            <div className="form-group">
              <label className="form-label">Target Host / URL / IP</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. 192.168.1.55 or http://juice-shop.local:3000"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                autoFocus
              />
              <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                Target must be a designated lab environment or authorized asset.
              </span>
            </div>

            <div className="form-group">
              <label className="form-label">Assessment Scope</label>
              <select
                className="form-select"
                value={scopeType}
                onChange={(e) => setScopeType(e.target.value)}
              >
                <option value="web">Web Application (ZAP, Nikto, WhatWeb, Wafw00f, Nuclei)</option>
                <option value="api">REST/OpenAPI Services (Fuzzer, Nuclei API, Dirsearch)</option>
                <option value="network">Network Infrastructure (Nmap, Services, Port Discovery, SMB)</option>
              </select>
            </div>

            {/* Authorized Exploitation Gating */}
            <div style={{
              background: 'rgba(255, 255, 255, 0.02)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '14px',
              marginTop: '10px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontSize: '0.88rem', fontWeight: '600' }}>Authorized Exploitation (Tier 3 Gate)</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    Unlock active verification modules (Metasploit, SQLMap, Hydra) against allowlisted IPs
                  </div>
                </div>
                <input
                  type="checkbox"
                  style={{ width: '18px', height: '18px', accentColor: 'var(--cyber-cyan)', cursor: 'pointer' }}
                  checked={authorizedExploit}
                  onChange={(e) => setAuthorizedExploit(e.target.checked)}
                />
              </div>

              {authorizedExploit && (
                <div style={{
                  marginTop: '10px',
                  fontSize: '0.74rem',
                  color: 'var(--sev-medium)',
                  background: 'var(--sev-medium-bg)',
                  padding: '8px 10px',
                  borderRadius: '6px',
                  border: '1px solid var(--sev-medium-border)'
                }}>
                  ⚠️ Target will be verified against the server EXPLOIT_ALLOWLIST. Targets outside private lab CIDRs will be blocked.
                </div>
              )}
            </div>

            {/* Custom Tool Selection Panel */}
            <div style={{ marginTop: '14px' }}>
              <button
                type="button"
                className="btn btn-secondary"
                style={{ width: '100%', justifyContent: 'space-between', padding: '10px 14px' }}
                onClick={() => setShowToolSelect(!showToolSelect)}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.84rem' }}>
                  <Wrench size={16} color="var(--cyber-cyan)" />
                  <span>Customize Pipeline Tools ({selectedTools.size} enabled)</span>
                </div>
                {showToolSelect ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
              </button>

              {showToolSelect && (
                <div style={{
                  background: 'rgba(6, 9, 17, 0.7)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '8px',
                  padding: '12px',
                  marginTop: '8px',
                  maxHeight: '200px',
                  overflowY: 'auto',
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
                  gap: '8px',
                }}>
                  {availableTools
                    .filter((t) => t.installed && (t.tier <= 2 || authorizedExploit))
                    .map((t) => {
                      const isChecked = selectedTools.has(t.name);
                      return (
                        <label
                          key={t.name}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '8px',
                            padding: '6px 8px',
                            borderRadius: '6px',
                            background: isChecked ? 'rgba(0, 242, 254, 0.08)' : 'rgba(255, 255, 255, 0.02)',
                            cursor: 'pointer',
                            fontSize: '0.78rem',
                            border: isChecked ? '1px solid rgba(0, 242, 254, 0.25)' : '1px solid transparent',
                          }}
                        >
                          <input
                            type="checkbox"
                            checked={isChecked}
                            onChange={() => toggleTool(t.name)}
                            style={{ accentColor: 'var(--cyber-cyan)' }}
                          />
                          <span style={{ fontWeight: '600' }}>{t.name}</span>
                          <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>T{t.tier}</span>
                        </label>
                      );
                    })}
                </div>
              )}
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              <Play size={16} />
              <span>{loading ? 'Launching Pipeline...' : 'Start Pipeline'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
