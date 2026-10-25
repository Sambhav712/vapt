import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Download, 
  Copy, 
  Check, 
  FileCode, 
  Flame, 
  Terminal 
} from 'lucide-react';

export default function DefensiveView({ activeJobId, onSelectJob }) {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeFormat, setActiveFormat] = useState('sigma');
  const [copiedId, setCopiedId] = useState(null);

  useEffect(() => {
    const fetchRules = async () => {
      setLoading(true);
      try {
        if (!activeJobId) {
          const scansResp = await fetch('/api/scans');
          if (scansResp.ok) {
            const scans = await scansResp.json();
            if (scans.length > 0) {
              onSelectJob(scans[0].id);
              return;
            }
          }
        } else {
          const resp = await fetch(`/api/scans/${activeJobId}/defensive-rules`);
          if (resp.ok) {
            const data = await resp.json();
            setRules(data);
          }
        }
      } catch (err) {
        console.error('Failed to fetch defensive rules:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchRules();
  }, [activeJobId]);

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* ── Header Card ────────────────────────────────────────── */}
      <div className="card" style={{
        background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(15, 23, 42, 0.9) 100%)',
        border: '1px solid rgba(16, 185, 129, 0.25)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--cyber-emerald)', fontWeight: '700', fontSize: '0.85rem' }}>
              <ShieldCheck size={18} />
              <span>PURPLE TEAM DETECTION HUB</span>
            </div>
            <h2 style={{ fontSize: '1.45rem', marginTop: '4px' }}>Automated Defensive Rule Generation</h2>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginTop: '4px' }}>
              Every confirmed security finding is automatically converted into SIEM detection rules,
              host intrusion rules, and network IDS signatures.
            </p>
          </div>

          {activeJobId && rules.length > 0 && (
            <a 
              href={`/api/scans/${activeJobId}/defensive-rules/export`}
              download
              className="btn btn-primary"
            >
              <Download size={16} />
              <span>Export Rules (.ZIP)</span>
            </a>
          )}
        </div>
      </div>

      {/* ── Format Switcher ────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: '10px' }}>
        {[
          { id: 'sigma', label: 'Sigma SIEM Rules', count: rules.filter((r) => r.sigma_rule).length },
          { id: 'wazuh', label: 'Wazuh HIDS Rules', count: rules.filter((r) => r.wazuh_rule).length },
          { id: 'suricata', label: 'Suricata NIDS', count: rules.filter((r) => r.suricata_rule).length },
          { id: 'firewall', label: 'Host Firewall', count: rules.filter((r) => r.firewall_rule).length },
        ].map((fmt) => (
          <button
            key={fmt.id}
            className={`btn btn-secondary ${activeFormat === fmt.id ? 'btn-primary' : ''}`}
            style={{ fontSize: '0.82rem', padding: '7px 16px' }}
            onClick={() => setActiveFormat(fmt.id)}
          >
            <span>{fmt.label}</span>
            <span style={{
              background: 'rgba(0,0,0,0.3)',
              padding: '2px 6px',
              borderRadius: '4px',
              fontSize: '0.72rem'
            }}>
              {fmt.count}
            </span>
          </button>
        ))}
      </div>

      {/* ── Rules Display ──────────────────────────────────────── */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
          Loading detection engineering rules...
        </div>
      ) : rules.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '50px 20px', color: 'var(--text-muted)' }}>
          <ShieldCheck size={38} style={{ opacity: 0.3, marginBottom: '10px' }} />
          <h3>No Detection Rules Available</h3>
          <p style={{ fontSize: '0.86rem', marginTop: '4px' }}>
            Rules will appear here automatically when high-severity vulnerabilities are cataloged.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {rules.map((r) => {
            let ruleContent = '';
            let lang = 'yaml';

            if (activeFormat === 'sigma') {
              ruleContent = r.sigma_rule;
              lang = 'yaml';
            } else if (activeFormat === 'wazuh') {
              ruleContent = r.wazuh_rule;
              lang = 'xml';
            } else if (activeFormat === 'suricata') {
              ruleContent = r.suricata_rule;
              lang = 'text';
            } else if (activeFormat === 'firewall') {
              ruleContent = r.firewall_rule;
              lang = 'bash';
            }

            if (!ruleContent) return null;

            return (
              <div key={r.id} className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                  <div>
                    <h4 style={{ fontSize: '1rem', fontWeight: '700' }}>{r.finding_title}</h4>
                    <div style={{ fontSize: '0.76rem', color: 'var(--text-secondary)', marginTop: '2px', display: 'flex', gap: '10px' }}>
                      <span>Severity: <b style={{ color: `var(--sev-${r.finding_severity})` }}>{r.finding_severity?.toUpperCase()}</b></span>
                      {r.mitre_technique_id && <span>MITRE: <code>{r.mitre_technique_id}</code></span>}
                      {activeFormat === 'sigma' && r.sigma_valid && (
                        <span style={{ color: 'var(--cyber-emerald)', fontWeight: '600' }}>✓ Valid Sigma YAML</span>
                      )}
                    </div>
                  </div>

                  <button
                    className="btn btn-secondary"
                    style={{ fontSize: '0.75rem', padding: '6px 12px' }}
                    onClick={() => copyToClipboard(ruleContent, r.id)}
                  >
                    {copiedId === r.id ? <Check size={14} color="var(--cyber-emerald)" /> : <Copy size={14} />}
                    <span>{copiedId === r.id ? 'Copied' : 'Copy Rule'}</span>
                  </button>
                </div>

                <pre style={{
                  background: '#040711',
                  padding: '14px 16px',
                  borderRadius: '8px',
                  fontSize: '0.8rem',
                  fontFamily: 'var(--font-mono)',
                  color: '#e2e8f0',
                  overflowX: 'auto',
                  border: '1px solid var(--border-subtle)',
                  lineHeight: '1.5'
                }}>
                  {ruleContent}
                </pre>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
