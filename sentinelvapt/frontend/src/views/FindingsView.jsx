import React, { useState, useEffect } from 'react';
import { 
  Bug, 
  Search, 
  ChevronDown, 
  ChevronUp, 
  CheckCircle, 
  AlertTriangle, 
  ShieldCheck, 
  Cpu, 
  ExternalLink 
} from 'lucide-react';

export default function FindingsView({ activeJobId, onSelectJob }) {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterSev, setFilterSev] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [includeFP, setIncludeFP] = useState(false);

  const fetchFindings = async () => {
    setLoading(true);
    try {
      let url = activeJobId 
        ? `/api/scans/${activeJobId}/findings?include_false_positives=${includeFP}`
        : `/api/scans`; // fallback
      
      if (activeJobId) {
        if (filterSev !== 'all') {
          url += `&severity=${filterSev}`;
        }
        const resp = await fetch(url);
        if (resp.ok) {
          const data = await resp.json();
          setFindings(data);
        }
      } else {
        // Fetch latest scan findings if no specific job selected
        const scansResp = await fetch('/api/scans');
        if (scansResp.ok) {
          const scans = await scansResp.json();
          if (scans.length > 0) {
            const firstJobId = scans[0].id;
            onSelectJob(firstJobId);
          }
        }
      }
    } catch (err) {
      console.error('Failed to fetch findings:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (activeJobId) {
      fetchFindings();
    }
  }, [activeJobId, filterSev, includeFP]);

  const toggleFalsePositive = async (findingId, currentStatus) => {
    try {
      const resp = await fetch(`/api/findings/${findingId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_false_positive: !currentStatus }),
      });
      if (resp.ok) {
        setFindings((prev) =>
          prev.map((f) =>
            f.id === findingId ? { ...f, is_false_positive: !currentStatus } : f
          )
        );
      }
    } catch (err) {
      alert('Failed to update false positive status: ' + err.message);
    }
  };

  const filtered = findings.filter((f) => {
    const q = searchQuery.toLowerCase();
    const titleMatch = f.title?.toLowerCase().includes(q);
    const assetMatch = f.affected_asset?.toLowerCase().includes(q);
    const cveMatch = f.cve_ids?.some((c) => c.toLowerCase().includes(q));
    const cweMatch = f.cwe_ids?.some((c) => c.toLowerCase().includes(q));
    return titleMatch || assetMatch || cveMatch || cweMatch;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* ── Filters & Search Header ────────────────────────────── */}
      <div className="card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: '14px' }}>
          {/* Severity Pills */}
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            {['all', 'critical', 'high', 'medium', 'low', 'info'].map((sev) => (
              <button
                key={sev}
                className={`btn btn-secondary ${filterSev === sev ? 'btn-primary' : ''}`}
                style={{ 
                  padding: '5px 12px', 
                  fontSize: '0.78rem',
                  textTransform: 'uppercase',
                  fontWeight: '700'
                }}
                onClick={() => setFilterSev(sev)}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Search bar & False Positive Toggle */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <div style={{ position: 'relative', width: '260px' }}>
              <Search size={15} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-muted)' }} />
              <input
                type="text"
                className="form-input"
                style={{ paddingLeft: '32px', fontSize: '0.82rem', padding: '7px 10px 7px 32px' }}
                placeholder="Search CVE, weakness, asset..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.78rem', color: 'var(--text-secondary)', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={includeFP}
                onChange={(e) => setIncludeFP(e.target.checked)}
                style={{ accentColor: 'var(--cyber-cyan)' }}
              />
              <span>Include FP</span>
            </label>
          </div>
        </div>
      </div>

      {/* ── Findings List ──────────────────────────────────────── */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px', color: 'var(--text-muted)' }}>
          Scanning findings repository...
        </div>
      ) : filtered.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '50px 20px', color: 'var(--text-muted)' }}>
          <CheckCircle size={38} color="var(--cyber-emerald)" style={{ marginBottom: '10px' }} />
          <h3>No Vulnerabilities Found</h3>
          <p style={{ fontSize: '0.86rem', marginTop: '4px' }}>
            Under the current filter criteria, no active findings were recorded.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {filtered.map((f) => {
            const isExpanded = expandedId === f.id;
            const sev = (f.severity || 'info').toLowerCase();
            const badgeClass = `badge-${sev}`;

            return (
              <div 
                key={f.id} 
                className="card"
                style={{ 
                  padding: '16px 20px', 
                  borderLeft: `4px solid var(--sev-${sev})`,
                  cursor: 'pointer' 
                }}
                onClick={() => setExpandedId(isExpanded ? null : f.id)}
              >
                {/* Header Row */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '14px' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                    <span className={`badge ${badgeClass}`}>{f.severity}</span>
                    <div>
                      <h4 style={{ fontSize: '0.98rem', fontWeight: '700' }}>{f.title}</h4>
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '4px', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                        <span>Asset: <code style={{ color: '#fff' }}>{f.affected_asset}</code></span>
                        {f.affected_component && <span>Component: <code>{f.affected_component}</code></span>}
                        <span>Tool: <span style={{ color: 'var(--cyber-cyan)' }}>{f.source_tool}</span></span>
                        {f.cvss_score && <span>CVSS: <b style={{ color: 'var(--sev-critical)' }}>{f.cvss_score.toFixed(1)}</b></span>}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {f.is_false_positive && (
                      <span className="badge badge-info" style={{ textDecoration: 'line-through' }}>False Positive</span>
                    )}
                    {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div 
                    style={{ 
                      marginTop: '16px', 
                      paddingTop: '16px', 
                      borderTop: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '14px'
                    }}
                    onClick={(e) => e.stopPropagation()}
                  >
                    {/* Description */}
                    <div>
                      <div style={{ fontSize: '0.8rem', fontWeight: '700', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                        DESCRIPTION
                      </div>
                      <p style={{ fontSize: '0.88rem', color: 'var(--text-primary)', lineHeight: '1.6' }}>
                        {f.description}
                      </p>
                    </div>

                    {/* AI Reasoning & Attack Chain */}
                    {f.ai_reasoning && (
                      <div style={{
                        background: 'rgba(121, 40, 202, 0.08)',
                        border: '1px solid rgba(121, 40, 202, 0.25)',
                        borderRadius: '8px',
                        padding: '12px 16px',
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--cyber-purple)', fontSize: '0.8rem', fontWeight: '700', marginBottom: '6px' }}>
                          <Cpu size={15} />
                          <span>AI VALIDATION & THREAT REASONING</span>
                        </div>
                        <p style={{ fontSize: '0.84rem', color: '#e2e8f0', lineHeight: '1.6' }}>
                          {f.ai_reasoning}
                        </p>
                        {f.attack_chain && (
                          <div style={{ marginTop: '8px', fontSize: '0.82rem', color: 'var(--cyber-cyan)' }}>
                            <b>Attack Vector:</b> {f.attack_chain}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Remediation Guidance */}
                    <div>
                      <div style={{ fontSize: '0.8rem', fontWeight: '700', color: 'var(--cyber-emerald)', marginBottom: '4px' }}>
                        REMEDIATION GUIDANCE
                      </div>
                      <div style={{
                        background: 'rgba(16, 185, 129, 0.08)',
                        border: '1px solid rgba(16, 185, 129, 0.2)',
                        padding: '10px 14px',
                        borderRadius: '6px',
                        fontSize: '0.85rem',
                        lineHeight: '1.5'
                      }}>
                        {f.remediation || 'Apply latest vendor security patch and restrict port access.'}
                      </div>
                    </div>

                    {/* Technical Proof / Evidence */}
                    {f.evidence && (
                      <div>
                        <div style={{ fontSize: '0.8rem', fontWeight: '700', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                          EVIDENCE / VERIFICATION OUTPUT
                        </div>
                        <pre style={{
                          background: '#040711',
                          padding: '12px 14px',
                          borderRadius: '8px',
                          fontSize: '0.78rem',
                          color: '#94a3b8',
                          overflowX: 'auto',
                          maxHeight: '220px',
                          border: '1px solid var(--border-subtle)'
                        }}>
                          {f.evidence}
                        </pre>
                      </div>
                    )}

                    {/* References & Actions */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '8px' }}>
                      <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                        {f.cve_ids?.map((c) => (
                          <span key={c} className="badge badge-info">{c}</span>
                        ))}
                        {f.cwe_ids?.map((w) => (
                          <span key={w} className="badge badge-info">{w}</span>
                        ))}
                        {f.mitre_technique_id && (
                          <span className="badge badge-info" style={{ color: 'var(--cyber-cyan)' }}>
                            MITRE {f.mitre_technique_id}
                          </span>
                        )}
                      </div>

                      <button 
                        className="btn btn-secondary" 
                        style={{ fontSize: '0.75rem', padding: '5px 12px' }}
                        onClick={() => toggleFalsePositive(f.id, f.is_false_positive)}
                      >
                        {f.is_false_positive ? 'Mark as Confirmed' : 'Mark as False Positive'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
