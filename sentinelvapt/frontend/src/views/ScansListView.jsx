import React, { useState } from 'react';
import { 
  Scan, 
  Trash2, 
  FileText, 
  Play, 
  Search, 
  ArrowRight, 
  ShieldAlert, 
  CheckCircle2 
} from 'lucide-react';

export default function ScansListView({ 
  scans, 
  onSelectScan, 
  onOpenNewScan, 
  onRefreshScans 
}) {
  const [search, setSearch] = useState('');

  const handleDelete = async (e, scanId) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this scan and its records?')) return;
    try {
      const resp = await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
      if (resp.ok) {
        onRefreshScans();
      }
    } catch (err) {
      alert('Failed to delete scan: ' + err.message);
    }
  };

  const filtered = scans.filter((s) => 
    s.target?.toLowerCase().includes(search.toLowerCase()) ||
    s.id?.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* ── Header Bar ────────────────────────────────────────── */}
      <div className="card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ position: 'relative', width: '320px' }}>
            <Search size={16} style={{ position: 'absolute', left: '12px', top: '10px', color: 'var(--text-muted)' }} />
            <input
              type="text"
              className="form-input"
              style={{ paddingLeft: '36px', fontSize: '0.85rem' }}
              placeholder="Filter by target or Job ID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <button className="btn btn-primary" onClick={onOpenNewScan}>
            <Play size={16} />
            <span>New Scan Job</span>
          </button>
        </div>
      </div>

      {/* ── Table of Scans ─────────────────────────────────────── */}
      <div className="card">
        {filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '50px 20px', color: 'var(--text-muted)' }}>
            <Scan size={38} style={{ opacity: 0.3, marginBottom: '10px' }} />
            <p>No matching scan jobs found.</p>
          </div>
        ) : (
          <div className="table-container">
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Target Host</th>
                  <th>Scope</th>
                  <th>Current State</th>
                  <th>Findings Overview</th>
                  <th>Reports</th>
                  <th>Timestamp</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((s) => {
                  const counts = s.finding_counts || {};
                  const isDone = s.current_stage === 'done';
                  const isRunning = !isDone && s.current_stage !== 'failed';

                  return (
                    <tr 
                      key={s.id} 
                      onClick={() => onSelectScan(s.id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <div style={{ fontWeight: '700', color: '#fff' }}>{s.target}</div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                          {s.id}
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-info">{s.scope_type}</span>
                      </td>
                      <td>
                        <span style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '6px',
                          fontSize: '0.8rem',
                          fontWeight: '600',
                          color: isDone ? 'var(--cyber-emerald)' : isRunning ? 'var(--cyber-cyan)' : 'var(--sev-critical)'
                        }}>
                          {isRunning && <span className="status-dot"></span>}
                          {s.current_stage.replace('_', ' ').toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          {counts.critical > 0 && <span className="badge badge-critical">{counts.critical} C</span>}
                          {counts.high > 0 && <span className="badge badge-high">{counts.high} H</span>}
                          {counts.medium > 0 && <span className="badge badge-medium">{counts.medium} M</span>}
                          {counts.low > 0 && <span className="badge badge-low">{counts.low} L</span>}
                          {Object.values(counts).reduce((a, b) => a + b, 0) === 0 && (
                            <span style={{ color: 'var(--text-dim)', fontSize: '0.78rem' }}>0 findings</span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '6px' }} onClick={(e) => e.stopPropagation()}>
                          {s.has_pdf_report && (
                            <a 
                              href={`/api/scans/${s.id}/reports/download/pdf`} 
                              target="_blank" 
                              rel="noreferrer"
                              className="btn-icon" 
                              title="Download PDF"
                            >
                              <FileText size={15} color="var(--sev-critical)" />
                            </a>
                          )}
                          {s.has_md_report && (
                            <a 
                              href={`/api/scans/${s.id}/reports/download/markdown`} 
                              target="_blank" 
                              rel="noreferrer"
                              className="btn-icon" 
                              title="Download Markdown"
                            >
                              <FileText size={15} color="var(--cyber-blue)" />
                            </a>
                          )}
                        </div>
                      </td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        {new Date(s.created_at).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '8px' }} onClick={(e) => e.stopPropagation()}>
                          <button 
                            className="btn btn-secondary" 
                            style={{ fontSize: '0.74rem', padding: '6px 10px' }}
                            onClick={() => onSelectScan(s.id)}
                          >
                            Monitor
                          </button>
                          <button 
                            className="btn-icon" 
                            style={{ color: 'var(--sev-critical)' }}
                            onClick={(e) => handleDelete(e, s.id)}
                            title="Delete Scan"
                          >
                            <Trash2 size={15} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
