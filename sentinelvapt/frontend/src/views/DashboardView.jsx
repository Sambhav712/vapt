import React from 'react';
import { 
  Play, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Flame, 
  Scan, 
  ArrowRight, 
  Download, 
  FileText 
} from 'lucide-react';

export default function DashboardView({ 
  scans, 
  tools, 
  onOpenNewScan, 
  onSelectScan, 
  onNavigate 
}) {
  // Aggregate KPIs
  const totalScans = scans.length;
  let totalCritical = 0;
  let totalHigh = 0;

  scans.forEach((s) => {
    totalCritical += s.finding_counts?.critical || 0;
    totalHigh += s.finding_counts?.high || 0;
  });

  const readyToolsCount = tools.filter((t) => t.installed).length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* ── Hero Launch Banner ─────────────────────────────────── */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(20, 30, 55, 0.8) 100%)',
        border: '1px solid rgba(0, 242, 254, 0.2)',
        borderRadius: '16px',
        padding: '28px 32px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        boxShadow: '0 10px 30px -10px rgba(0, 242, 254, 0.1)',
        position: 'relative',
        overflow: 'hidden',
      }}>
        <div style={{ zIndex: 1, maxWidth: '650px' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 10px',
            borderRadius: '20px',
            background: 'rgba(0, 242, 254, 0.1)',
            color: 'var(--cyber-cyan)',
            fontSize: '0.75rem',
            fontWeight: '600',
            marginBottom: '12px',
            border: '1px solid rgba(0, 242, 254, 0.25)',
          }}>
            <ShieldAlert size={14} />
            <span>AI-Driven Autonomous VAPT Engine</span>
          </div>
          <h2 style={{ fontSize: '1.75rem', fontWeight: '800', marginBottom: '8px' }}>
            Next-Gen Autonomous Security Pipeline
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.92rem', lineHeight: '1.6' }}>
            Orchestrate multi-tool recon, vulnerability auditing, AI false-positive elimination,
            and automatic Purple-Team defensive detection engineering against consented targets.
          </p>
        </div>

        <div style={{ zIndex: 1 }}>
          <button className="btn btn-primary" style={{ padding: '12px 24px', fontSize: '0.95rem' }} onClick={onOpenNewScan}>
            <Play size={18} />
            <span>Launch New Scan</span>
          </button>
        </div>
      </div>

      {/* ── KPI Stat Cards ─────────────────────────────────────── */}
      <div className="stats-grid">
        <div className="stat-card" style={{ '--accent-color': 'var(--cyber-cyan)' }}>
          <div className="stat-icon"><Scan size={22} /></div>
          <div className="stat-info">
            <span className="stat-value">{totalScans}</span>
            <span className="stat-label">Total Executions</span>
          </div>
        </div>

        <div className="stat-card" style={{ '--accent-color': 'var(--sev-critical)' }}>
          <div className="stat-icon"><Flame size={22} /></div>
          <div className="stat-info">
            <span className="stat-value" style={{ color: 'var(--sev-critical)' }}>{totalCritical}</span>
            <span className="stat-label">Critical Findings</span>
          </div>
        </div>

        <div className="stat-card" style={{ '--accent-color': 'var(--sev-high)' }}>
          <div className="stat-icon"><AlertTriangle size={22} /></div>
          <div className="stat-info">
            <span className="stat-value" style={{ color: 'var(--sev-high)' }}>{totalHigh}</span>
            <span className="stat-label">High Severity</span>
          </div>
        </div>

        <div className="stat-card" style={{ '--accent-color': 'var(--cyber-emerald)' }}>
          <div className="stat-icon"><CheckCircle2 size={22} /></div>
          <div className="stat-info">
            <span className="stat-value">{readyToolsCount} / {tools.length || 10}</span>
            <span className="stat-label">Security Tools Ready</span>
          </div>
        </div>
      </div>

      {/* ── Recent Scans Section ───────────────────────────────── */}
      <div className="card">
        <div className="card-title">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Scan size={18} color="var(--cyber-cyan)" />
            <span>Recent Pipeline Executions</span>
          </div>
          <button 
            className="btn btn-secondary" 
            style={{ fontSize: '0.78rem', padding: '5px 10px' }}
            onClick={() => onNavigate('scans')}
          >
            <span>View All</span>
            <ArrowRight size={14} />
          </button>
        </div>

        {scans.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
            <Scan size={36} style={{ opacity: 0.3, marginBottom: '10px' }} />
            <p>No security assessments recorded yet.</p>
            <button className="btn btn-secondary" style={{ marginTop: '12px' }} onClick={onOpenNewScan}>
              Start your first scan
            </button>
          </div>
        ) : (
          <div className="table-container">
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Scope</th>
                  <th>Current Stage</th>
                  <th>Findings</th>
                  <th>Reports</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 8).map((scan) => {
                  const counts = scan.finding_counts || {};
                  const isDone = scan.current_stage === 'done';
                  const isRunning = !isDone && scan.current_stage !== 'failed';

                  return (
                    <tr key={scan.id}>
                      <td>
                        <div style={{ fontWeight: '600', color: '#fff' }}>{scan.target}</div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                          ID: {scan.id.slice(0, 8)}...
                        </div>
                      </td>
                      <td>
                        <span className="badge badge-info">{scan.scope_type}</span>
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
                          {scan.current_stage.replace('_', ' ').toUpperCase()}
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
                        <div style={{ display: 'flex', gap: '6px' }}>
                          {scan.has_pdf_report && (
                            <a 
                              href={`/api/scans/${scan.id}/reports/download/pdf`} 
                              target="_blank" 
                              rel="noreferrer"
                              className="btn-icon" 
                              title="Download PDF Report"
                            >
                              <FileText size={15} color="var(--sev-critical)" />
                            </a>
                          )}
                          {scan.has_md_report && (
                            <a 
                              href={`/api/scans/${scan.id}/reports/download/markdown`} 
                              target="_blank" 
                              rel="noreferrer"
                              className="btn-icon" 
                              title="Download Markdown Report"
                            >
                              <FileText size={15} color="var(--cyber-blue)" />
                            </a>
                          )}
                        </div>
                      </td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        {new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td>
                        <button 
                          className="btn btn-secondary" 
                          style={{ fontSize: '0.76rem', padding: '6px 12px' }}
                          onClick={() => onSelectScan(scan.id)}
                        >
                          Monitor
                        </button>
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
