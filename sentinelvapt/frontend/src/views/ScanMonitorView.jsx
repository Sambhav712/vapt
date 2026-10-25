import React, { useState, useEffect, useRef } from 'react';
import { 
  Terminal, 
  Check, 
  Clock, 
  AlertCircle, 
  Download, 
  FileText, 
  ArrowLeft, 
  XOctagon, 
  Bug, 
  ShieldCheck, 
  RefreshCw 
} from 'lucide-react';

const STAGES = [
  { id: 'tool_check', label: 'Tool Check' },
  { id: 'recon', label: 'Reconnaissance' },
  { id: 'vuln_scan', label: 'Vuln Scan' },
  { id: 'exploitation', label: 'Exploitation' },
  { id: 'ai_analysis', label: 'AI Analysis' },
  { id: 'report_generation', label: 'Reports' },
  { id: 'defensive_rule_generation', label: 'Defensive Rules' },
  { id: 'done', label: 'Concluded' },
];

export default function ScanMonitorView({ 
  jobId, 
  onBack, 
  onViewFindings, 
  onViewDefensive 
}) {
  const [job, setJob] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const terminalRef = useRef(null);

  // Poll scan details
  const fetchJob = async () => {
    try {
      const resp = await fetch(`/api/scans/${jobId}`);
      if (resp.ok) {
        const data = await resp.json();
        setJob(data);
        if (data.logs && data.logs.length > logs.length) {
          setLogs(data.logs);
        }
      }
    } catch (err) {
      console.error('Failed to fetch job status:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchJob();
    const interval = setInterval(fetchJob, 3000);
    return () => clearInterval(interval);
  }, [jobId]);

  // Connect to SSE stream for live updates
  useEffect(() => {
    const eventSource = new EventSource(`/api/scans/${jobId}/stream`);

    eventSource.onmessage = (e) => {
      try {
        const payload = JSON.parse(e.data);
        if (payload.msg) {
          setLogs((prev) => [...prev, payload]);
        }
      } catch (err) {
        // Raw text event
        setLogs((prev) => [
          ...prev, 
          { ts: new Date().toISOString(), stage: 'stream', msg: e.data }
        ]);
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [jobId]);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  const handleCancel = async () => {
    if (!confirm('Are you sure you want to cancel this active scan?')) return;
    try {
      await fetch(`/api/scans/${jobId}/cancel`, { method: 'POST' });
      fetchJob();
    } catch (err) {
      alert('Failed to cancel scan: ' + err.message);
    }
  };

  if (loading && !job) {
    return (
      <div style={{ textAlign: 'center', padding: '80px', color: 'var(--text-muted)' }}>
        <RefreshCw size={28} className="spin" style={{ marginBottom: '12px' }} />
        <p>Loading scan telemetry...</p>
      </div>
    );
  }

  const currentStage = job?.current_stage || 'tool_check';
  const stageStatuses = job?.stage_statuses || {};
  const isConcluded = currentStage === 'done' || currentStage === 'failed';
  const counts = job?.finding_counts || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* ── Top Bar with Actions ───────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <button className="btn btn-secondary" onClick={onBack} style={{ padding: '8px 12px' }}>
            <ArrowLeft size={16} />
            <span>All Scans</span>
          </button>
          <div>
            <h2 style={{ fontSize: '1.4rem', fontWeight: '800' }}>{job?.target}</h2>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', gap: '12px' }}>
              <span>Scope: <b style={{ color: 'var(--cyber-cyan)' }}>{job?.scope_type?.toUpperCase()}</b></span>
              <span>•</span>
              <span>ID: <code style={{ color: 'var(--text-muted)' }}>{jobId}</code></span>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          {!isConcluded && (
            <button className="btn btn-danger" onClick={handleCancel}>
              <XOctagon size={16} />
              <span>Cancel Scan</span>
            </button>
          )}

          <button className="btn btn-secondary" onClick={() => onViewFindings(jobId)}>
            <Bug size={16} color="var(--sev-high)" />
            <span>Findings ({counts.critical + counts.high + counts.medium + counts.low || 0})</span>
          </button>

          <button className="btn btn-secondary" onClick={() => onViewDefensive(jobId)}>
            <ShieldCheck size={16} color="var(--cyber-emerald)" />
            <span>Defensive Rules</span>
          </button>
        </div>
      </div>

      {/* ── Pipeline Stepper ───────────────────────────────────── */}
      <div className="stepper-container">
        {STAGES.map((s, idx) => {
          const status = stageStatuses[s.id];
          const isCurrent = currentStage === s.id;
          const isPassed = status === 'completed' || isConcluded && s.id !== currentStage;
          const isFailed = status === 'failed';

          let stateClass = '';
          if (isPassed) stateClass = 'completed';
          else if (isCurrent && !isConcluded) stateClass = 'running';
          else if (isFailed) stateClass = 'failed';

          return (
            <div key={s.id} className={`step-item ${stateClass}`}>
              <div className="step-circle">
                {isPassed ? (
                  <Check size={16} />
                ) : isCurrent && !isConcluded ? (
                  <span className="spin" style={{ display: 'inline-block' }}>⚙</span>
                ) : (
                  idx + 1
                )}
              </div>
              <div className="step-label">{s.label}</div>
            </div>
          );
        })}
      </div>

      {/* ── Telemetry & Reports Card ───────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '20px' }}>
        {/* Terminal Window */}
        <div className="terminal-window">
          <div className="terminal-header">
            <div className="terminal-dots">
              <span className="terminal-dot red"></span>
              <span className="terminal-dot yellow"></span>
              <span className="terminal-dot green"></span>
            </div>
            <div className="terminal-title">
              live_telemetry://{job?.target}:{job?.current_stage}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--cyber-cyan)' }}>
              {logs.length} events
            </div>
          </div>

          <div className="terminal-body" ref={terminalRef}>
            {logs.length === 0 ? (
              <div style={{ color: 'var(--text-muted)' }}>Connecting to pipeline orchestrator stream...</div>
            ) : (
              logs.map((log, idx) => (
                <div key={idx} className="terminal-line">
                  <span className="terminal-ts">
                    {log.ts ? new Date(log.ts).toLocaleTimeString() : '--:--:--'}
                  </span>
                  <span className="terminal-stage">[{log.stage || 'scan'}]</span>
                  <span className="terminal-msg">{log.msg}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Info Sidebar */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Finding Scorecard */}
          <div className="card">
            <div className="card-title" style={{ fontSize: '0.9rem' }}>Vulnerability Scorecard</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="badge badge-critical">Critical</span>
                <span style={{ fontWeight: '700', fontSize: '1.1rem', color: 'var(--sev-critical)' }}>
                  {counts.critical || 0}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="badge badge-high">High</span>
                <span style={{ fontWeight: '700', fontSize: '1.1rem', color: 'var(--sev-high)' }}>
                  {counts.high || 0}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="badge badge-medium">Medium</span>
                <span style={{ fontWeight: '700', fontSize: '1.1rem', color: 'var(--sev-medium)' }}>
                  {counts.medium || 0}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="badge badge-low">Low / Info</span>
                <span style={{ fontWeight: '700', fontSize: '1.1rem', color: 'var(--sev-low)' }}>
                  {(counts.low || 0) + (counts.info || 0)}
                </span>
              </div>
            </div>
          </div>

          {/* Reports Card */}
          <div className="card">
            <div className="card-title" style={{ fontSize: '0.9rem' }}>Generated Audit Reports</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <a 
                href={`/api/scans/${jobId}/reports/download/pdf`}
                target="_blank"
                rel="noreferrer"
                className="btn btn-secondary"
                style={{ justifyContent: 'flex-start' }}
              >
                <FileText size={16} color="var(--sev-critical)" />
                <span>Executive PDF Report</span>
              </a>

              <a 
                href={`/api/scans/${jobId}/reports/download/markdown`}
                target="_blank"
                rel="noreferrer"
                className="btn btn-secondary"
                style={{ justifyContent: 'flex-start' }}
              >
                <FileText size={16} color="var(--cyber-blue)" />
                <span>Technical Markdown (.md)</span>
              </a>

              <a 
                href={`/api/scans/${jobId}/reports/download/json`}
                target="_blank"
                rel="noreferrer"
                className="btn btn-secondary"
                style={{ justifyContent: 'flex-start' }}
              >
                <Download size={16} color="var(--cyber-emerald)" />
                <span>Machine Raw JSON (.json)</span>
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
