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
  RefreshCw,
  Brain,
  Cpu,
  Zap,
  ChevronDown,
  ChevronUp,
  Sparkles,
  ShieldAlert
} from 'lucide-react';

const STAGES = [
  { id: 'tool_check', label: 'Tool Check' },
  { id: 'ai_orchestration', label: 'AI Decision Loop' },
  { id: 'ai_analysis', label: 'AI Synthesis' },
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
  const [aiDecisions, setAiDecisions] = useState([]);
  const [activeTab, setActiveTab] = useState('ai'); // 'ai' or 'terminal'
  const [expandedDecisions, setExpandedDecisions] = useState({});
  const [loading, setLoading] = useState(true);
  const terminalRef = useRef(null);

  // Poll scan details & AI decisions
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

  const fetchAiDecisions = async () => {
    try {
      const resp = await fetch(`/api/scans/${jobId}/ai-decisions`);
      if (resp.ok) {
        const data = await resp.json();
        setAiDecisions(data);
      }
    } catch (err) {
      console.error('Failed to fetch AI decisions:', err);
    }
  };

  useEffect(() => {
    fetchJob();
    fetchAiDecisions();
    const interval = setInterval(() => {
      fetchJob();
      fetchAiDecisions();
    }, 2500);
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
    if (terminalRef.current && activeTab === 'terminal') {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs, activeTab]);

  const handleCancel = async () => {
    if (!confirm('Are you sure you want to cancel this active scan?')) return;
    try {
      await fetch(`/api/scans/${jobId}/cancel`, { method: 'POST' });
      fetchJob();
    } catch (err) {
      alert('Failed to cancel scan: ' + err.message);
    }
  };

  const toggleDecisionExpand = (id) => {
    setExpandedDecisions((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  if (loading && !job) {
    return (
      <div style={{ textAlign: 'center', padding: '80px', color: 'var(--text-muted)' }}>
        <RefreshCw size={28} className="spin" style={{ marginBottom: '12px' }} />
        <p>Loading AI scan telemetry...</p>
      </div>
    );
  }

  const currentStage = job?.current_stage || 'tool_check';
  const stageStatuses = job?.stage_statuses || {};
  const isConcluded = currentStage === 'done' || currentStage === 'failed';
  const counts = job?.finding_counts || {};

  const currentIteration = job?.current_iteration || aiDecisions.length || 0;
  const maxIterations = job?.max_iterations || 20;
  const isHeuristic = job?.ai_orchestration_mode === 'heuristic_fallback';
  const progressPercent = Math.min(100, Math.round((currentIteration / maxIterations) * 100));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* ── Top Bar with Target & Action Controls ──────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <button className="btn btn-secondary" onClick={onBack} style={{ padding: '8px 12px' }}>
            <ArrowLeft size={16} />
            <span>All Scans</span>
          </button>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h2 style={{ fontSize: '1.4rem', fontWeight: '800' }}>{job?.target}</h2>
              {isHeuristic ? (
                <span className="ai-mode-badge heuristic">
                  <Cpu size={13} />
                  Heuristic Fallback
                </span>
              ) : (
                <span className="ai-mode-badge ai-driven">
                  <Brain size={13} />
                  AI-Driven Orchestrator
                </span>
              )}
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', display: 'flex', gap: '12px', marginTop: '4px' }}>
              <span>Scope: <b style={{ color: 'var(--cyber-cyan)' }}>{job?.scope_type?.toUpperCase()}</b></span>
              <span>•</span>
              <span>Mode: <b style={{ color: job?.authorized_exploitation ? 'var(--sev-high)' : 'var(--cyber-blue)' }}>
                {job?.authorized_exploitation ? 'EXPLOITATION AUTHORIZED' : 'ACTIVE SCAN'}
              </b></span>
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

      {/* ── AI Orchestration Live Status Banner ───────────────── */}
      <div className="ai-status-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{ 
              width: '38px', 
              height: '38px', 
              borderRadius: '10px', 
              background: 'rgba(0, 242, 254, 0.12)', 
              border: '1px solid rgba(0, 242, 254, 0.3)',
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center' 
            }}>
              <Brain size={20} color="var(--cyber-cyan)" className={!isConcluded ? "spin" : ""} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontSize: '0.95rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                  Autonomous AI Decision Engine
                </span>
                <span style={{ 
                  fontSize: '0.72rem', 
                  padding: '2px 8px', 
                  borderRadius: '12px',
                  background: isConcluded ? 'rgba(16, 185, 129, 0.2)' : 'rgba(0, 242, 254, 0.2)',
                  color: isConcluded ? 'var(--cyber-emerald)' : 'var(--cyber-cyan)',
                  fontWeight: '600'
                }}>
                  {isConcluded ? 'Assessment Completed' : `Iteration ${currentIteration} of ${maxIterations}`}
                </span>
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                {isConcluded 
                  ? 'All targeted testing, vulnerability correlation, and defensive hardening completed.' 
                  : aiDecisions.length > 0 
                    ? `Current Tool: [${aiDecisions[aiDecisions.length - 1]?.chosen_tool || 'Analyzing'}] — ${aiDecisions[aiDecisions.length - 1]?.reasoning?.slice(0, 85)}...`
                    : 'Gathering preliminary target fingerprinting and recon telemetry...'}
              </div>
            </div>
          </div>

          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Progress</div>
            <div style={{ fontSize: '1.1rem', fontWeight: '800', color: 'var(--cyber-cyan)' }}>
              {isConcluded ? '100%' : `${progressPercent}%`}
            </div>
          </div>
        </div>

        <div className="ai-progress-track">
          <div className="ai-progress-bar" style={{ width: isConcluded ? '100%' : `${progressPercent}%` }} />
        </div>
      </div>

      {/* ── High-Level Pipeline Stepper ──────────────────────── */}
      <div className="stepper-container">
        {STAGES.map((s, idx) => {
          const status = stageStatuses[s.id];
          const isCurrent = currentStage === s.id;
          const isPassed = status === 'completed' || (isConcluded && s.id !== currentStage);
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

      {/* ── Main Dual Telemetry & Sidebar View ───────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '20px' }}>
        {/* Left Column: AI Decision Timeline or Raw Console */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {/* Tab Selector */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button 
                className={`tab-nav-btn ${activeTab === 'ai' ? 'active' : ''}`}
                onClick={() => setActiveTab('ai')}
              >
                <Brain size={16} />
                <span>AI Decision Thought Process ({aiDecisions.length})</span>
              </button>

              <button 
                className={`tab-nav-btn ${activeTab === 'terminal' ? 'active' : ''}`}
                onClick={() => setActiveTab('terminal')}
              >
                <Terminal size={16} />
                <span>Raw Console Telemetry ({logs.length})</span>
              </button>
            </div>

            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Auto-updating via SSE & polling
            </div>
          </div>

          {/* Tab Content: AI Thought Process Timeline */}
          {activeTab === 'ai' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {aiDecisions.length === 0 ? (
                <div className="card" style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                  <Brain size={32} color="var(--cyber-purple)" className="spin" style={{ marginBottom: '12px' }} />
                  <p style={{ fontWeight: '600' }}>AI Decision Engine Initializing...</p>
                  <p style={{ fontSize: '0.8rem', marginTop: '4px' }}>
                    Examining target parameters and consulting tool registry. First decision will appear shortly.
                  </p>
                </div>
              ) : (
                aiDecisions.map((decision) => {
                  const isExpanded = !!expandedDecisions[decision.id];
                  const res = decision.tool_execution_result || {};
                  const isFinish = decision.action === 'finish';
                  const isGated = decision.action === 'need_authorization';

                  return (
                    <div 
                      key={decision.id} 
                      className={`ai-decision-card action-${decision.action}`}
                    >
                      {/* Card Header Row */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <span style={{ 
                            fontSize: '0.75rem', 
                            fontWeight: '800', 
                            padding: '3px 8px', 
                            borderRadius: '4px',
                            background: 'rgba(255, 255, 255, 0.08)',
                            color: 'var(--text-primary)',
                            fontFamily: 'var(--font-mono)'
                          }}>
                            STEP {decision.iteration}
                          </span>

                          <span style={{
                            fontSize: '0.75rem',
                            fontWeight: '800',
                            padding: '3px 8px',
                            borderRadius: '4px',
                            textTransform: 'uppercase',
                            background: isFinish 
                              ? 'rgba(16, 185, 129, 0.2)' 
                              : isGated 
                                ? 'rgba(255, 119, 0, 0.2)' 
                                : 'rgba(0, 242, 254, 0.15)',
                            color: isFinish 
                              ? 'var(--cyber-emerald)' 
                              : isGated 
                                ? 'var(--sev-high)' 
                                : 'var(--cyber-cyan)',
                          }}>
                            {isFinish 
                              ? 'ACTION: CONCLUDE SCAN' 
                              : isGated 
                                ? `GATED: ${decision.chosen_tool}` 
                                : `RUN TOOL: ${decision.chosen_tool}`}
                          </span>

                          <span style={{ 
                            fontSize: '0.75rem', 
                            color: 'var(--text-secondary)',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '4px'
                          }}>
                            <Sparkles size={12} color="var(--cyber-purple)" />
                            {Math.round((decision.confidence || 0.9) * 100)}% Confidence
                          </span>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {decision.latency > 0 && (
                            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                              LLM: {decision.latency.toFixed(2)}s
                            </span>
                          )}
                          <button 
                            className="btn btn-secondary" 
                            style={{ padding: '3px 8px', fontSize: '0.72rem' }}
                            onClick={() => toggleDecisionExpand(decision.id)}
                          >
                            <span>Details</span>
                            {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                          </button>
                        </div>
                      </div>

                      {/* AI Thought Process / Reasoning */}
                      <div style={{ marginBottom: '8px' }}>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: '700', marginBottom: '4px' }}>
                          AI Thought Process & Rationale
                        </div>
                        <div className="ai-reasoning-box">
                          {decision.reasoning}
                        </div>
                      </div>

                      {/* Expected Outcome */}
                      {decision.expected_outcome && (
                        <div style={{ marginBottom: '8px' }}>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: '700', marginBottom: '4px' }}>
                            Expected Intelligence Outcome
                          </div>
                          <div className="ai-outcome-box">
                            {decision.expected_outcome}
                          </div>
                        </div>
                      )}

                      {/* Tool Execution Summary Tag */}
                      {res.summary && (
                        <div style={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          justifyContent: 'space-between',
                          marginTop: '8px', 
                          paddingTop: '8px',
                          borderTop: '1px solid var(--border-subtle)',
                          fontSize: '0.76rem',
                          color: 'var(--text-secondary)'
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ 
                              width: '8px', 
                              height: '8px', 
                              borderRadius: '50%', 
                              background: res.success ? 'var(--cyber-emerald)' : 'var(--sev-critical)' 
                            }} />
                            <span>Execution: <b>{res.summary}</b></span>
                          </div>
                          {res.findings_count !== undefined && (
                            <span style={{ 
                              padding: '2px 8px', 
                              borderRadius: '4px',
                              background: res.findings_count > 0 ? 'rgba(255, 42, 95, 0.2)' : 'rgba(255, 255, 255, 0.05)',
                              color: res.findings_count > 0 ? 'var(--sev-critical)' : 'var(--text-muted)',
                              fontWeight: '700'
                            }}>
                              {res.findings_count} findings
                            </span>
                          )}
                        </div>
                      )}

                      {/* Accordion Expand for raw details */}
                      {isExpanded && (
                        <div style={{ 
                          marginTop: '10px', 
                          padding: '10px', 
                          background: 'rgba(0, 0, 0, 0.4)', 
                          borderRadius: '6px',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.75rem',
                          color: 'var(--cyber-cyan)'
                        }}>
                          <div style={{ color: 'var(--text-muted)', marginBottom: '4px' }}>Parameters & Telemetry:</div>
                          <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                            {JSON.stringify({ 
                              action: decision.action,
                              tool_name: decision.chosen_tool,
                              tool_args: decision.tool_args,
                              execution_result: decision.tool_execution_result,
                              tokens: { prompt: decision.prompt_tokens, completion: decision.completion_tokens }
                            }, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          )}

          {/* Tab Content: Raw Terminal Telemetry */}
          {activeTab === 'terminal' && (
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
          )}
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
