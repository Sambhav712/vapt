import React, { useState, useEffect, useRef } from 'react';
import {
  Terminal,
  Play,
  Square,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Cpu,
  Layers,
  Bug,
  Shield,
  RefreshCw,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Sparkles,
  Zap
} from 'lucide-react';

export default function AgentView() {
  const [sessions, setSessions] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState(null);
  const [currentSession, setCurrentSession] = useState(null);
  const [steps, setSteps] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [isLaunching, setIsLaunching] = useState(false);
  const [activeTab, setActiveTab] = useState('terminal'); // 'terminal', 'findings', 'audit'

  // Form states for launching a new agent
  const [target, setTarget] = useState('');
  const [scopeType, setScopeType] = useState('single_target');
  const [goal, setGoal] = useState('Conduct an autonomous vulnerability assessment and identify open attack surfaces, services, and security flaws.');
  const [maxIterations, setMaxIterations] = useState(20);
  const [safeMode, setSafeMode] = useState(true);
  const [allowTier3, setAllowTier3] = useState(false);
  const [showLaunchModal, setShowLaunchModal] = useState(false);

  const eventSourceRef = useRef(null);
  const terminalBottomRef = useRef(null);

  // Fetch all sessions & global agent stats
  const fetchSessions = async () => {
    try {
      const res = await fetch('/api/agent/sessions');
      if (res.ok) {
        const data = await res.json();
        setSessions(data);
        if (!selectedSessionId && data.length > 0) {
          setSelectedSessionId(data[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to fetch agent sessions:', err);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/agent/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Failed to fetch agent stats:', err);
    }
  };

  // Fetch specific session details and its step history
  const fetchSessionDetails = async (sessionId) => {
    if (!sessionId) return;
    try {
      const [sessRes, stepsRes] = await Promise.all([
        fetch(`/api/agent/sessions/${sessionId}`),
        fetch(`/api/agent/sessions/${sessionId}/steps?limit=100`)
      ]);
      if (sessRes.ok) {
        const sessData = await sessRes.json();
        setCurrentSession(sessData);
      }
      if (stepsRes.ok) {
        const stepsData = await stepsRes.json();
        setSteps(stepsData);
      }
    } catch (err) {
      console.error('Failed to load session details:', err);
    }
  };

  useEffect(() => {
    fetchSessions();
    fetchStats();
    const interval = setInterval(() => {
      fetchSessions();
      fetchStats();
    }, 6000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (selectedSessionId) {
      fetchSessionDetails(selectedSessionId);
      setupEventStream(selectedSessionId);
    }
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, [selectedSessionId]);

  // Setup Server-Sent Events (SSE) for live agent stream
  const setupEventStream = (sessionId) => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    try {
      const es = new EventSource(`/api/agent/sessions/${sessionId}/stream`);
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === 'step') {
            setSteps((prev) => [...prev, payload.data]);
            setCurrentSession((prev) => prev ? { ...prev, current_iteration: payload.data.iteration } : prev);
          } else if (payload.type === 'session_status') {
            setCurrentSession((prev) => prev ? { ...prev, status: payload.status } : prev);
            fetchSessions();
          } else if (payload.type === 'finding') {
            fetchSessionDetails(sessionId);
          }
        } catch (e) {
          console.error('Error parsing SSE event:', e);
        }
      };

      es.onerror = () => {
        es.close();
      };
    } catch (e) {
      console.error('Failed to setup SSE:', e);
    }
  };

  // Scroll to bottom on new steps
  useEffect(() => {
    if (terminalBottomRef.current) {
      terminalBottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [steps]);

  // Handle agent launch
  const handleLaunch = async (e) => {
    e.preventDefault();
    if (!target) return;
    setIsLaunching(true);

    try {
      const res = await fetch('/api/agent/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: target.trim(),
          scope_type: scopeType,
          goal: goal.trim(),
          max_iterations: parseInt(maxIterations, 10),
          safe_mode: safeMode,
          allow_tier3: allowTier3
        })
      });

      if (res.ok) {
        const data = await res.json();
        setShowLaunchModal(false);
        setTarget('');
        await fetchSessions();
        setSelectedSessionId(data.session_id);
      } else {
        const err = await res.json();
        alert(`Launch failed: ${err.detail || 'Unknown error'}`);
      }
    } catch (err) {
      console.error('Launch request error:', err);
      alert('Network error launching agent.');
    } finally {
      setIsLaunching(false);
    }
  };

  // Handle agent cancellation
  const handleCancel = async () => {
    if (!selectedSessionId) return;
    if (!window.confirm('Are you sure you want to abort this autonomous agent session?')) return;
    try {
      const res = await fetch(`/api/agent/sessions/${selectedSessionId}/cancel`, {
        method: 'POST'
      });
      if (res.ok) {
        fetchSessionDetails(selectedSessionId);
        fetchSessions();
      }
    } catch (err) {
      console.error('Failed to cancel session:', err);
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'running':
        return (
          <span className="badge badge-running" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
            <span className="status-dot"></span> RUNNING
          </span>
        );
      case 'completed':
        return (
          <span className="badge badge-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
            <CheckCircle2 size={13} /> COMPLETED
          </span>
        );
      case 'failed':
        return (
          <span className="badge badge-danger" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
            <XCircle size={13} /> FAILED
          </span>
        );
      case 'cancelled':
        return (
          <span className="badge badge-warning" style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
            <AlertTriangle size={13} /> CANCELLED
          </span>
        );
      default:
        return <span className="badge badge-info">{status?.toUpperCase() || 'UNKNOWN'}</span>;
    }
  };

  return (
    <div className="view-container">
      {/* Top Banner / Stats Header */}
      <div className="view-header" style={{ marginBottom: '1.25rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.25), rgba(0, 242, 254, 0.25))',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              border: '1px solid rgba(168, 85, 247, 0.4)'
            }}>
              <Terminal size={20} color="var(--cyber-cyan)" />
            </div>
            <div>
              <h1 style={{ fontSize: '1.5rem', fontWeight: '800', letterSpacing: '-0.02em', margin: 0 }}>
                Autonomous <span style={{ color: 'var(--cyber-cyan)' }}>Terminal Agent</span>
              </h1>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', margin: 0 }}>
                Goal-oriented ReAct reasoning loop (Think &rarr; Act &rarr; Observe) driving Kali Linux command execution.
              </p>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button 
            className="btn btn-secondary" 
            onClick={() => { fetchSessions(); fetchStats(); if (selectedSessionId) fetchSessionDetails(selectedSessionId); }}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
          <button 
            className="btn btn-primary"
            onClick={() => setShowLaunchModal(true)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              background: 'linear-gradient(135deg, #7928ca 0%, #00f2fe 100%)',
              border: 'none',
              fontWeight: '700'
            }}
          >
            <Play size={15} fill="currentColor" /> Launch Agent
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '1rem',
        marginBottom: '1.5rem'
      }}>
        <div className="card" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ padding: '10px', borderRadius: '8px', background: 'rgba(0, 242, 254, 0.1)', color: 'var(--cyber-cyan)' }}>
            <Cpu size={22} />
          </div>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: '600' }}>Active Sessions</div>
            <div style={{ fontSize: '1.4rem', fontWeight: '800' }}>{stats?.active_sessions ?? 0}</div>
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ padding: '10px', borderRadius: '8px', background: 'rgba(16, 185, 129, 0.1)', color: 'var(--cyber-emerald)' }}>
            <Layers size={22} />
          </div>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: '600' }}>Total Steps Run</div>
            <div style={{ fontSize: '1.4rem', fontWeight: '800' }}>{stats?.total_steps_executed ?? 0}</div>
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ padding: '10px', borderRadius: '8px', background: 'rgba(244, 63, 94, 0.1)', color: 'var(--sev-critical)' }}>
            <Bug size={22} />
          </div>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: '600' }}>Verified Findings</div>
            <div style={{ fontSize: '1.4rem', fontWeight: '800' }}>{stats?.total_findings_discovered ?? 0}</div>
          </div>
        </div>

        <div className="card" style={{ padding: '1rem', display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ padding: '10px', borderRadius: '8px', background: 'rgba(168, 85, 247, 0.1)', color: 'var(--cyber-purple)' }}>
            <Shield size={22} />
          </div>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: '600' }}>LLM Architecture</div>
            <div style={{ fontSize: '0.95rem', fontWeight: '700', color: 'var(--cyber-cyan)' }}>
              {stats?.llm_primary || 'Groq Llama-3.3'}
            </div>
          </div>
        </div>
      </div>

      {/* Main Agent Interface Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '1.25rem', minHeight: '620px' }}>
        {/* Left Column: Sessions List */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{
            padding: '0.85rem 1rem',
            borderBottom: '1px solid var(--border-subtle)',
            background: 'rgba(10, 15, 29, 0.5)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center'
          }}>
            <span style={{ fontSize: '0.85rem', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Agent Sessions ({sessions.length})
            </span>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', padding: '0.5rem' }}>
            {sessions.length === 0 ? (
              <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                No agent sessions yet. Click "Launch Agent" to begin an autonomous run.
              </div>
            ) : (
              sessions.map((sess) => {
                const isSelected = sess.id === selectedSessionId;
                return (
                  <div
                    key={sess.id}
                    onClick={() => setSelectedSessionId(sess.id)}
                    style={{
                      padding: '0.75rem',
                      borderRadius: '6px',
                      marginBottom: '0.4rem',
                      cursor: 'pointer',
                      background: isSelected ? 'rgba(0, 242, 254, 0.08)' : 'rgba(17, 25, 45, 0.4)',
                      border: isSelected ? '1px solid var(--cyber-cyan)' : '1px solid var(--border-subtle)',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span style={{ fontWeight: '700', fontSize: '0.9rem', color: isSelected ? 'var(--cyber-cyan)' : 'var(--text-primary)' }}>
                        {sess.target}
                      </span>
                      {getStatusBadge(sess.status)}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '6px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {sess.goal || 'No goal set'}
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                      <span>Iter: {sess.current_iteration}/{sess.max_iterations}</span>
                      <span>{new Date(sess.created_at).toLocaleTimeString()}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Active Session Console */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {currentSession ? (
            <>
              {/* Session Top Bar */}
              <div style={{
                padding: '0.85rem 1.25rem',
                borderBottom: '1px solid var(--border-subtle)',
                background: 'rgba(10, 15, 29, 0.7)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '10px'
              }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '1.1rem', fontWeight: '800' }}>{currentSession.target}</span>
                    {getStatusBadge(currentSession.status)}
                    <span className="badge" style={{ background: 'rgba(255,255,255,0.06)', fontSize: '0.75rem' }}>
                      Scope: {currentSession.scope_type}
                    </span>
                    {currentSession.allow_tier3 && (
                      <span className="badge badge-warning" style={{ fontSize: '0.72rem' }}>
                        TIER 3 EXPLOIT AUTHORIZED
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                    <strong>Goal:</strong> {currentSession.goal}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  {currentSession.status === 'running' && (
                    <button
                      className="btn btn-danger"
                      onClick={handleCancel}
                      style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
                    >
                      <Square size={13} fill="currentColor" /> Abort Agent
                    </button>
                  )}
                  <div style={{
                    display: 'flex',
                    background: 'rgba(0,0,0,0.3)',
                    borderRadius: '6px',
                    padding: '2px',
                    border: '1px solid var(--border-subtle)'
                  }}>
                    <button
                      onClick={() => setActiveTab('terminal')}
                      style={{
                        background: activeTab === 'terminal' ? 'var(--cyber-cyan)' : 'transparent',
                        color: activeTab === 'terminal' ? '#060911' : 'var(--text-muted)',
                        border: 'none',
                        padding: '4px 10px',
                        borderRadius: '4px',
                        fontSize: '0.78rem',
                        fontWeight: '700',
                        cursor: 'pointer'
                      }}
                    >
                      ReAct Stream ({steps.length})
                    </button>
                    <button
                      onClick={() => setActiveTab('findings')}
                      style={{
                        background: activeTab === 'findings' ? 'var(--cyber-cyan)' : 'transparent',
                        color: activeTab === 'findings' ? '#060911' : 'var(--text-muted)',
                        border: 'none',
                        padding: '4px 10px',
                        borderRadius: '4px',
                        fontSize: '0.78rem',
                        fontWeight: '700',
                        cursor: 'pointer'
                      }}
                    >
                      Findings ({currentSession.findings?.length || 0})
                    </button>
                  </div>
                </div>
              </div>

              {/* Console Body */}
              <div style={{ flex: 1, overflowY: 'auto', padding: '1rem', background: '#060911' }}>
                {activeTab === 'terminal' ? (
                  <div>
                    {steps.length === 0 ? (
                      <div style={{ textAlign: 'center', padding: '4rem 1rem', color: 'var(--text-muted)' }}>
                        <Terminal size={32} style={{ margin: '0 auto 10px', opacity: 0.4 }} />
                        <p>Initializing autonomous agent execution loop...</p>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                          Listening for ReAct actions and terminal stdout/stderr stream...
                        </span>
                      </div>
                    ) : (
                      steps.map((st, idx) => (
                        <div
                          key={st.id || idx}
                          style={{
                            marginBottom: '1.25rem',
                            borderRadius: '8px',
                            border: '1px solid var(--border-subtle)',
                            background: 'rgba(15, 23, 42, 0.7)',
                            overflow: 'hidden'
                          }}
                        >
                          {/* Step Header */}
                          <div style={{
                            padding: '0.6rem 0.9rem',
                            background: 'rgba(10, 15, 29, 0.9)',
                            borderBottom: '1px solid var(--border-subtle)',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            fontSize: '0.8rem'
                          }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span style={{
                                background: 'rgba(0, 242, 254, 0.15)',
                                color: 'var(--cyber-cyan)',
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontWeight: '800'
                              }}>
                                STEP {st.iteration}
                              </span>
                              <span style={{
                                fontWeight: '700',
                                color: st.action_type === 'FINISH' ? 'var(--cyber-emerald)' : 'var(--text-primary)'
                              }}>
                                {st.action_type}
                              </span>
                            </div>
                            <span style={{ color: 'var(--text-dim)', fontSize: '0.72rem' }}>
                              {st.created_at ? new Date(st.created_at).toLocaleTimeString() : ''}
                            </span>
                          </div>

                          {/* Step Content: Thought / Reasoning */}
                          {st.thought && (
                            <div style={{
                              padding: '0.75rem 0.9rem',
                              borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                              background: 'rgba(168, 85, 247, 0.04)',
                              fontSize: '0.85rem'
                            }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '5px', color: 'var(--cyber-purple)', fontWeight: '700', marginBottom: '4px', fontSize: '0.75rem' }}>
                                <Sparkles size={14} /> AI REASONING & HYPOTHESIS
                              </div>
                              <div style={{ color: 'var(--text-secondary)', lineHeight: '1.45', whiteSpace: 'pre-wrap' }}>
                                {st.thought}
                              </div>
                            </div>
                          )}

                          {/* Step Command Action */}
                          {st.command && (
                            <div style={{
                              padding: '0.6rem 0.9rem',
                              background: 'rgba(0, 0, 0, 0.5)',
                              borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.82rem',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '8px'
                            }}>
                              <span style={{ color: 'var(--cyber-emerald)', fontWeight: '700' }}>kali@sentinel:~$</span>
                              <span style={{ color: '#f8fafc', wordBreak: 'break-all' }}>{st.command}</span>
                              {st.exit_code !== undefined && (
                                <span style={{
                                  marginLeft: 'auto',
                                  fontSize: '0.7rem',
                                  padding: '1px 6px',
                                  borderRadius: '3px',
                                  background: st.exit_code === 0 ? 'rgba(16, 185, 129, 0.2)' : 'rgba(244, 63, 94, 0.2)',
                                  color: st.exit_code === 0 ? 'var(--cyber-emerald)' : 'var(--sev-critical)'
                                }}>
                                  exit: {st.exit_code}
                                </span>
                              )}
                            </div>
                          )}

                          {/* Step Observation / Terminal Output */}
                          {st.observation && (
                            <div style={{
                              padding: '0.75rem 0.9rem',
                              background: '#040711',
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.78rem',
                              maxHeight: '260px',
                              overflowY: 'auto',
                              color: '#94a3b8',
                              whiteSpace: 'pre-wrap',
                              lineHeight: '1.4'
                            }}>
                              {st.observation}
                            </div>
                          )}
                        </div>
                      ))
                    )}
                    <div ref={terminalBottomRef} />
                  </div>
                ) : (
                  <div>
                    {(!currentSession.findings || currentSession.findings.length === 0) ? (
                      <div style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)' }}>
                        <Bug size={32} style={{ margin: '0 auto 10px', opacity: 0.4 }} />
                        <p>No verified security findings reported yet for this session.</p>
                      </div>
                    ) : (
                      currentSession.findings.map((f, i) => (
                        <div key={i} className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <span className={`badge badge-${f.severity?.toLowerCase() || 'medium'}`}>
                                {f.severity?.toUpperCase() || 'MEDIUM'}
                              </span>
                              <span style={{ fontWeight: '700', fontSize: '1rem' }}>{f.title}</span>
                            </div>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                              CWE: {f.cwe_id || 'N/A'}
                            </span>
                          </div>
                          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                            {f.description}
                          </p>
                          {f.proof_of_concept && (
                            <div style={{
                              background: 'rgba(0,0,0,0.5)',
                              padding: '0.5rem 0.75rem',
                              borderRadius: '4px',
                              fontFamily: 'var(--font-mono)',
                              fontSize: '0.75rem',
                              color: 'var(--cyber-cyan)'
                            }}>
                              Proof: {f.proof_of_concept}
                            </div>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)' }}>
              <Terminal size={48} style={{ opacity: 0.3, marginBottom: '1rem' }} />
              <div style={{ fontSize: '1.1rem', fontWeight: '700', color: 'var(--text-primary)', marginBottom: '6px' }}>
                No Session Selected
              </div>
              <p style={{ fontSize: '0.85rem', maxWidth: '360px', textAlign: 'center', marginBottom: '1.25rem' }}>
                Select an existing agent session on the left or launch a new autonomous terminal scan.
              </p>
              <button
                className="btn btn-primary"
                onClick={() => setShowLaunchModal(true)}
                style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                <Play size={14} fill="currentColor" /> Launch Agent Now
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Launch Agent Modal */}
      {showLaunchModal && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(6px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1rem'
        }}>
          <div className="card" style={{
            maxWidth: '560px',
            width: '100%',
            padding: '1.5rem',
            border: '1px solid rgba(0, 242, 254, 0.3)',
            boxShadow: 'var(--glow-shadow)'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Terminal size={20} color="var(--cyber-cyan)" />
                <h3 style={{ margin: 0, fontSize: '1.15rem', fontWeight: '800' }}>Launch Autonomous Kali Agent</h3>
              </div>
              <button
                onClick={() => setShowLaunchModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1.2rem' }}
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleLaunch}>
              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: '700', marginBottom: '4px' }}>
                  Target IP / Hostname / URL *
                </label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1.105 or scanme.nmap.org"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  required
                  style={{
                    width: '100%',
                    padding: '0.6rem 0.8rem',
                    borderRadius: '6px',
                    background: 'rgba(10, 15, 29, 0.8)',
                    border: '1px solid var(--border-medium)',
                    color: '#fff',
                    fontFamily: 'var(--font-mono)'
                  }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: '700', marginBottom: '4px' }}>
                    Scope Type
                  </label>
                  <select
                    value={scopeType}
                    onChange={(e) => setScopeType(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.6rem 0.8rem',
                      borderRadius: '6px',
                      background: 'rgba(10, 15, 29, 0.8)',
                      border: '1px solid var(--border-medium)',
                      color: '#fff'
                    }}
                  >
                    <option value="single_target">Single Target (Strict)</option>
                    <option value="cidr">CIDR Subnet</option>
                    <option value="web_app">Web Application</option>
                    <option value="internal_network">Internal Network</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: '700', marginBottom: '4px' }}>
                    Max ReAct Iterations ({maxIterations})
                  </label>
                  <input
                    type="range"
                    min="5"
                    max="40"
                    step="1"
                    value={maxIterations}
                    onChange={(e) => setMaxIterations(e.target.value)}
                    style={{ width: '100%', marginTop: '8px' }}
                  />
                </div>
              </div>

              <div style={{ marginBottom: '1rem' }}>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: '700', marginBottom: '4px' }}>
                  Agent Mission Goal
                </label>
                <textarea
                  rows="3"
                  value={goal}
                  onChange={(e) => setGoal(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.6rem 0.8rem',
                    borderRadius: '6px',
                    background: 'rgba(10, 15, 29, 0.8)',
                    border: '1px solid var(--border-medium)',
                    color: '#fff',
                    fontSize: '0.82rem'
                  }}
                />
              </div>

              {/* Guardrails Options */}
              <div style={{
                padding: '0.85rem',
                borderRadius: '6px',
                background: 'rgba(0, 0, 0, 0.3)',
                border: '1px solid var(--border-subtle)',
                marginBottom: '1.25rem'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: '700' }}>Terminal Safety Guardrails</div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Blocks destructive system commands and out-of-scope targets</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={safeMode}
                    onChange={(e) => setSafeMode(e.target.checked)}
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '8px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                  <div>
                    <div style={{ fontSize: '0.82rem', fontWeight: '700', color: allowTier3 ? 'var(--sev-high)' : 'var(--text-primary)' }}>
                      Authorize Tier 3 Exploits
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Allow msfconsole, hydra, sqlmap injection with active verification</div>
                  </div>
                  <input
                    type="checkbox"
                    checked={allowTier3}
                    onChange={(e) => setAllowTier3(e.target.checked)}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowLaunchModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isLaunching || !target}
                  className="btn btn-primary"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: 'linear-gradient(135deg, #7928ca 0%, #00f2fe 100%)',
                    border: 'none',
                    fontWeight: '700'
                  }}
                >
                  {isLaunching ? <RefreshCw className="spin" size={15} /> : <Zap size={15} />}
                  Start Autonomous Agent
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
