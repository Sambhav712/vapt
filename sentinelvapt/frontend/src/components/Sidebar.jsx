import React from 'react';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  Scan, 
  Bug, 
  ShieldCheck, 
  Wrench, 
  Cpu, 
  Terminal 
} from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, systemStatus }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scans', label: 'Active Scans', icon: Scan },
    { id: 'findings', label: 'Findings Explorer', icon: Bug },
    { id: 'defensive', label: 'Purple Team Rules', icon: ShieldCheck },
    { id: 'tools', label: 'Tool Ecosystem', icon: Wrench },
    { id: 'system', label: 'Diagnostics', icon: Cpu },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="logo-badge">
          <ShieldAlert size={22} color="#060911" />
        </div>
        <div className="logo-text">
          <div className="logo-title">SENTINEL<span>VAPT</span></div>
          <div className="logo-sub">Autonomous AI Security</div>
        </div>
      </div>

      <div className="nav-section">
        <div className="nav-label">Navigation</div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              className={`nav-item ${isActive ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>

      <div className="sidebar-footer">
        <div className="status-pill">
          <span className="status-dot"></span>
          <span>SYSTEM {systemStatus?.status ? systemStatus.status.toUpperCase() : 'ONLINE'}</span>
        </div>
        <div style={{ 
          fontSize: '0.72rem', 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          marginTop: '4px' 
        }}>
          <span style={{ color: 'var(--text-muted)' }}>MODE:</span>
          <span style={{ 
            color: (systemStatus?.privilege?.level === 'root' || systemStatus?.privilege?.is_admin) 
              ? 'var(--cyber-emerald)' 
              : 'var(--sev-high)',
            fontWeight: '700',
            textTransform: 'uppercase'
          }}>
            {systemStatus?.privilege?.level ? `${systemStatus.privilege.level.toUpperCase()} ACCESS` : 'USER ACCESS'}
          </span>
        </div>
        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>
          LLM: <span style={{ color: 'var(--cyber-cyan)' }}>{systemStatus?.llm_provider || 'Groq'}</span>
        </div>
      </div>
    </aside>
  );
}
