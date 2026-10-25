import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import NewScanModal from './components/NewScanModal';
import DashboardView from './views/DashboardView';
import ScansListView from './views/ScansListView';
import ScanMonitorView from './views/ScanMonitorView';
import FindingsView from './views/FindingsView';
import DefensiveView from './views/DefensiveView';
import ToolsView from './views/ToolsView';
import SystemView from './views/SystemView';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [scans, setScans] = useState([]);
  const [tools, setTools] = useState([]);
  const [systemStatus, setSystemStatus] = useState(null);
  const [selectedJobId, setSelectedJobId] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Fetch all core datasets
  const fetchScans = async () => {
    try {
      const resp = await fetch('/api/scans');
      if (resp.ok) {
        const data = await resp.json();
        setScans(data);
      }
    } catch (err) {
      console.error('Failed to load scans:', err);
    }
  };

  const fetchTools = async () => {
    try {
      const resp = await fetch('/api/tools');
      if (resp.ok) {
        const data = await resp.json();
        setTools(data);
      }
    } catch (err) {
      console.error('Failed to load tools:', err);
    }
  };

  const fetchSystem = async () => {
    try {
      const resp = await fetch('/api/system/health');
      if (resp.ok) {
        const data = await resp.json();
        setSystemStatus(data);
      }
    } catch (err) {
      console.error('Failed to load system health:', err);
    }
  };

  useEffect(() => {
    fetchScans();
    fetchTools();
    fetchSystem();

    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleSelectScan = (jobId) => {
    setSelectedJobId(jobId);
    setActiveTab('scan-monitor');
  };

  const handleViewFindings = (jobId) => {
    setSelectedJobId(jobId);
    setActiveTab('findings');
  };

  const handleViewDefensive = (jobId) => {
    setSelectedJobId(jobId);
    setActiveTab('defensive');
  };

  const handleScanCreated = (newJobId) => {
    fetchScans();
    setSelectedJobId(newJobId);
    setActiveTab('scan-monitor');
  };

  return (
    <div className="app-container">
      <Sidebar 
        activeTab={activeTab === 'scan-monitor' ? 'scans' : activeTab} 
        setActiveTab={(tab) => {
          if (tab === 'scans') setSelectedJobId(null);
          setActiveTab(tab);
        }}
        systemStatus={systemStatus}
      />

      <main className="main-content">
        {activeTab === 'dashboard' && (
          <DashboardView
            scans={scans}
            tools={tools}
            onOpenNewScan={() => setIsModalOpen(true)}
            onSelectScan={handleSelectScan}
            onNavigate={setActiveTab}
          />
        )}

        {activeTab === 'scans' && (
          <ScansListView
            scans={scans}
            onSelectScan={handleSelectScan}
            onOpenNewScan={() => setIsModalOpen(true)}
            onRefreshScans={fetchScans}
          />
        )}

        {activeTab === 'scan-monitor' && selectedJobId && (
          <ScanMonitorView
            jobId={selectedJobId}
            onBack={() => setActiveTab('scans')}
            onViewFindings={handleViewFindings}
            onViewDefensive={handleViewDefensive}
          />
        )}

        {activeTab === 'findings' && (
          <FindingsView
            activeJobId={selectedJobId}
            onSelectJob={(jid) => setSelectedJobId(jid)}
          />
        )}

        {activeTab === 'defensive' && (
          <DefensiveView
            activeJobId={selectedJobId}
            onSelectJob={(jid) => setSelectedJobId(jid)}
          />
        )}

        {activeTab === 'tools' && (
          <ToolsView
            tools={tools}
            onRefreshTools={fetchTools}
          />
        )}

        {activeTab === 'system' && (
          <SystemView />
        )}
      </main>

      <NewScanModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onScanCreated={handleScanCreated}
      />
    </div>
  );
}
