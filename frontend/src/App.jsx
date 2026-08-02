import React, { useState, useEffect } from 'react';
import { ShieldAlert, Activity, AlertTriangle, Terminal, Search, Filter, Server, Shield } from 'lucide-react';
import './index.css';

// Mock data to simulate API responses for the initial PoC
const MOCK_ALERTS = [
  { id: 1, rule: 'Suspicious Python Script Execution', pid: 4892, score: 35, time: '14:23:45', severity: 'critical', mitre: 'T1059.006' },
  { id: 2, rule: 'Interactive Shell Spawned from Web Server', pid: 4893, score: 50, time: '14:23:46', severity: 'critical', mitre: 'T1505.003' },
  { id: 3, rule: 'Sensitive File Access (Shadow)', pid: 1042, score: 15, time: '14:15:10', severity: 'high', mitre: 'T1003.008' }
];

const MOCK_TELEMETRY = [
  { id: 1, type: 'EXEC', pid: 4892, ppid: 4010, cmd: 'python3 -c "import pty; pty.spawn(\'/bin/sh\')"' },
  { id: 2, type: 'FORK', pid: 4893, ppid: 4892, cmd: '/bin/sh' },
  { id: 3, type: 'CONNECT', pid: 4893, ppid: 4892, cmd: '192.168.1.50:4444' },
  { id: 4, type: 'READ', pid: 1042, ppid: 1, cmd: '/etc/shadow' }
];

function App() {
  const [alerts, setAlerts] = useState(MOCK_ALERTS);
  const [telemetry, setTelemetry] = useState(MOCK_TELEMETRY);
  const [activeTab, setActiveTab] = useState('alerts');

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', height: '100vh', overflow: 'hidden' }}>
      
      {/* Left Sidebar: Active Threat Queue */}
      <aside className="soc-panel" style={{ borderRight: '1px solid var(--border-subtle)', borderRadius: 0, display: 'flex', flexDirection: 'column', padding: 0 }}>
        
        <div style={{ padding: '16px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <ShieldAlert size={24} color="var(--threat-critical)" />
          <div>
            <h1 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>Spectre EDR</h1>
            <div className="mono-data" style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>v0.2.0-alpha</div>
          </div>
        </div>

        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-secondary)', fontWeight: 600 }}>Threat Queue</span>
          <span className="badge badge-critical">{alerts.length} Active</span>
        </div>

        <div style={{ overflowY: 'auto', flex: 1, padding: '8px' }}>
          {alerts.map(alert => (
            <div key={alert.id} className="soc-panel" style={{ marginBottom: '8px', cursor: 'pointer', borderColor: alert.severity === 'critical' ? 'rgba(229, 57, 53, 0.3)' : 'var(--border-subtle)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span className={`badge badge-${alert.severity}`}>{alert.severity}</span>
                <span className="mono-data" style={{ color: 'var(--text-secondary)' }}>{alert.time}</span>
              </div>
              <div style={{ fontWeight: 500, fontSize: '0.9rem', marginBottom: '8px', lineHeight: 1.4 }}>
                {alert.rule}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="mono-data mono-blue">PID: {alert.pid}</span>
                <span className="badge badge-info">{alert.mitre}</span>
              </div>
            </div>
          ))}
        </div>
        
        <div style={{ padding: '12px', borderTop: '1px solid var(--border-subtle)', fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Activity size={14} color="var(--threat-success)" />
          Netlink Sensor: Connected
        </div>
      </aside>

      {/* Main Content Area */}
      <main style={{ display: 'flex', flexDirection: 'column', height: '100vh', backgroundColor: 'var(--bg-app)' }}>
        
        {/* Top Navbar */}
        <header style={{ height: '60px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', padding: '0 24px', gap: '16px' }}>
          <button className="btn" style={{ borderColor: activeTab === 'alerts' ? 'var(--threat-info)' : '' }} onClick={() => setActiveTab('alerts')}>
            <AlertTriangle size={16} /> Incident Response
          </button>
          <button className="btn" style={{ borderColor: activeTab === 'telemetry' ? 'var(--threat-info)' : '' }} onClick={() => setActiveTab('telemetry')}>
            <Terminal size={16} /> Raw Telemetry
          </button>
          <div style={{ flex: 1 }}></div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
            <Server size={16} /> localhost
          </div>
        </header>

        {/* Dynamic Content */}
        <div style={{ flex: 1, padding: '24px', overflowY: 'auto' }}>
          
          {activeTab === 'alerts' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <div className="soc-panel" style={{ padding: '24px' }}>
                <h2 style={{ margin: '0 0 16px 0', fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Shield size={20} color="var(--threat-info)" />
                  Process Lineage Analysis
                </h2>
                
                <div className="soc-panel" style={{ backgroundColor: '#000', fontFamily: 'var(--font-mono)', padding: '16px', fontSize: '0.9rem', lineHeight: 1.6 }}>
                  <div style={{ color: 'var(--text-secondary)' }}># Tracing execution chain for PID 4893</div>
                  <div>
                    <span className="mono-blue">root</span> nginx <span style={{ color: 'var(--text-secondary)' }}>(PID: 4010)</span>
                  </div>
                  <div>
                    └─ <span className="mono-blue">www-data</span> bash <span style={{ color: 'var(--text-secondary)' }}>(PID: 4892)</span> <span style={{ color: 'var(--threat-high)' }}>[T1059.004]</span>
                  </div>
                  <div>
                    &nbsp;&nbsp;&nbsp;├─ <span className="mono-green">READ</span> /etc/passwd
                  </div>
                  <div>
                    &nbsp;&nbsp;&nbsp;└─ <span className="mono-blue">www-data</span> python3 <span style={{ color: 'var(--text-secondary)' }}>(PID: 4893)</span> <span className="badge badge-critical">SCORE: 50</span>
                  </div>
                  <div>
                    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;└─ <span className="mono-orange">CONNECT</span> 192.168.1.50:4444 <span style={{ color: 'var(--text-secondary)' }}>(Reverse Shell)</span>
                  </div>
                </div>
                
                <div style={{ marginTop: '16px', display: 'flex', gap: '12px' }}>
                  <button className="btn" style={{ backgroundColor: 'rgba(229, 57, 53, 0.1)', color: 'var(--threat-critical)', borderColor: 'var(--threat-critical)' }}>
                    Mitigate (SIGKILL)
                  </button>
                  <button className="btn" style={{ backgroundColor: 'rgba(251, 140, 0, 0.1)', color: 'var(--threat-high)', borderColor: 'var(--threat-high)' }}>
                    Freeze (SIGSTOP)
                  </button>
                  <button className="btn">Ignore Chain</button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'telemetry' && (
            <div className="soc-panel" style={{ padding: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column', height: '100%' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', gap: '12px' }}>
                <div style={{ position: 'relative', flex: 1 }}>
                  <Search size={14} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-secondary)' }} />
                  <input 
                    type="text" 
                    placeholder="Filter by PID, path, or IP..." 
                    style={{ width: '100%', backgroundColor: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: '4px', padding: '8px 8px 8px 32px', color: 'var(--text-primary)', fontFamily: 'var(--font-ui)' }}
                  />
                </div>
                <button className="btn"><Filter size={16} /> Filters</button>
              </div>
              
              <div className="table-header table-row">
                <div>Type</div>
                <div>Target / Cmd</div>
                <div>PID</div>
                <div>Parent PID</div>
              </div>
              
              <div style={{ overflowY: 'auto', flex: 1 }}>
                {telemetry.map(t => (
                  <div key={t.id} className="table-row mono-data" style={{ fontSize: '0.8rem' }}>
                    <div style={{ 
                      color: t.type === 'EXEC' || t.type === 'FORK' ? 'var(--threat-info)' : 
                             t.type === 'READ' ? '#A5D6A7' : 
                             t.type === 'CONNECT' ? '#FFCC80' : 'var(--text-primary)',
                      fontWeight: 600
                    }}>{t.type}</div>
                    <div style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.cmd}</div>
                    <div>{t.pid}</div>
                    <div style={{ color: 'var(--text-secondary)' }}>{t.ppid}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      </main>
    </div>
  );
}

export default App;
