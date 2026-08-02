import React, { useState, useEffect } from 'react';
import { ShieldAlert, Activity, AlertTriangle, Terminal, Search, Filter, Server, Shield } from 'lucide-react';
import './index.css';

function App() {
  const [sessions, setSessions] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [telemetry, setTelemetry] = useState([]);
  const [stats, setStats] = useState({ total_events: 0, total_sessions: 0, total_alerts: 0 });
  const [activeTab, setActiveTab] = useState('alerts');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, sessionsRes, alertsRes, eventsRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/sessions?limit=20'),
          fetch('/api/alerts?limit=10'),
          fetch('/api/events?limit=50')
        ]);
        
        if (!statsRes.ok) throw new Error('API down');
        
        const statsData = await statsRes.json();
        const sessionsData = await sessionsRes.json();
        const alertsData = await alertsRes.json();
        const eventsData = await eventsRes.json();
        
        setStats(statsData);
        setSessions(sessionsData.sessions || []);
        setAlerts(alertsData.alerts || []);
        setTelemetry(eventsData.events || []);
        setError(false);
      } catch (err) {
        console.error(err);
        setError(true);
      } finally {
        setLoading(false);
      }
    };
    
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

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
          <span className="badge badge-critical">{sessions.length} Active</span>
        </div>

        <div style={{ overflowY: 'auto', flex: 1, padding: '8px' }}>
          {sessions.map(s => {
            const severity = s.total_score >= 15 ? 'critical' : 'high';
            const date = new Date(s.last_updated * 1000);
            return (
              <div key={s.id} className="soc-panel" style={{ marginBottom: '8px', cursor: 'pointer', borderColor: severity === 'critical' ? 'rgba(229, 57, 53, 0.3)' : 'var(--border-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <span className={`badge badge-${severity}`}>{severity}</span>
                  <span className="mono-data" style={{ color: 'var(--text-secondary)' }}>{date.toLocaleTimeString()}</span>
                </div>
                <div style={{ fontWeight: 500, fontSize: '0.9rem', marginBottom: '8px', lineHeight: 1.4 }}>
                  {s.leader_name}
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="mono-data mono-blue">PID: {s.leader_pid}</span>
                  <span className="badge badge-info">SCORE: {s.total_score}</span>
                </div>
              </div>
            );
          })}
          
          {sessions.length === 0 && !loading && (
            <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              No active threat sessions.
            </div>
          )}
        </div>
        
        <div style={{ padding: '12px', borderTop: '1px solid var(--border-subtle)', fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          {error ? (
            <><Activity size={14} color="var(--threat-critical)" /> API Disconnected</>
          ) : (
            <><Activity size={14} color="var(--threat-success)" /> System Online (Events: {stats.total_events})</>
          )}
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
              {alerts.length === 0 ? (
                <div className="soc-panel" style={{ padding: '48px', textAlign: 'center', color: 'var(--text-secondary)' }}>
                  <Shield size={48} style={{ opacity: 0.2, margin: '0 auto 16px auto' }} />
                  <h3>No Critical Alerts Detected</h3>
                  <p>The system is monitoring process execution and resource access.</p>
                </div>
              ) : alerts.map(alert => (
                <div key={alert.id} className="soc-panel" style={{ padding: '24px', borderLeft: '3px solid var(--threat-critical)' }}>
                  <h2 style={{ margin: '0 0 8px 0', fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <ShieldAlert size={20} color="var(--threat-critical)" />
                    {alert.rule_name}
                  </h2>
                  <div style={{ marginBottom: '16px', display: 'flex', gap: '12px' }}>
                    <span className="badge badge-critical">SCORE: {alert.score}</span>
                    <span className="mono-data" style={{ color: 'var(--text-secondary)' }}>
                      {new Date(alert.timestamp * 1000).toLocaleString()}
                    </span>
                  </div>
                  
                  <div className="soc-panel" style={{ backgroundColor: '#000', fontFamily: 'var(--font-mono)', padding: '16px', fontSize: '0.9rem', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
                    {alert.explanation}
                  </div>
                  
                  <div style={{ marginTop: '16px', display: 'flex', gap: '12px' }}>
                    <button className="btn" style={{ backgroundColor: 'rgba(229, 57, 53, 0.1)', color: 'var(--threat-critical)', borderColor: 'var(--threat-critical)' }}>
                      Mitigate (SIGKILL)
                    </button>
                    <button className="btn" style={{ backgroundColor: 'rgba(251, 140, 0, 0.1)', color: 'var(--threat-high)', borderColor: 'var(--threat-high)' }}>
                      Freeze (SIGSTOP)
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'telemetry' && (
            <div className="soc-panel" style={{ padding: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column', height: '100%' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', gap: '12px' }}>
                <div style={{ position: 'relative', flex: 1 }}>
                  <Search size={14} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-secondary)' }} />
                  <input 
                    type="text" 
                    placeholder="Filter by PID, path, or rule..." 
                    style={{ width: '100%', backgroundColor: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: '4px', padding: '8px 8px 8px 32px', color: 'var(--text-primary)', fontFamily: 'var(--font-ui)' }}
                  />
                </div>
                <button className="btn"><Filter size={16} /> Filters</button>
              </div>
              
              <div className="table-header table-row" style={{ gridTemplateColumns: '150px 100px 150px 1fr' }}>
                <div>Time</div>
                <div>Rule ID</div>
                <div>Proc Name</div>
                <div>Detail</div>
              </div>
              
              <div style={{ overflowY: 'auto', flex: 1 }}>
                {telemetry.length === 0 && !loading && (
                   <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-secondary)' }}>No telemetry events found.</div>
                )}
                {telemetry.map(t => (
                  <div key={t.id} className="table-row mono-data" style={{ fontSize: '0.8rem', gridTemplateColumns: '150px 100px 150px 1fr' }}>
                    <div style={{ color: 'var(--text-secondary)' }}>
                      {new Date(t.timestamp * 1000).toLocaleTimeString()}
                    </div>
                    <div style={{ color: 'var(--threat-info)', fontWeight: 600 }}>{t.event_type}</div>
                    <div className="mono-blue">{t.proc_name} <span style={{color: 'var(--text-secondary)'}}>({t.proc_pid})</span></div>
                    <div style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={t.detail}>{t.detail}</div>
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
