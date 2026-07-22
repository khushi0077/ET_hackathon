import React, { useState, useEffect, useRef } from 'react';
import { Shield, Activity, Target, ShieldAlert, Cpu, ChevronRight, Zap, Database, Network } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import ForceGraph2D from 'react-force-graph-2d';

export default function App() {
  const [streamData, setStreamData] = useState([]);
  const [metrics, setMetrics] = useState({ 
    total_events: 0, anomalies_flagged: 0, auto_resolved: 0, gated_approvals: 0,
    throughput_eps: 0, detection_latency_ms: 0.0, llm_latency_s: 0.0, fp_rate: 0.0
  });
  const [wsStatus, setWsStatus] = useState('connecting');
  const [pendingApprovals, setPendingApprovals] = useState({});
  const [latestAlert, setLatestAlert] = useState(null);
  const [auditStatus, setAuditStatus] = useState('VERIFIED');
  const [sparkline, setSparkline] = useState(Array(30).fill(0));
  const [activeLeftTab, setActiveLeftTab] = useState('telemetry');
  const [topologyData, setTopologyData] = useState({ nodes: [], links: [] });
  const [graphAnomalies, setGraphAnomalies] = useState([]);
  
  const wsRef = useRef(null);

  useEffect(() => {
    let reconnectTimeout;
    let backoffTime = 1000;
    
    const connectWs = () => {
      wsRef.current = new WebSocket('ws://localhost:8000/ws/stream');
      
      wsRef.current.onopen = () => {
        setWsStatus('connected');
        backoffTime = 1000;
        fetchPendingApprovals();
        verifyAudit();
      };
      
      wsRef.current.onclose = () => {
        setWsStatus('reconnecting');
        reconnectTimeout = setTimeout(connectWs, backoffTime);
        backoffTime = Math.min(backoffTime * 1.5, 10000);
      };
      
      wsRef.current.onerror = () => wsRef.current.close();
      
      wsRef.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'TELEMETRY') {
          setStreamData(prev => [data.flow, ...prev].slice(0, 50));
          if (data.stats) setMetrics(data.stats);
          setSparkline(prev => [...prev.slice(1), data.anomaly_score * 100]);
          
          if (data.anomaly_score > 0.6) {
            setLatestAlert({
              flow: data.flow,
              score: data.anomaly_score,
              technique: data.technique,
              explanation: data.explanation,
              similar: data.similar_incidents
            });
            
            if (data.response?.status === 'pending_approval') {
              fetchPendingApprovals();
            }
          }
        } else if (data.type === 'GRAPH_ANOMALY') {
          setGraphAnomalies(prev => [data.anomaly, ...prev].slice(0, 5));
        }
      };
    };
    
    const fetchTopology = async () => {
      try {
        const res = await fetch('http://localhost:8000/graph/topology');
        const data = await res.json();
        setTopologyData(data);
      } catch (e) {
        console.error("Topology fetch error:", e);
      }
    };
    
    connectWs();
    fetchTopology();
    const topInterval = setInterval(fetchTopology, 5000);
    
    return () => { 
      clearTimeout(reconnectTimeout); 
      clearInterval(topInterval);
      wsRef.current?.close(); 
    };
  }, []);

  const verifyAudit = async () => {
    try {
      const res = await fetch('http://localhost:8000/audit/verify');
      const data = await res.json();
      setAuditStatus(data.valid ? 'VERIFIED' : 'TAMPERED');
    } catch (e) {
      setAuditStatus('OFFLINE');
    }
  };

  const fetchPendingApprovals = async () => {
    try {
      const res = await fetch('http://localhost:8000/orchestrator/pending');
      const data = await res.json();
      setPendingApprovals(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleAction = async (id, type) => {
    try {
      await fetch(`http://localhost:8000/orchestrator/${type}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approval_id: id })
      });
      fetchPendingApprovals();
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="min-h-screen bg-[#020617] text-slate-200 flex flex-col font-sans selection:bg-cyan-500/30 overflow-hidden relative">
      {/* Dynamic Background Glows */}
      <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-cyan-600/20 rounded-full blur-[120px] -z-10 pointer-events-none mix-blend-screen" />
      <div className="absolute bottom-0 right-1/4 w-[600px] h-[600px] bg-indigo-600/10 rounded-full blur-[150px] -z-10 pointer-events-none mix-blend-screen" />
      {latestAlert && (
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-red-600/5 rounded-full blur-[200px] -z-10 pointer-events-none"
        />
      )}

      {/* Premium Header */}
      <header className="px-8 py-5 border-b border-white/5 flex justify-between items-center bg-black/40 backdrop-blur-2xl z-10 sticky top-0">
        <div className="flex items-center gap-4">
          <motion.div 
            animate={{ rotate: wsStatus === 'connected' ? 360 : 0 }} 
            transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
            className="relative flex items-center justify-center w-12 h-12"
          >
            <div className="absolute inset-0 bg-gradient-to-tr from-cyan-500 to-emerald-500 rounded-xl opacity-20 blur-md" />
            <Shield className="w-8 h-8 text-cyan-400 drop-shadow-[0_0_15px_rgba(34,211,238,0.5)] relative z-10" />
          </motion.div>
          <div>
            <h1 className="text-2xl font-black tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-white to-slate-400">PRAHARI</h1>
            <p className="text-[10px] text-cyan-400 uppercase tracking-[0.3em] font-bold opacity-80 mt-0.5">Autonomous Cyber-Resilience</p>
          </div>
        </div>

        <div className="flex items-center gap-8">
          {/* Status Indicators */}
          <div className="flex flex-col gap-2 items-end">
            <div className="flex items-center gap-3">
              <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 font-semibold">{wsStatus}</span>
              <div className="relative flex h-3 w-3">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${wsStatus === 'connected' ? 'bg-cyan-400' : 'bg-red-400'}`}></span>
                <span className={`relative inline-flex rounded-full h-3 w-3 ${wsStatus === 'connected' ? 'bg-cyan-500' : 'bg-red-500'}`}></span>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 font-semibold">AUDIT CHAIN</span>
              <div className={`px-2 py-0.5 rounded text-[9px] font-bold ${auditStatus === 'VERIFIED' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>
                {auditStatus}
              </div>
            </div>
          </div>

          {/* Premium Metrics Strip */}
          <div className="flex bg-slate-900/50 border border-white/10 rounded-2xl p-1.5 shadow-2xl backdrop-blur-xl">
            {[
              { label: 'THROUGHPUT', val: `${metrics.throughput_eps} EPS`, color: 'text-white' },
              { label: 'DETECTION LATENCY', val: `${metrics.detection_latency_ms.toFixed(2)}ms`, color: 'text-emerald-400' },
              { label: 'THREATS', val: metrics.anomalies_flagged, color: 'text-red-400 drop-shadow-[0_0_8px_rgba(248,113,113,0.5)]' },
              { label: 'EST. FP RATE', val: `${(metrics.fp_rate * 100).toFixed(2)}%`, color: 'text-indigo-400' },
              { label: 'LLM LATENCY', val: `${metrics.llm_latency_s.toFixed(2)}s`, color: 'text-cyan-400' }
            ].map((m, i) => (
              <div key={i} className="flex flex-col px-5 py-1 border-r border-white/5 last:border-0" title={m.label === 'EST. FP RATE' ? 'Synthetic Baseline Heuristic' : ''}>
                <span className="text-[9px] text-slate-500 font-bold tracking-widest mb-1 flex items-center gap-1">
                  {m.label} {m.label === 'EST. FP RATE' && <span className="text-slate-600">*</span>}
                </span>
                <span className={`text-lg font-mono font-bold ${m.color}`}>{m.val}</span>
              </div>
            ))}
          </div>
        </div>
      </header>

      <main className="flex-1 p-8 grid grid-cols-12 gap-8 min-h-0 relative z-10">
        {/* Left Column: Live Telemetry & Gated Approvals */}
        <div className="col-span-4 flex flex-col gap-8 min-h-0">
          
          {/* Telemetry Stream */}
          <div className="h-[400px] shrink-0 bg-slate-900/40 border border-white/10 rounded-2xl flex flex-col overflow-hidden backdrop-blur-md shadow-2xl">
            <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between bg-white/[0.02]">
              <div className="flex items-center gap-4">
                <button 
                  onClick={() => setActiveLeftTab('telemetry')}
                  className={`flex items-center gap-2 text-xs font-bold uppercase tracking-widest transition-colors ${activeLeftTab === 'telemetry' ? 'text-cyan-400' : 'text-slate-500 hover:text-slate-300'}`}
                >
                  <Activity className="w-4 h-4" /> Stream
                </button>
                <button 
                  onClick={() => setActiveLeftTab('topology')}
                  className={`flex items-center gap-2 text-xs font-bold uppercase tracking-widest transition-colors ${activeLeftTab === 'topology' ? 'text-indigo-400' : 'text-slate-500 hover:text-slate-300'}`}
                >
                  <Network className="w-4 h-4" /> Topology
                </button>
              </div>
              <div className="h-6 w-24 flex items-end gap-[2px]">
                {sparkline.map((val, i) => (
                  <motion.div 
                    key={i} 
                    initial={{ height: 0 }}
                    animate={{ height: `${Math.max(10, val)}%` }}
                    className={`flex-1 rounded-t-sm ${val > 80 ? 'bg-red-500' : 'bg-cyan-500/60'}`} 
                  />
                ))}
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-1.5 custom-scrollbar relative">
              {activeLeftTab === 'telemetry' ? (
                <AnimatePresence initial={false}>
                  {streamData.map((f, i) => (
                    <motion.div 
                      key={f.timestamp + i} 
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      className={`text-[11px] font-mono p-2.5 rounded-lg border flex items-center justify-between ${
                        f.is_attack 
                          ? 'bg-red-950/30 text-red-300 border-red-500/30 shadow-[inset_0_0_20px_rgba(239,68,68,0.1)]' 
                          : 'bg-white/[0.02] text-slate-400 border-white/5 hover:bg-white/5 transition-colors'
                      }`}
                    >
                      <span>{f.src_ip}:{f.dst_port} <ChevronRight className="inline w-3 h-3 text-slate-600 mx-1"/> {f.dst_ip}</span>
                      <span className="text-slate-500 text-[9px]">{f.bytes_sent}B</span>
                    </motion.div>
                  ))}
                </AnimatePresence>
              ) : (
                <div className="absolute inset-0 flex items-center justify-center overflow-hidden">
                  <ForceGraph2D 
                    graphData={topologyData}
                    width={400}
                    height={350}
                    nodeColor={(node) => graphAnomalies.some(a => a.src_ip === node.id) ? '#ef4444' : '#818cf8'}
                    linkColor={() => 'rgba(255,255,255,0.15)'}
                    backgroundColor="transparent"
                    nodeRelSize={4}
                  />
                </div>
              )}
            </div>
          </div>

          {/* Graph Lateral Movement Alerts */}
          <AnimatePresence>
            {graphAnomalies.length > 0 && (
              <motion.div 
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                className="bg-indigo-950/40 border border-indigo-500/30 rounded-2xl overflow-hidden backdrop-blur-md shadow-[0_0_30px_rgba(99,102,241,0.15)]"
              >
                <div className="px-5 py-3 border-b border-indigo-500/20 flex items-center gap-3 bg-indigo-500/10">
                  <Network className="w-4 h-4 text-indigo-400 animate-pulse" /> 
                  <span className="text-[10px] font-bold uppercase tracking-widest text-indigo-300">Lateral Movement Detected</span>
                </div>
                <div className="p-4 space-y-2 max-h-40 overflow-y-auto custom-scrollbar">
                  {graphAnomalies.map((ano, i) => (
                    <div key={i} className="text-xs flex flex-col gap-1 bg-black/40 p-2 rounded border border-indigo-500/10">
                      <div className="text-indigo-400 font-mono font-bold">Source: {ano.src_ip}</div>
                      <div className="text-slate-400">{ano.reason} ({ano.distinct_dsts} targets)</div>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
          
          {/* Gated Approvals */}
          <div className="h-[300px] bg-slate-900/60 border border-amber-500/20 rounded-2xl flex flex-col overflow-hidden backdrop-blur-md shadow-2xl relative">
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-amber-500 to-transparent opacity-50" />
            <div className="px-5 py-4 border-b border-white/5 flex items-center gap-3 bg-amber-500/5">
              <ShieldAlert className="w-5 h-5 text-amber-500 animate-pulse" /> 
              <span className="text-xs font-bold uppercase tracking-widest text-amber-400">Action Queue</span>
              <span className="ml-auto bg-amber-500/20 text-amber-400 py-0.5 px-2.5 rounded-full text-[10px] font-bold">
                {Object.keys(pendingApprovals).length} PENDING
              </span>
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
              <AnimatePresence>
                {Object.entries(pendingApprovals).map(([id, req]) => (
                  <motion.div 
                    key={id} 
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0, scale: 0.9, height: 0 }}
                    className="bg-black/50 p-4 rounded-xl border border-white/10 hover:border-amber-500/30 transition-colors shadow-lg"
                  >
                    <p className="text-sm font-bold text-white mb-2 flex items-center gap-2">
                      <Zap className="w-4 h-4 text-amber-400" /> {req.action}
                    </p>
                    <p className="text-xs text-slate-400 mb-4 line-clamp-2 leading-relaxed">{req.explanation || "Analysis pending..."}</p>
                    <div className="flex gap-3">
                      <button onClick={() => handleAction(id, 'approve')} className="flex-1 py-2 bg-emerald-500/20 hover:bg-emerald-500/40 text-emerald-400 border border-emerald-500/50 text-xs font-bold rounded-lg transition-all shadow-[0_0_15px_rgba(16,185,129,0.1)] hover:shadow-[0_0_20px_rgba(16,185,129,0.3)]">APPROVE</button>
                      <button onClick={() => handleAction(id, 'deny')} className="flex-1 py-2 bg-red-500/20 hover:bg-red-500/40 text-red-400 border border-red-500/50 text-xs font-bold rounded-lg transition-all shadow-[0_0_15px_rgba(239,68,68,0.1)] hover:shadow-[0_0_20px_rgba(239,68,68,0.3)]">DENY</button>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
              {Object.keys(pendingApprovals).length === 0 && (
                <div className="h-full flex items-center justify-center text-slate-600 font-mono text-xs tracking-widest uppercase">
                  Queue Empty
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right Column: AI Analysis & Attribution */}
        <div className="col-span-8 bg-slate-900/40 border border-white/10 rounded-2xl flex flex-col overflow-hidden backdrop-blur-md shadow-2xl relative">
          <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/10 rounded-full blur-[100px] -z-10" />
          
          <div className="px-6 py-5 border-b border-white/5 flex items-center gap-3 bg-white/[0.02]">
            <Cpu className="w-5 h-5 text-indigo-400" /> 
            <div className="flex flex-col">
              <span className="text-xs font-bold uppercase tracking-widest text-slate-200">Gemini AI Attribution & Vector Memory</span>
              <span className="text-[9px] font-mono tracking-widest text-emerald-500 mt-0.5">PRIVACY PRESERVING: PAYLOADS ANONYMIZED BEFORE LLM</span>
            </div>
          </div>
          
          <div className="flex-1 p-8 overflow-y-auto custom-scrollbar">
            {latestAlert ? (
              <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                key={latestAlert.flow.timestamp} 
                className="space-y-8"
              >
                {/* Hero Alert Section */}
                <div className="relative">
                  <div className="absolute -inset-4 bg-red-500/5 blur-xl rounded-3xl -z-10" />
                  <div className="flex items-center gap-4 mb-6">
                    <div className="px-4 py-2 bg-red-950/50 text-red-400 text-sm font-black rounded-lg border border-red-500/30 shadow-[0_0_20px_rgba(239,68,68,0.2)]">
                      THREAT SCORE: {(latestAlert.score * 100).toFixed(1)}%
                    </div>
                    <div className="px-4 py-2 bg-indigo-950/50 text-indigo-400 text-sm font-bold rounded-lg border border-indigo-500/30 font-mono">
                      MITRE ATT&CK: {latestAlert.technique}
                    </div>
                  </div>
                  
                  <div className="bg-black/60 p-6 rounded-2xl border border-white/10 relative overflow-hidden">
                    <div className="absolute top-0 left-0 w-1 h-full bg-gradient-to-b from-red-500 to-indigo-500" />
                    <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3 flex items-center gap-2"><Cpu className="w-3 h-3"/> Gemini 1.5 Flash Analysis</h3>
                    <p className="text-base text-slate-200 leading-relaxed font-light">
                      {latestAlert.explanation || "Analysis pending..."}
                    </p>
                  </div>
                </div>
                
                {/* Vector Memory Retrieval */}
                <div className="pt-4">
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-5 flex items-center gap-2">
                    <Database className="w-4 h-4 text-cyan-500" /> 
                    Retrieved Similar Incidents (ChromaDB)
                  </h3>
                  <div className="grid grid-cols-1 gap-4">
                    {latestAlert.similar.map((inc, i) => (
                       <motion.div 
                         initial={{ opacity: 0, x: 20 }}
                         animate={{ opacity: 1, x: 0 }}
                         transition={{ delay: i * 0.1 }}
                         key={i} 
                         className="bg-white/[0.03] p-5 rounded-xl border border-white/5 hover:bg-white/[0.05] transition-colors flex justify-between items-center gap-6 group"
                       >
                         <div className="flex items-start gap-4 flex-1">
                           <Target className="w-5 h-5 text-slate-600 mt-0.5 group-hover:text-cyan-500 transition-colors" />
                           <p className="text-sm text-slate-300 font-light leading-relaxed">{inc.description}</p>
                         </div>
                         <div className="text-right shrink-0 bg-black/40 px-4 py-2 rounded-lg border border-white/5">
                           <div className="text-xs font-bold text-emerald-400 mb-1">{inc.metadata.outcome}</div>
                           <div className="text-[10px] font-mono text-slate-500">{inc.metadata.date} | Analyst: <span className="text-slate-300">{inc.metadata.analyst}</span></div>
                         </div>
                       </motion.div>
                    ))}
                  </div>
                </div>
              </motion.div>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-4">
                <div className="w-24 h-24 rounded-full border border-dashed border-slate-700 flex items-center justify-center animate-[spin_10s_linear_infinite]">
                  <Shield className="w-8 h-8 text-slate-700 animate-[spin_10s_linear_infinite_reverse]" />
                </div>
                <div className="font-mono text-xs tracking-widest uppercase">Waiting for high-confidence anomaly...</div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
