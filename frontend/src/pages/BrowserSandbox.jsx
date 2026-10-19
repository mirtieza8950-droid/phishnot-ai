import { useState, useEffect, useRef } from 'react';
import { startSandboxScan, getSandboxStatus, getSandboxResult } from '../api/phishguard';
import { useReveal } from '../hooks/useReveal';
import SummaryTab    from './BrowserSandbox/SummaryTab';
import ScreenshotTab from './BrowserSandbox/ScreenshotTab';
import DOMTab        from './BrowserSandbox/DOMTab';
import NetworkTab    from './BrowserSandbox/NetworkTab';
import JavaScriptTab from './BrowserSandbox/JavaScriptTab';

const SEVERITY_STYLES = {
  critical: 'border-red-700 bg-red-950/40 text-red-300',
  high:     'border-orange-700 bg-orange-950/30 text-orange-300',
  medium:   'border-yellow-700 bg-yellow-950/20 text-yellow-300',
  low:      'border-gray-700 bg-gray-900/30 text-gray-400',
  none:     'border-green-700 bg-green-950/20 text-green-400',
};

const TABS = ['summary', 'screenshot', 'dom', 'network', 'javascript'];

export default function BrowserSandbox() {
  const [url,       setUrl]       = useState('');
  const [jobId,     setJobId]     = useState(null);
  const [scanning,  setScanning]  = useState(false);
  const [result,    setResult]    = useState(null);
  const [elapsed,   setElapsed]   = useState(0);
  const [activeTab, setActiveTab] = useState('summary');
  const pollRef  = useRef(null);
  const timerRef = useRef(null);
  const reveal   = useReveal();
  const revealInput  = useReveal();
  const revealEmpty  = useReveal();
  const revealRisk   = useReveal();

  useEffect(() => () => {
    if (pollRef.current)  clearInterval(pollRef.current);
    if (timerRef.current) clearInterval(timerRef.current);
  }, []);

  const handleScan = async () => {
    const cleanUrl = url.trim();
    if (!cleanUrl) return;
    setScanning(true); setResult(null); setElapsed(0); setActiveTab('summary');
    try {
      const { job_id } = await startSandboxScan(cleanUrl);
      setJobId(job_id);
      timerRef.current = setInterval(() => setElapsed(p => p + 1), 1000);
      pollRef.current  = setInterval(async () => {
        try {
          const status = await getSandboxStatus(job_id);
          if (status.status === 'done' || status.status === 'completed') {
            clearInterval(pollRef.current);
            clearInterval(timerRef.current);
            setResult(await getSandboxResult(job_id));
            setScanning(false);
          } else if (status.status === 'error') {
            clearInterval(pollRef.current);
            clearInterval(timerRef.current);
            setResult({ error: status.error || 'Sandbox analysis failed' });
            setScanning(false);
          }
        } catch (e) {
          clearInterval(pollRef.current);
          clearInterval(timerRef.current);
          setResult({ error: e.message });
          setScanning(false);
        }
      }, 2000);
    } catch (e) {
      setResult({ error: e.message });
      setScanning(false);
    }
  };

  const severity = result?.risk_score >= 8 ? 'critical' :
                   result?.risk_score >= 6 ? 'high' :
                   result?.risk_score >= 4 ? 'medium' :
                   result?.risk_score >= 1 ? 'low' : 'none';

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div>
        <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Browser Sandbox</h2>
        <p className="text-gray-500 text-sm mt-1">
          Executes a URL in isolated headless Chromium. Tracks DOM mutations, credential forms,
          network requests, JavaScript obfuscation, and captures a screenshot.
        </p>
      </div>

      {/* URL Input */}
      <div ref={revealInput} className="glass-card p-6 space-y-4">
        <div className="flex gap-2">
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !scanning && handleScan()}
            placeholder="https://suspicious-site.com/login"
            className="flex-1 bg-black/30 border border-gray-600 rounded-lg p-3 text-white text-sm"
            disabled={scanning}
          />
          <button
            onClick={handleScan}
            disabled={scanning || !url.trim()}
            className="px-6 py-3 bg-red-700 hover:bg-red-600 text-white font-bold rounded-lg text-sm disabled:opacity-50 transition"
          >
            {scanning ? `Scanning… (${elapsed}s)` : 'Start Sandbox Scan'}
          </button>
        </div>
        {scanning && (
          <div className="flex items-center gap-3 text-yellow-400 text-sm">
            <div className="animate-spin h-4 w-4 border-2 border-yellow-400 border-t-transparent rounded-full" />
            Sandbox analysis in progress — page is being rendered and inspected…
          </div>
        )}
      </div>

      {/* Error */}
      {result?.error && (
        <div ref={reveal} className="glass-card border-red-700 p-6">
          <p className="text-red-400 font-semibold">Error</p>
          <p className="text-red-300 text-sm mt-1">{result.error}</p>
        </div>
      )}

      {/* Results */}
      {result && !result.error && (
        <div className="space-y-4">
          {/* Risk Score Card */}
          <div ref={revealRisk} className={`glass-card border ${SEVERITY_STYLES[severity]} p-6`}>
            <div className="flex items-center gap-6">
              <div className="text-center">
                <p className="text-4xl font-black">{result.risk_score ?? 0}/10</p>
                <p className="text-xs uppercase tracking-wide mt-1 font-semibold">Risk Score</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-black">{result.dom?.mutation_count ?? 0}</p>
                <p className="text-xs uppercase tracking-wide mt-1 font-semibold">DOM Mutations</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-black">{result.network?.cross_origin_requests ?? 0}</p>
                <p className="text-xs uppercase tracking-wide mt-1 font-semibold">Cross-Origin Reqs</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-black">{result.findings?.length ?? 0}</p>
                <p className="text-xs uppercase tracking-wide mt-1 font-semibold">Findings</p>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex gap-2 flex-wrap">
            {TABS.map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)}
                className={`px-4 py-2 rounded-lg font-semibold text-sm capitalize transition ${
                  activeTab === tab ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                }`}>
                {tab}
              </button>
            ))}
          </div>

          {activeTab === 'summary'    && <SummaryTab    result={result} />}
          {activeTab === 'screenshot' && <ScreenshotTab screenshot={result.screenshot} />}
          {activeTab === 'dom'        && <DOMTab        dom={result.dom} />}
          {activeTab === 'network'    && <NetworkTab    network={result.network} />}
          {activeTab === 'javascript' && <JavaScriptTab javascript={result.javascript} />}
        </div>
      )}

      {/* Empty state */}
      {!result && !scanning && (
        <div ref={revealEmpty} className="glass-card p-12 text-center">
          <p className="text-gray-500">Enter a URL and click "Start Sandbox Scan" to analyse a page.</p>
        </div>
      )}
    </div>
  );
}
