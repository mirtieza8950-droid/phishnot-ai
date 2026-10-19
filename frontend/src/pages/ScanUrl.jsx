import { useState, useRef, useEffect } from 'react';
import { scanUrl, aiThinking, askAnalyst, downloadReport, traceRedirects, submitFeedback } from '../api/phishguard';
import VerdictBanner from '../components/VerdictBanner';
import RiskGauge from '../components/RiskGauge';
import Probabilities from '../components/Probabilities';
import ModelVotingLog from '../components/ModelVotingLog';
import AIReasoning from '../components/AIReasoning';
import AIThinkingCard from '../components/AIThinkingCard';
import AnalystChatBox from '../components/AnalystChatBox';
import { useReveal } from '../hooks/useReveal';
import ThreatIntelCard from '../components/ThreatIntelCard';

function FeatureGrid({ features }) {
  const ref = useReveal();
  const entries = Object.entries(features).slice(0, 18);
  if (!entries.length) return null;
  return (
    <div ref={ref} className="glass-card p-4 col-span-full">
      <h4 className="text-xs uppercase tracking-wider opacity-60 mb-3">URL Feature Vector</h4>
      <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-xs">
        {entries.map(([k, v]) => (
          <div key={k} className="flex justify-between bg-black/30 rounded px-2 py-1">
            <span className="text-gray-400">{k.replace(/_/g, ' ')}</span>
            <span className="font-bold text-accent">
              {typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(3)) : String(v)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function RedirectChain({ chain, suspicious, hopCount, domainChanged, risk }) {
  const ref = useReveal();
  return (
    <div ref={ref} className="glass-card p-6 col-span-full space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-sm uppercase tracking-wider opacity-60">Redirect Chain ({hopCount} hops)</h4>
        {domainChanged && <span className="text-xs font-bold text-orange-400">Domain Changed</span>}
      </div>
      {suspicious.length > 0 && (
        <div className="space-y-1">
          {suspicious.map((s, i) => (
            <div key={i} className="text-xs text-red-400 bg-red-900/20 px-3 py-1 rounded-lg">{s}</div>
          ))}
        </div>
      )}
      <div className="space-y-1">
        {chain.map((hop, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <span className="text-gray-500 w-4">{i + 1}.</span>
            <span className="px-1.5 py-0.5 rounded text-xs font-bold"
              style={{ background: hop.status_code >= 400 ? '#ef444422' : '#6c63ff22',
                       color: hop.status_code >= 400 ? '#ef4444' : '#6c63ff' }}>
              {hop.status_code}
            </span>
            <span className="text-gray-300 font-mono truncate">{hop.url}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ScanUrl() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [tracing, setTracing] = useState(false);
  const [traceResult, setTraceResult] = useState(null);
  const [thinking, setThinking] = useState(null);
  const [chatAnswer, setChatAnswer] = useState('');
  const chatInputRef = useRef(null);

  useEffect(() => {
    if (result) {
      const pred = (result.prediction || '').toLowerCase();
      document.body.classList.remove('verdict-ham', 'verdict-spam', 'verdict-phishing', 'verdict-legitimate', 'verdict-suspicious');
      if (pred) document.body.classList.add('verdict-' + pred);
    }
    return () => {
      document.body.classList.remove('verdict-ham', 'verdict-spam', 'verdict-phishing', 'verdict-legitimate', 'verdict-suspicious');
    };
  }, [result]);

  const handleScan = async () => {
    setLoading(true);
    setResult(null);
    setThinking(null);
    setTraceResult(null);
    setChatAnswer('');
    try {
      const data = await scanUrl(url);
      setResult(data);
      setThinking('');
      aiThinking(url, data.prediction)
        .then(t => setThinking(t.thinking || 'Analysis not available.'))
        .catch(() => setThinking('AI analysis unavailable.'));
    } catch (e) { alert(e.message); }
    finally { setLoading(false); }
  };

  const handleTrace = async () => {
    setTracing(true);
    try {
      const data = await traceRedirects(url);
      setTraceResult(data);
    } catch (e) { alert('Trace failed: ' + e.message); }
    finally { setTracing(false); }
  };

  const handleAsk = async () => {
    const q = chatInputRef.current?.value?.trim();
    if (!q || !result) return;
    setChatAnswer('Thinking...');
    try {
      const res = await askAnalyst({ prediction: result.prediction, confidence: result.confidence,
        model_predictions: result.model_predictions, reasoning: result.reasoning, text: url, question: q });
      setChatAnswer(res.answer || 'No answer.');
    } catch { setChatAnswer('Error contacting AI.'); }
  };

  const handleReport = async () => {
    if (!result) return;
    try {
      const blob = await downloadReport({ prediction: result.prediction, confidence: result.confidence,
        model_predictions: result.model_predictions, reasoning: result.reasoning, scan_id: result.scan_id || '' });
      const u = URL.createObjectURL(blob);
      Object.assign(document.createElement('a'), { href: u, download: `report_url_${Date.now()}.pdf` }).click();
    } catch { alert('Report generation failed.'); }
  };

  const handleFeedback = async (correct) => {
    if (!result) return;
    const label = correct ? result.prediction : prompt('Correct label? (legitimate/suspicious/phishing)');
    if (!label) return;
    try {
      await submitFeedback({ scan_id: result.scan_id, user_label: label,
        model_prediction: result.prediction, input_text: url, input_type: 'url' });
      alert('Feedback saved. Thank you!');
    } catch { alert('Feedback failed.'); }
  };

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-6">
      <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>URL Checker</h2>

      <div className="flex gap-2">
        <input value={url} onChange={e => setUrl(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && url.trim() && handleScan()}
          className="flex-1 bg-gray-900/80 border border-gray-700 rounded-xl p-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-accent"
          placeholder="https://suspicious-site.com/verify" />
        <button onClick={handleTrace} disabled={tracing || !url.trim()}
          className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 font-semibold rounded-xl transition disabled:opacity-50 text-sm whitespace-nowrap">
          {tracing ? 'Tracing...' : 'Trace'}
        </button>
      </div>

      <button onClick={handleScan} disabled={loading || !url.trim()}
        className="w-full py-4 bg-purple-600 hover:bg-purple-700 text-white font-extrabold rounded-xl transition disabled:opacity-50">
        {loading ? 'Scanning...' : 'INITIATE NEURAL SCAN'}
      </button>

      {loading && <div className="text-center text-gray-400 animate-pulse">Analyzing URL forensics...</div>}

      {traceResult && (
        <RedirectChain
          chain={traceResult.chain || []}
          suspicious={traceResult.suspicious_hops || []}
          hopCount={traceResult.hop_count || 0}
          domainChanged={traceResult.domain_changed}
          risk={traceResult.risk_score}
        />
      )}

      {result && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <VerdictBanner prediction={result.prediction} />
          <RiskGauge score={result.reasoning?.risk_score ?? Math.round(result.confidence * 100)}
            level={result.reasoning?.risk_level ?? 'N/A'} />
          <Probabilities probs={result.all_probabilities} />
          <ModelVotingLog votes={result.model_predictions} />

          {result.features && Object.keys(result.features).length > 0 && (
            <FeatureGrid features={result.features} />
          )}

          <div className="col-span-full"><AIReasoning reasoning={result.reasoning} /></div>

          {result.confidence_interval && (
            <div className="glass-card p-4 text-sm">
              <h4 className="text-xs uppercase tracking-wider opacity-60 mb-2">Calibrated Confidence</h4>
              <div className="text-2xl font-black text-accent">{(result.confidence * 100).toFixed(1)}%</div>
              <div className="text-xs text-gray-400 mt-1">
                90% interval: [{(result.confidence_interval[0] * 100).toFixed(1)}%, {(result.confidence_interval[1] * 100).toFixed(1)}%]
              </div>
            </div>
          )}

          <div className="col-span-full flex flex-wrap items-center gap-3 text-sm">
            <span className="text-gray-400">Accurate?</span>
            <button onClick={() => handleFeedback(true)} className="px-3 py-1 rounded bg-green-900/30 text-green-400 hover:bg-green-900/50 text-xs font-semibold">Yes</button>
            <button onClick={() => handleFeedback(false)} className="px-3 py-1 rounded bg-red-900/30 text-red-400 hover:bg-red-900/50 text-xs font-semibold">No</button>
            <button onClick={handleReport} className="ml-auto px-3 py-1 rounded bg-purple-600 text-white text-xs font-semibold hover:bg-purple-700">Download Report</button>
          </div>

          <ThreatIntelCard url={result?.url} />

          {thinking && <div className="col-span-full"><AIThinkingCard thinking={thinking} /></div>}
          <div className="col-span-full"><AnalystChatBox answer={chatAnswer} onAsk={handleAsk} inputRef={chatInputRef} /></div>
        </div>
      )}
    </div>
  );
}
