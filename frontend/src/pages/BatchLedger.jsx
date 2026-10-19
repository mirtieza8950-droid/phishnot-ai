import { useState } from 'react';
import { batchScan } from '../api/phishguard';
import { useReveal } from '../hooks/useReveal';

const EXAMPLE = JSON.stringify([
  { text: "Urgent! Your account has been suspended. Verify now to avoid permanent loss." },
  { url: "https://paypal-secure-verify.malicious-site.com/login" },
  { text: "Hi Sarah, your invoice #4521 is attached. Have a great weekend!" },
  { url: "https://www.google.com" },
], null, 2);

const PRED_COLORS = { phishing: '#ef4444', suspicious: '#f97316', spam: '#f59e0b', ham: '#22c55e', legitimate: '#22c55e' };

function SummaryCard({ label, value, color }) {
  const ref = useReveal();
  return (
    <div ref={ref} className="glass-card p-4 text-center">
      <div className="text-3xl font-black" style={{ color }}>{value}</div>
      <div className="text-xs text-gray-400 mt-1">{label}</div>
    </div>
  );
}

export default function BatchLedger() {
  const [input, setInput] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async () => {
    setError('');
    let items;
    try {
      items = JSON.parse(input);
      if (!Array.isArray(items)) throw new Error('Top-level value must be a JSON array');
      if (items.length === 0) throw new Error('Array is empty');
    } catch (e) {
      setError(e.message);
      return;
    }
    setLoading(true);
    setResults(null);
    try {
      const data = await batchScan(items);
      setResults(data);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const summary = results?.results ? (() => {
    const r = results.results;
    return {
      total: results.total,
      phishing: r.filter(x => x.prediction === 'phishing').length,
      suspicious: r.filter(x => x.prediction === 'suspicious').length,
      spam: r.filter(x => x.prediction === 'spam').length,
      safe: r.filter(x => x.prediction === 'ham' || x.prediction === 'legitimate').length,
      errors: r.filter(x => x.error).length,
    };
  })() : null;

  const tableRef = useReveal();

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-6">
      <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Bulk Ledger</h2>

      <div className="glass-card p-4 text-sm text-gray-400 space-y-1">
        <div className="text-gray-300 font-semibold">Format: JSON array — each item must have a <code className="text-purple-400">"text"</code> or <code className="text-purple-400">"url"</code> key.</div>
        <button onClick={() => setInput(EXAMPLE)} className="text-purple-400 hover:text-purple-300 underline text-xs">Load example</button>
      </div>

      <textarea value={input} onChange={e => setInput(e.target.value)} rows={12}
        className="w-full bg-gray-900/80 border border-gray-700 rounded-xl p-4 text-white font-mono text-sm placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-accent resize-y"
        placeholder={EXAMPLE} />

      {error && <div className="p-3 bg-red-900/30 border border-red-700/50 rounded-lg text-red-400 text-sm">{error}</div>}

      <button onClick={handleScan} disabled={loading || !input.trim()}
        className="w-full py-4 bg-purple-600 hover:bg-purple-700 text-white font-extrabold rounded-xl transition disabled:opacity-50">
        {loading ? 'Processing batch...' : 'RUN BATCH SCAN'}
      </button>

      {loading && <div className="text-center text-gray-400 animate-pulse">Analyzing items in parallel...</div>}

      {summary && (
        <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
          <SummaryCard label="Total" value={summary.total} color="var(--accent)" />
          <SummaryCard label="Phishing" value={summary.phishing} color="#ef4444" />
          <SummaryCard label="Suspicious" value={summary.suspicious} color="#f97316" />
          <SummaryCard label="Spam" value={summary.spam} color="#f59e0b" />
          <SummaryCard label="Safe" value={summary.safe} color="#22c55e" />
          <SummaryCard label="Errors" value={summary.errors} color="#6b7280" />
        </div>
      )}

      {results?.results && (
        <div ref={tableRef} className="glass-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                <th className="p-3 text-left w-10">#</th>
                <th className="p-3 text-left w-20">Type</th>
                <th className="p-3 text-left">Verdict</th>
                <th className="p-3 text-left">Confidence</th>
                <th className="p-3 text-left">Risk</th>
              </tr>
            </thead>
            <tbody>
              {results.results.map((r, i) => (
                <tr key={i} className="border-b border-gray-800 hover:bg-white/5 transition">
                  <td className="p-3 text-gray-500">{r.index + 1}</td>
                  <td className="p-3">
                    <span className="px-2 py-0.5 rounded text-xs font-bold bg-gray-700 text-gray-300">
                      {(r.type || '?').toUpperCase()}
                    </span>
                  </td>
                  <td className="p-3 font-bold" style={{ color: r.error ? '#6b7280' : (PRED_COLORS[r.prediction] || '#e4e6f0') }}>
                    {r.error ? 'ERROR' : (r.prediction || 'N/A').toUpperCase()}
                  </td>
                  <td className="p-3 text-gray-300">
                    {r.confidence != null ? `${(r.confidence * 100).toFixed(1)}%` : (r.error ? r.error.slice(0, 40) : 'N/A')}
                  </td>
                  <td className="p-3">
                    {r.risk_score != null ? (
                      <div className="flex items-center gap-2">
                        <div className="w-20 h-1.5 bg-gray-700 rounded-full">
                          <div className="h-full rounded-full"
                            style={{ width: `${r.risk_score}%`,
                                     background: r.risk_score >= 70 ? '#ef4444' : r.risk_score >= 40 ? '#f59e0b' : '#22c55e' }} />
                        </div>
                        <span className="text-xs text-gray-400">{r.risk_score}</span>
                      </div>
                    ) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
