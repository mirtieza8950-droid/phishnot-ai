import { useState, useEffect } from 'react';
import { getHistory, downloadReport } from '../api/phishguard';
import { useReveal } from '../hooks/useReveal';

const PRED_COLORS = { phishing: '#ef4444', suspicious: '#f97316', spam: '#f59e0b', ham: '#22c55e', legitimate: '#22c55e' };

function HistoryRow({ r }) {
  const pred = (r.prediction || '').toLowerCase();
  const color = PRED_COLORS[pred] || '#e4e6f0';

  const handleDownload = async () => {
    try {
      let breakdown = {};
      let reasoning = {};
      try { breakdown = r.model_breakdown ? JSON.parse(r.model_breakdown) : {}; } catch (_) {}
      try { reasoning = r.reasoning ? JSON.parse(r.reasoning) : {}; } catch (_) {}
      const blob = await downloadReport({ prediction: r.prediction, confidence: r.confidence,
        model_predictions: breakdown, reasoning, scan_id: r.id });
      const url = URL.createObjectURL(blob);
      Object.assign(document.createElement('a'), { href: url, download: `report_${r.id || 'scan'}.pdf` }).click();
    } catch { alert('Report failed. This scan may not have enough data.'); }
  };

  return (
    <tr className="border-b border-gray-800 hover:bg-white/5 transition group">
      <td className="p-4 text-gray-500 text-xs whitespace-nowrap">
        {r.timestamp ? new Date(r.timestamp + 'Z').toLocaleString() : 'N/A'}
      </td>
      <td className="p-4">
        <span className="px-2 py-0.5 rounded text-xs font-bold bg-gray-700 text-gray-300">
          {(r.input_type || '?').toUpperCase()}
        </span>
      </td>
      <td className="p-4 text-gray-300 text-xs max-w-xs">
        <span className="truncate block" title={r.input_preview}>{r.input_preview || '—'}</span>
      </td>
      <td className="p-4 font-black text-sm" style={{ color }}>{pred.toUpperCase() || 'N/A'}</td>
      <td className="p-4 text-gray-300">
        {r.confidence != null ? `${(r.confidence * 100).toFixed(1)}%` : '—'}
      </td>
      <td className="p-4">
        <button onClick={handleDownload}
          className="px-3 py-1 rounded bg-purple-600 text-white text-xs font-semibold hover:bg-purple-700 transition opacity-0 group-hover:opacity-100">
          PDF
        </button>
      </td>
    </tr>
  );
}

export default function ScanHistory() {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [limit, setLimit] = useState(50);
  const tableRef = useReveal();

  useEffect(() => {
    setLoading(true);
    getHistory(limit).then(setRecords).catch(() => setRecords([])).finally(() => setLoading(false));
  }, [limit]);

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Scan History</h2>
        <div className="flex items-center gap-3">
          <span className="text-sm text-gray-400">{records.length} records</span>
          <select value={limit} onChange={e => setLimit(Number(e.target.value))}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:ring-2 focus:ring-accent">
            <option value={25}>Last 25</option>
            <option value={50}>Last 50</option>
            <option value={100}>Last 100</option>
            <option value={200}>Last 200</option>
          </select>
          <button onClick={() => { setLoading(true); getHistory(limit).then(setRecords).finally(() => setLoading(false)); }}
            className="px-3 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm transition">
            Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="text-center text-gray-400 animate-pulse py-12">Loading scan history...</div>
      ) : records.length === 0 ? (
        <div className="glass-card p-12 text-center text-gray-400">
          <div className="text-4xl mb-3 opacity-30">—</div>
          <div>No scans recorded yet.</div>
          <div className="text-sm mt-1 opacity-60">Run some scans to see history here.</div>
        </div>
      ) : (
        <div ref={tableRef} className="glass-card overflow-hidden overflow-x-auto">
          <table className="w-full text-sm min-w-[640px]">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase sticky top-0 bg-gray-900/90 backdrop-blur">
                <th className="p-4 text-left">Time</th>
                <th className="p-4 text-left">Type</th>
                <th className="p-4 text-left">Preview</th>
                <th className="p-4 text-left">Verdict</th>
                <th className="p-4 text-left">Confidence</th>
                <th className="p-4 text-left">Report</th>
              </tr>
            </thead>
            <tbody>
              {records.map((r, i) => <HistoryRow key={r.id || i} r={r} />)}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
