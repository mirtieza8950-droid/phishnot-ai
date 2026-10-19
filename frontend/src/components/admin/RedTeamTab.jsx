import { useState, useEffect, useRef } from 'react';
import { triggerEval, getEvalStatus, getEvalResults } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

const F1_COLOR = (f1) => {
  if (f1 >= 0.90) return 'text-green-400';
  if (f1 >= 0.75) return 'text-yellow-400';
  if (f1 >= 0.55) return 'text-orange-400';
  return 'text-red-400';
};

const CM_MAX_OPACITY = (val, rowMax) =>
  rowMax === 0 ? 0 : Math.round((val / rowMax) * 80);

function MetricsTable({ label, data }) {
  if (!data?.per_class) return null;
  const classes = Object.keys(data.per_class);
  return (
    <div>
      <p className="text-xs text-gray-500 font-semibold mb-1 uppercase tracking-wide">{label}</p>
      <table className="w-full text-xs text-left">
        <thead>
          <tr className="text-gray-500 border-b border-gray-700">
            <th className="py-1 pr-3">Class</th>
            <th className="py-1 pr-3">Precision</th>
            <th className="py-1 pr-3">Recall</th>
            <th className="py-1 pr-3">F1</th>
            <th className="py-1">Support</th>
          </tr>
        </thead>
        <tbody>
          {classes.map(cls => {
            const m = data.per_class[cls];
            return (
              <tr key={cls} className="border-b border-gray-800">
                <td className="py-1 pr-3 font-semibold text-gray-300 capitalize">{cls}</td>
                <td className="py-1 pr-3 text-gray-300">{(m.precision * 100).toFixed(1)}%</td>
                <td className="py-1 pr-3 text-gray-300">{(m.recall * 100).toFixed(1)}%</td>
                <td className={`py-1 pr-3 font-bold ${F1_COLOR(m.f1)}`}>{(m.f1 * 100).toFixed(1)}%</td>
                <td className="py-1 text-gray-500">{m.support}</td>
              </tr>
            );
          })}
          <tr className="text-gray-400 font-semibold">
            <td className="py-1 pr-3">Macro avg</td>
            <td className="py-1 pr-3">{(data.macro_avg.precision * 100).toFixed(1)}%</td>
            <td className="py-1 pr-3">{(data.macro_avg.recall * 100).toFixed(1)}%</td>
            <td className={`py-1 pr-3 font-bold ${F1_COLOR(data.macro_avg.f1)}`}>{(data.macro_avg.f1 * 100).toFixed(1)}%</td>
            <td className="py-1 text-gray-500">—</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

function ConfusionMatrix({ cm }) {
  if (!cm?.labels || !cm?.matrix) return null;
  const { labels, matrix } = cm;
  return (
    <div>
      <p className="text-xs text-gray-500 font-semibold mb-2 uppercase tracking-wide">Confusion Matrix</p>
      <div className="overflow-x-auto">
        <table className="text-xs text-center">
          <thead>
            <tr>
              <th className="p-1 text-gray-600">true ↓ / pred →</th>
              {labels.map(l => <th key={l} className="p-1 text-gray-400 capitalize w-20">{l}</th>)}
            </tr>
          </thead>
          <tbody>
            {matrix.map((row, ri) => {
              const rowMax = Math.max(...row);
              return (
                <tr key={ri}>
                  <td className="p-1 text-gray-400 font-semibold capitalize text-right pr-3">{labels[ri]}</td>
                  {row.map((val, ci) => (
                    <td
                      key={ci}
                      className={`p-1 w-20 font-mono rounded ${ri === ci ? 'font-bold' : ''}`}
                      style={{
                        backgroundColor: ri === ci
                          ? `rgba(34,197,94,${CM_MAX_OPACITY(val, rowMax) / 100})`
                          : `rgba(239,68,68,${CM_MAX_OPACITY(val, rowMax) / 100})`,
                        color: val === 0 ? '#4b5563' : '#e5e7eb',
                      }}
                    >
                      {val}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function RedTeamTab() {
  const [results, setResults] = useState(null);
  const [running, setRunning] = useState(false);
  const [maxSamples, setMaxSamples] = useState(500);
  const [activeModel, setActiveModel] = useState('ensemble');
  const pollRef = useRef(null);
  const ref = useReveal();

  const loadResults = async () => {
    try {
      const res = await getEvalResults();
      if (res.results) setResults(res.results);
    } catch { /* ignore */ }
  };

  const checkStatus = async () => {
    try {
      const { running: r } = await getEvalStatus();
      setRunning(r);
      if (!r) {
        clearInterval(pollRef.current);
        await loadResults();
      }
    } catch { /* ignore */ }
  };

  const handleRun = async () => {
    try {
      await triggerEval(maxSamples);
      setRunning(true);
      pollRef.current = setInterval(checkStatus, 3000);
    } catch (e) {
      alert(e.message || 'Failed to start evaluation');
    }
  };

  useEffect(() => {
    loadResults();
    getEvalStatus().then(({ running: r }) => {
      if (r) {
        setRunning(true);
        pollRef.current = setInterval(checkStatus, 3000);
      }
    }).catch(() => {});
    return () => clearInterval(pollRef.current);
  }, []);

  const modelKeys = results ? ['ensemble', ...Object.keys(results.sub_models)] : [];
  const activeData = results
    ? (activeModel === 'ensemble' ? results.ensemble : results.sub_models[activeModel])
    : null;

  return (
    <div ref={ref} className="glass-card p-6 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-lg font-bold text-white">Red Team Evaluation Suite</h3>
          {results && (
            <p className="text-xs text-gray-500 mt-0.5">
              Last run: {results.timestamp?.replace('T', ' ').slice(0, 19)} UTC
              — {results.total_samples} samples
              {results.meta_learner ? ' · meta-learner active' : ' · weighted avg ensemble'}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-400">Max samples:</label>
          <select
            value={maxSamples}
            onChange={e => setMaxSamples(Number(e.target.value))}
            className="bg-gray-800 text-gray-300 text-sm rounded px-2 py-1"
          >
            {[100, 250, 500, 1000, 2000].map(n => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
          <button
            onClick={handleRun}
            disabled={running}
            className="px-4 py-2 bg-red-700 hover:bg-red-600 text-white text-sm font-bold rounded-lg disabled:opacity-50"
          >
            {running ? 'Running...' : 'Run Evaluation'}
          </button>
        </div>
      </div>

      {running && (
        <div className="p-3 bg-yellow-900/30 text-yellow-300 text-sm rounded-lg animate-pulse">
          Evaluation in progress — polling every 3s…
        </div>
      )}

      {!results && !running && (
        <p className="text-gray-500 text-sm">No evaluation results yet. Click "Run Evaluation" to start.</p>
      )}

      {results && (
        <>
          <div className="flex gap-2 flex-wrap">
            {modelKeys.map(k => (
              <button
                key={k}
                onClick={() => setActiveModel(k)}
                className={`px-3 py-1.5 text-xs rounded-lg font-semibold capitalize transition ${
                  activeModel === k
                    ? 'bg-red-700 text-white'
                    : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                }`}
              >
                {k.replace(/_/g, ' ')}
                {k === 'ensemble' && (
                  <span className={`ml-1 font-bold ${F1_COLOR(results.ensemble.macro_avg.f1)}`}>
                    {(results.ensemble.macro_avg.f1 * 100).toFixed(0)}%
                  </span>
                )}
              </button>
            ))}
          </div>

          {activeData && (
            <div className="flex gap-6 text-sm">
              <span className="text-gray-400">Accuracy: <span className="text-white font-bold">{(activeData.accuracy * 100).toFixed(2)}%</span></span>
              <span className="text-gray-400">Macro F1: <span className={`font-bold ${F1_COLOR(activeData.macro_avg.f1)}`}>{(activeData.macro_avg.f1 * 100).toFixed(2)}%</span></span>
            </div>
          )}

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <MetricsTable label={`${activeModel.replace(/_/g, ' ')} — per class`} data={activeData} />
            <ConfusionMatrix cm={activeData?.confusion_matrix} />
          </div>

          {results.high_confidence_errors?.length > 0 && activeModel === 'ensemble' && (
            <div>
              <p className="text-xs text-gray-500 font-semibold mb-2 uppercase tracking-wide">
                High-Confidence Errors (≥70% wrong) — top {results.high_confidence_errors.length}
              </p>
              <div className="space-y-1.5 max-h-60 overflow-y-auto">
                {results.high_confidence_errors.map((e, i) => (
                  <div key={i} className="bg-black/20 px-3 py-2 rounded text-xs flex gap-3 items-start">
                    <span className="text-red-400 font-bold shrink-0">{(e.confidence * 100).toFixed(0)}%</span>
                    <span className="text-gray-400 shrink-0">true: <span className="text-green-400">{e.true}</span></span>
                    <span className="text-gray-400 shrink-0">pred: <span className="text-red-400">{e.pred}</span></span>
                    <span className="text-gray-600 truncate">{e.text_preview}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
