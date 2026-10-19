import { useState, useEffect, useRef } from 'react';
import {
  triggerIngest, getIngestStatus,
  triggerUrlRetrain, getUrlRetrainStatus,
} from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

function StatPill({ label, value, color = 'text-white' }) {
  return (
    <div className="bg-black/30 rounded-lg px-4 py-3 text-center">
      <p className={`text-2xl font-black ${color}`}>{value ?? '—'}</p>
      <p className="text-xs text-gray-500 mt-1">{label}</p>
    </div>
  );
}

function StatusBadge({ status }) {
  const map = {
    idle:    'bg-gray-700 text-gray-300',
    running: 'bg-yellow-900/60 text-yellow-300 animate-pulse',
    done:    'bg-green-900/60 text-green-300',
    error:   'bg-red-900/60 text-red-300',
  };
  return (
    <span className={`px-3 py-1 rounded-full text-xs font-bold ${map[status] ?? map.idle}`}>
      {status ?? 'idle'}
    </span>
  );
}

// ── Data Ingestion section ────────────────────────────────────────────────────

function IngestSection({ onDone }) {
  const reveal = useReveal();
  const [usePhishingDb, setUsePhishingDb] = useState(true);
  const [useKaggle,     setUseKaggle]     = useState(true);
  const [maxPdb,        setMaxPdb]        = useState(20000);
  const [maxKaggle,     setMaxKaggle]     = useState(100000);
  const [state,         setState]         = useState(null);
  const [loading,       setLoading]       = useState(false);
  const pollRef = useRef(null);

  useEffect(() => {
    getIngestStatus().then(setState).catch(() => {});
    return () => clearInterval(pollRef.current);
  }, []);

  const startPoll = () => {
    clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const s = await getIngestStatus();
        setState(s);
        if (s.status === 'done' || s.status === 'error') {
          clearInterval(pollRef.current);
          setLoading(false);
          if (s.status === 'done') onDone?.();
        }
      } catch (_) {}
    }, 2500);
  };

  const handleStart = async () => {
    if (!usePhishingDb && !useKaggle) return;
    setLoading(true);
    try {
      await triggerIngest({ use_phishing_db: usePhishingDb, use_kaggle: useKaggle, max_phishing_db: maxPdb, max_kaggle: maxKaggle });
      startPoll();
    } catch (e) {
      setLoading(false);
      setState(prev => ({ ...prev, status: 'error', error: e.message }));
    }
  };

  const running = state?.status === 'running' || loading;

  return (
    <div ref={reveal} className="glass-card p-6 space-y-5">
      <div>
        <h3 className="text-lg font-bold text-white">Step 1 — Fetch Training Data</h3>
        <p className="text-xs text-gray-500 mt-1">
          Downloads phishing URLs from open sources and saves them to
          <span className="font-mono text-gray-400"> data/url_training_data.csv</span>.
        </p>
      </div>

      {/* Source selection */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <label className={`flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition ${
          usePhishingDb ? 'border-purple-600 bg-purple-900/20' : 'border-gray-700 bg-black/20'
        }`}>
          <input type="checkbox" checked={usePhishingDb} onChange={e => setUsePhishingDb(e.target.checked)}
            className="mt-0.5 accent-purple-500" />
          <div>
            <p className="text-sm font-bold text-white">Phishing.Database (GitHub)</p>
            <p className="text-xs text-gray-500 mt-0.5">
              Active phishing links + domains. No account needed.
            </p>
            <div className="flex items-center gap-2 mt-2">
              <span className="text-xs text-gray-500">Max URLs:</span>
              <input type="number" value={maxPdb} min={100} max={100000} step={1000}
                onChange={e => setMaxPdb(+e.target.value)}
                disabled={!usePhishingDb}
                className="w-24 bg-black/30 border border-gray-600 rounded px-2 py-1 text-xs text-white disabled:opacity-40" />
            </div>
          </div>
        </label>

        <label className={`flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition ${
          useKaggle ? 'border-orange-600 bg-orange-900/20' : 'border-gray-700 bg-black/20'
        }`}>
          <input type="checkbox" checked={useKaggle} onChange={e => setUseKaggle(e.target.checked)}
            className="mt-0.5 accent-orange-500" />
          <div>
            <p className="text-sm font-bold text-white">Kaggle — phishing-site-urls</p>
            <p className="text-xs text-gray-500 mt-0.5">
              ~550k labeled URLs (phishing + legitimate). Requires
              <span className="font-mono text-gray-400"> ~/.kaggle/kaggle.json</span>.
            </p>
            <div className="flex items-center gap-2 mt-2">
              <span className="text-xs text-gray-500">Max rows:</span>
              <input type="number" value={maxKaggle} min={100} max={500000} step={10000}
                onChange={e => setMaxKaggle(+e.target.value)}
                disabled={!useKaggle}
                className="w-28 bg-black/30 border border-gray-600 rounded px-2 py-1 text-xs text-white disabled:opacity-40" />
            </div>
          </div>
        </label>
      </div>

      <button onClick={handleStart} disabled={running || (!usePhishingDb && !useKaggle)}
        className="px-6 py-3 bg-purple-700 hover:bg-purple-600 text-white font-bold rounded-lg text-sm disabled:opacity-50 transition">
        {running ? (
          <span className="flex items-center gap-2">
            <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
            Fetching…
          </span>
        ) : 'Fetch & Process Data'}
      </button>

      {/* Status */}
      {state && state.status !== 'idle' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <StatusBadge status={state.status} />
            {state.finished_at && (
              <span className="text-xs text-gray-600">
                Finished {new Date(state.finished_at).toLocaleTimeString()}
              </span>
            )}
          </div>

          {state.status === 'done' && (
            <div className="grid grid-cols-3 gap-3">
              <StatPill label="Total URLs"   value={state.total?.toLocaleString()}      color="text-white" />
              <StatPill label="Phishing"     value={state.phishing_count?.toLocaleString()}   color="text-red-400" />
              <StatPill label="Legitimate"   value={state.legitimate_count?.toLocaleString()} color="text-green-400" />
            </div>
          )}

          {state.sources_used?.length > 0 && (
            <div className="space-y-1">
              {state.sources_used.map((s, i) => (
                <p key={i} className="text-xs text-gray-400">✓ {s}</p>
              ))}
            </div>
          )}

          {state.error && (
            <p className="text-xs text-yellow-400">⚠ {state.error}</p>
          )}
        </div>
      )}
    </div>
  );
}

// ── URL Model Retrain section ─────────────────────────────────────────────────

function RetrainSection({ canRetrain }) {
  const reveal = useReveal();
  const [state,   setState]   = useState(null);
  const [loading, setLoading] = useState(false);
  const pollRef = useRef(null);

  useEffect(() => {
    getUrlRetrainStatus().then(setState).catch(() => {});
    return () => clearInterval(pollRef.current);
  }, []);

  const startPoll = () => {
    clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      try {
        const s = await getUrlRetrainStatus();
        setState(s);
        if (s.status === 'done' || s.status === 'error') {
          clearInterval(pollRef.current);
          setLoading(false);
        }
      } catch (_) {}
    }, 3000);
  };

  const handleRetrain = async () => {
    setLoading(true);
    try {
      await triggerUrlRetrain();
      startPoll();
    } catch (e) {
      setLoading(false);
      setState(prev => ({ ...prev, status: 'error', error: e.message }));
    }
  };

  const running = state?.status === 'running' || loading;

  return (
    <div ref={reveal} className="glass-card p-6 space-y-5">
      <div>
        <h3 className="text-lg font-bold text-white">Step 2 — Retrain URL Model</h3>
        <p className="text-xs text-gray-500 mt-1">
          Extracts 20 lexical features from every ingested URL, trains a
          GradientBoostingClassifier, versions and hot-swaps the running model.
          No network calls during feature extraction — runs fast.
        </p>
      </div>

      {!canRetrain && (
        <p className="text-sm text-yellow-400 bg-yellow-900/20 border border-yellow-800 rounded-lg px-4 py-3">
          Complete Step 1 (data ingestion) before retraining.
        </p>
      )}

      <button onClick={handleRetrain} disabled={running || !canRetrain}
        className="px-6 py-3 bg-green-700 hover:bg-green-600 text-white font-bold rounded-lg text-sm disabled:opacity-50 transition">
        {running ? (
          <span className="flex items-center gap-2">
            <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
            Training…
          </span>
        ) : 'Retrain URL Model'}
      </button>

      {state && state.status !== 'idle' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <StatusBadge status={state.status} />
            {state.version && (
              <span className="text-xs text-gray-400">Model v{state.version}</span>
            )}
            {state.finished_at && (
              <span className="text-xs text-gray-600">
                Finished {new Date(state.finished_at).toLocaleTimeString()}
              </span>
            )}
          </div>

          {state.status === 'done' && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <StatPill label="Total Samples"  value={state.total_samples?.toLocaleString()} />
              <StatPill label="Train Samples"  value={state.train_samples?.toLocaleString()} />
              <StatPill label="Test Accuracy"
                value={state.test_accuracy ? `${(state.test_accuracy * 100).toFixed(1)}%` : '—'}
                color={state.test_accuracy > 0.95 ? 'text-green-400' : state.test_accuracy > 0.90 ? 'text-yellow-400' : 'text-red-400'} />
              <StatPill label="Phishing Precision"
                value={state.phishing_precision ? `${(state.phishing_precision * 100).toFixed(1)}%` : '—'}
                color="text-orange-400" />
            </div>
          )}

          {state.error && <p className="text-xs text-red-400">✗ {state.error}</p>}
        </div>
      )}
    </div>
  );
}

// ── Main tab ──────────────────────────────────────────────────────────────────

export default function DataTab() {
  const [ingestDone, setIngestDone] = useState(false);

  useEffect(() => {
    getIngestStatus().then(s => setIngestDone(s.status === 'done')).catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      <IngestSection onDone={() => setIngestDone(true)} />
      <RetrainSection canRetrain={ingestDone} />
    </div>
  );
}
