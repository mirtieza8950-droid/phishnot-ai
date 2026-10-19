import { useState, useEffect, useRef } from 'react';
import { startLookalikeScan, getLookalikeScanStatus } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

export default function LookalikePanel() {
  const [domain,   setDomain]   = useState('');
  const [result,   setResult]   = useState(null);
  const [scanning, setScanning] = useState(false);
  const [filter,   setFilter]   = useState('all');
  const pollRef = useRef(null);
  const reveal  = useReveal();

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const handleScan = async () => {
    const d = domain.trim().toLowerCase();
    if (!d) return;
    setScanning(true); setResult(null);
    try {
      const res = await startLookalikeScan(d);
      if (res.status === 'completed' && res.result) { setResult(res.result); setScanning(false); return; }
      pollRef.current = setInterval(async () => {
        try {
          const s = await getLookalikeScanStatus(d);
          if (s.status === 'completed') { clearInterval(pollRef.current); setResult(s.result); setScanning(false); }
          else if (s.status === 'failed') { clearInterval(pollRef.current); setScanning(false); setResult({ error: 'Scan failed' }); }
        } catch { clearInterval(pollRef.current); setScanning(false); }
      }, 3000);
    } catch (e) {
      setResult({ error: e.message }); setScanning(false);
    }
  };

  const candidates = result?.results || result?.candidates || result?.registered || [];
  const all        = result ? [...(result.registered || []).map(d => ({ domain: d, status: 'registered' })),
                               ...(result.unregistered_sample || []).map(d => ({ domain: d, status: 'unregistered' }))]
                            : candidates;
  const filtered   = filter === 'all' ? all : all.filter(c => c.status === filter);

  return (
    <div ref={reveal} className="glass-card p-6 space-y-4">
      <div>
        <h3 className="text-lg font-bold text-white">Lookalike Domain Scanner</h3>
        <p className="text-xs text-gray-500 mt-1">Detects domains that visually resemble your brand.</p>
      </div>
      <div className="flex gap-2">
        <input value={domain} onChange={e => setDomain(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !scanning && handleScan()}
          placeholder="e.g. paypal.com"
          className="flex-1 bg-black/30 border border-gray-600 rounded-lg p-3 text-white text-sm" />
        <button onClick={handleScan} disabled={scanning}
          className="px-6 py-3 bg-orange-700 hover:bg-orange-600 text-white font-bold rounded-lg text-sm disabled:opacity-50">
          {scanning ? 'Scanning…' : 'Scan'}
        </button>
      </div>
      {scanning && <p className="text-yellow-400 text-sm animate-pulse">Scanning DNS for lookalike domains…</p>}
      {result?.error && <p className="text-red-400 text-sm">{result.error}</p>}
      {all.length > 0 && (
        <div className="space-y-2">
          <div className="flex gap-2 text-xs">
            {['all', 'registered', 'unregistered'].map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`px-3 py-1.5 rounded-lg font-semibold capitalize ${filter === f ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}>
                {f} ({f === 'all' ? all.length : all.filter(c => c.status === f).length})
              </button>
            ))}
          </div>
          <div className="max-h-80 overflow-y-auto space-y-1.5">
            {filtered.map((c, i) => (
              <div key={i} className="bg-black/20 px-3 py-2 rounded text-xs flex flex-wrap gap-3 items-center">
                <span className="font-mono text-gray-300">{c.domain}</span>
                <span className={`px-2 py-0.5 rounded text-xs font-semibold ${c.status === 'registered' ? 'bg-red-900/40 text-red-300' : 'bg-green-900/40 text-green-300'}`}>
                  {c.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
