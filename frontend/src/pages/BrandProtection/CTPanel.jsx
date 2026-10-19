import { useState } from 'react';
import { getCTLogs } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

export default function CTPanel() {
  const [domain,     setDomain]     = useState('');
  const [loading,    setLoading]    = useState(false);
  const [result,     setResult]     = useState(null);
  const [error,      setError]      = useState('');
  const [riskFilter, setRiskFilter] = useState('all');
  const [showAll,    setShowAll]    = useState(false);
  const reveal = useReveal();

  const handleScan = async () => {
    const d = domain.trim().toLowerCase().replace(/^www\./, '');
    if (!d) return;
    setLoading(true); setError(''); setResult(null); setShowAll(false);
    try {
      const res = await getCTLogs(d);
      if (res.error) setError(res.error); else setResult(res);
    } catch (e) { setError(e.message || 'CT log query failed'); }
    finally { setLoading(false); }
  };

  const filtered = result ? result.results.filter(r => {
    if (riskFilter === 'high')   return r.risk >= 6;
    if (riskFilter === 'medium') return r.risk >= 3 && r.risk < 6;
    if (riskFilter === 'low')    return r.risk < 3;
    return true;
  }) : [];
  const displayed  = showAll ? filtered : filtered.slice(0, 50);
  const highCount  = result ? result.results.filter(r => r.risk >= 6).length : 0;
  const medCount   = result ? result.results.filter(r => r.risk >= 3 && r.risk < 6).length : 0;

  return (
    <div ref={reveal} className="glass-card p-6 space-y-5">
      <div>
        <h3 className="text-lg font-bold text-white">Certificate Transparency Logs</h3>
        <p className="text-xs text-gray-500 mt-1">Finds SSL/TLS certs issued to domains containing your brand — data from crt.sh.</p>
      </div>
      <div className="flex gap-2">
        <input value={domain} onChange={e => setDomain(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleScan()}
          placeholder="e.g. paypal.com"
          className="flex-1 bg-black/30 border border-gray-600 rounded-lg p-3 text-white text-sm" />
        <button onClick={handleScan} disabled={loading}
          className="px-6 py-3 bg-orange-700 hover:bg-orange-600 text-white font-bold rounded-lg text-sm disabled:opacity-50">
          {loading ? 'Querying…' : 'Scan CT Logs'}
        </button>
      </div>
      {loading && <p className="text-yellow-400 text-sm animate-pulse">Querying crt.sh — this may take 5–15 seconds…</p>}
      {error   && <p className="text-red-400 text-sm">{error}</p>}
      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-3 text-center">
            <div className="bg-black/20 rounded-lg p-3">
              <p className="text-2xl font-black text-white">{result.total}</p>
              <p className="text-xs text-gray-500 mt-1">Certs found</p>
            </div>
            <div className={`rounded-lg p-3 ${highCount > 0 ? 'bg-red-900/20' : 'bg-black/20'}`}>
              <p className={`text-2xl font-black ${highCount > 0 ? 'text-red-400' : 'text-gray-500'}`}>{highCount}</p>
              <p className="text-xs text-gray-500 mt-1">High risk</p>
            </div>
            <div className={`rounded-lg p-3 ${medCount > 0 ? 'bg-yellow-900/20' : 'bg-black/20'}`}>
              <p className={`text-2xl font-black ${medCount > 0 ? 'text-yellow-400' : 'text-gray-500'}`}>{medCount}</p>
              <p className="text-xs text-gray-500 mt-1">Medium risk</p>
            </div>
          </div>
          {result.total > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500 border-b border-gray-700">
                    <th className="py-2 text-left pr-3">Domain</th>
                    <th className="py-2 text-left pr-3">Risk</th>
                    <th className="py-2 text-left pr-3">Issuer</th>
                    <th className="py-2 text-left pr-3">First Seen</th>
                    <th className="py-2 text-left">Link</th>
                  </tr>
                </thead>
                <tbody>
                  {displayed.map((r, i) => (
                    <tr key={i} className="border-b border-gray-800/60 hover:bg-white/5">
                      <td className="py-2 pr-3 font-mono text-gray-300 max-w-[220px] truncate">{r.domain}</td>
                      <td className="py-2 pr-3">
                        <span className={`px-2 py-0.5 rounded border text-xs font-semibold ${
                          r.risk >= 6 ? 'bg-red-900/60 text-red-300 border-red-800' :
                          r.risk >= 3 ? 'bg-yellow-900/60 text-yellow-300 border-yellow-700' :
                                        'bg-gray-800 text-gray-400 border-gray-700'
                        }`}>
                          {r.risk >= 6 ? 'High' : r.risk >= 3 ? 'Med' : 'Low'} {r.risk}/10
                        </span>
                      </td>
                      <td className="py-2 pr-3 text-gray-500 max-w-[140px] truncate">{r.issuer}</td>
                      <td className="py-2 pr-3 text-gray-500 whitespace-nowrap">{r.not_before?.slice(0, 10) || '—'}</td>
                      <td className="py-2">
                        {r.id && <a href={`https://crt.sh/?id=${r.id}`} target="_blank" rel="noopener noreferrer" className="text-purple-400 hover:text-purple-300 underline">crt.sh ↗</a>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filtered.length > 50 && !showAll && (
                <button onClick={() => setShowAll(true)} className="mt-3 text-xs text-purple-400 hover:text-purple-300">
                  Show all {filtered.length} results
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
