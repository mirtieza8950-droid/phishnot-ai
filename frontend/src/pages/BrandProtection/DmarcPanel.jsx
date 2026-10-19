import { useState } from 'react';
import { checkDmarc } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

const GRADE_COLOR    = { A: 'text-green-400', B: 'text-yellow-400', C: 'text-orange-400', F: 'text-red-500' };

function StatusBadge({ found, label }) {
  return (
    <div className={`p-4 rounded-lg border text-center ${found ? 'border-green-700 bg-green-950/30' : 'border-red-800 bg-red-950/20'}`}>
      <p className={`text-lg font-black ${found ? 'text-green-400' : 'text-red-400'}`}>{found ? '✓' : '✗'}</p>
      <p className="text-xs text-gray-400 mt-1">{label}</p>
    </div>
  );
}

export default function DmarcPanel() {
  const [domain,  setDomain]  = useState('');
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');
  const reveal = useReveal();

  const handleCheck = async () => {
    const d = domain.trim().toLowerCase();
    if (!d) return;
    setLoading(true); setError(''); setResult(null);
    try {
      setResult(await checkDmarc(d));
    } catch (e) {
      setError(e.message || 'DMARC check failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div ref={reveal} className="glass-card p-6 space-y-4">
      <div>
        <h3 className="text-lg font-bold text-white">DMARC / SPF / DKIM</h3>
        <p className="text-xs text-gray-500 mt-1">Check email authentication posture for a domain.</p>
      </div>
      <div className="flex gap-2">
        <input value={domain} onChange={e => setDomain(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleCheck()}
          placeholder="e.g. paypal.com"
          className="flex-1 bg-black/30 border border-gray-600 rounded-lg p-3 text-white text-sm" />
        <button onClick={handleCheck} disabled={loading}
          className="px-6 py-3 bg-purple-600 hover:bg-purple-500 text-white font-bold rounded-lg text-sm disabled:opacity-50">
          {loading ? 'Checking…' : 'Check'}
        </button>
      </div>
      {error && <p className="text-red-400 text-sm">{error}</p>}
      {result && (
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <span className={`text-6xl font-black ${GRADE_COLOR[result.grade]}`}>{result.grade}</span>
            <div>
              <p className="font-semibold text-white">{result.domain}</p>
              <p className="text-xs text-gray-400">{result.security_level} protection</p>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <StatusBadge found={result.dmarc.found} label="DMARC" />
            <StatusBadge found={result.spf?.found}  label="SPF" />
            <StatusBadge found={result.dkim?.found} label="DKIM" />
          </div>
          {result.dmarc.raw && (
            <div className="bg-black/30 rounded-lg p-3 text-xs font-mono text-gray-400 break-all">
              <span className="text-gray-600 mr-2">DMARC:</span>{result.dmarc.raw}
            </div>
          )}
          {result.spf?.raw && (
            <div className="bg-black/30 rounded-lg p-3 text-xs font-mono text-gray-400 break-all">
              <span className="text-gray-600 mr-2">SPF:</span>{result.spf.raw}
            </div>
          )}
          {result.recommendations?.length > 0 && (
            <div className="space-y-1.5">
              {result.recommendations.map((r, i) => <p key={i} className="text-xs text-yellow-400">{r}</p>)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
