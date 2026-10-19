import { useState } from 'react';
import { fingerprintKit, getKitSignatures } from '../api/phishguard';
import { useReveal } from '../hooks/useReveal';
import KitCard        from './PhishingKit/KitCard';
import StructureCard  from './PhishingKit/StructureCard';
import DatabaseDrawer from './PhishingKit/DatabaseDrawer';

const SEV_STYLE = {
  critical: 'border-red-700 bg-red-950/30 text-red-300',
  high:     'border-orange-700 bg-orange-950/20 text-orange-300',
  medium:   'border-yellow-700 bg-yellow-950/20 text-yellow-300',
  low:      'border-gray-700 bg-gray-900/20 text-gray-400',
};
const SEV_BADGE = {
  critical: 'bg-red-900/60 text-red-300 border border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border border-orange-700',
  medium:   'bg-yellow-900/40 text-yellow-300 border border-yellow-700',
  low:      'bg-gray-800 text-gray-400 border border-gray-700',
};
const SCORE_COLOR = s =>
  s >= 8 ? 'text-red-400' : s >= 6 ? 'text-orange-400' : s >= 4 ? 'text-yellow-400' : s >= 2 ? 'text-blue-400' : 'text-green-400';

export default function PhishingKit() {
  const [url,      setUrl]      = useState('');
  const [scanning, setScanning] = useState(false);
  const [result,   setResult]   = useState(null);
  const [error,    setError]    = useState('');
  const [showDb,   setShowDb]   = useState(false);
  const [dbKits,   setDbKits]   = useState([]);

  const revealInput  = useReveal();
  const revealEmpty  = useReveal();
  const revealResult = useReveal();
  const revealSummary = useReveal();
  const revealInds   = useReveal();

  const handleScan = async () => {
    const u = url.trim();
    if (!u) return;
    setScanning(true); setResult(null); setError('');
    try {
      setResult(await fingerprintKit(u));
    } catch (e) {
      setError(e.message || 'Fingerprinting failed');
    } finally {
      setScanning(false);
    }
  };

  const handleToggleDb = async () => {
    if (!showDb && dbKits.length === 0) {
      try { setDbKits((await getKitSignatures()).kits || []); } catch (_) {}
    }
    setShowDb(v => !v);
  };

  const indicators = result?.indicators || [];
  const critical   = indicators.filter(i => i.severity === 'critical');
  const high       = indicators.filter(i => i.severity === 'high');
  const medium     = indicators.filter(i => i.severity === 'medium');

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Phishing Kit Fingerprinting</h2>
          <p className="text-gray-500 text-sm mt-1">
            Fetches a URL and matches its HTML/JS against a database of{' '}
            <button onClick={handleToggleDb} className="text-purple-400 hover:text-purple-300 underline">
              known phishing kits
            </button>
            {' '}— plus kit-agnostic heuristics for credential harvesting, exfiltration channels, and evasion techniques.
          </p>
        </div>
      </div>

      {/* URL input */}
      <div ref={revealInput} className="glass-card p-6 space-y-3">
        <div className="flex gap-2">
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !scanning && handleScan()}
            placeholder="https://suspicious-login-page.com/verify"
            className="flex-1 bg-black/30 border border-gray-600 rounded-lg p-3 text-white text-sm placeholder-gray-600"
            disabled={scanning}
          />
          <button
            onClick={handleScan}
            disabled={scanning || !url.trim()}
            className="px-6 py-3 bg-purple-700 hover:bg-purple-600 text-white font-bold rounded-lg text-sm disabled:opacity-50 transition"
          >
            {scanning ? (
              <span className="flex items-center gap-2">
                <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                Scanning…
              </span>
            ) : 'Fingerprint'}
          </button>
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      {showDb && dbKits.length > 0 && <DatabaseDrawer kits={dbKits} onClose={() => setShowDb(false)} />}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Risk summary */}
          <div ref={revealResult} className="glass-card p-6">
            <div className="flex flex-wrap gap-8 items-center">
              <div className="text-center">
                <p className={`text-5xl font-black ${SCORE_COLOR(result.risk_score)}`}>{result.risk_score}/10</p>
                <p className="text-xs text-gray-500 uppercase tracking-wide mt-1">Risk Score</p>
              </div>
              <div className="text-center">
                <p className={`text-3xl font-black ${result.matched_kit ? 'text-red-400' : 'text-green-400'}`}>
                  {result.matched_kit || 'Unknown'}
                </p>
                <p className="text-xs text-gray-500 uppercase tracking-wide mt-1">Kit Match</p>
              </div>
              <div className="text-center">
                <p className="text-3xl font-black text-white">{indicators.length}</p>
                <p className="text-xs text-gray-500 uppercase tracking-wide mt-1">Indicators</p>
              </div>
              {critical.length > 0 && <div className="text-center"><p className="text-2xl font-black text-red-400">{critical.length}</p><p className="text-xs text-gray-500 uppercase tracking-wide mt-1">Critical</p></div>}
              {high.length     > 0 && <div className="text-center"><p className="text-2xl font-black text-orange-400">{high.length}</p><p className="text-xs text-gray-500 uppercase tracking-wide mt-1">High</p></div>}
              {medium.length   > 0 && <div className="text-center"><p className="text-2xl font-black text-yellow-400">{medium.length}</p><p className="text-xs text-gray-500 uppercase tracking-wide mt-1">Medium</p></div>}
              <div className="text-sm text-gray-500 ml-auto">
                <p className="break-all max-w-xs">{result.final_url}</p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {result.matched_kit ? (
              <KitCard kitName={result.matched_kit} meta={result.kit_meta} confidence={result.kit_confidence} scores={result.kit_scores} />
            ) : (
              <div ref={revealSummary} className="glass-card p-6 flex flex-col items-center justify-center text-center space-y-2 min-h-40">
                <p className="text-green-400 text-3xl">✓</p>
                <p className="text-gray-300 font-semibold">No Known Kit Matched</p>
                <p className="text-gray-600 text-xs">
                  {Object.keys(result.kit_scores || {}).length > 0
                    ? `Weak partial signals from: ${Object.keys(result.kit_scores).join(', ')}`
                    : 'Page did not match any signature in the database.'}
                </p>
              </div>
            )}

            {/* Indicators */}
            <div ref={revealInds} className="glass-card p-6 space-y-3">
              <h3 className="text-base font-bold text-white">Behavioural Indicators</h3>
              {indicators.length === 0 ? (
                <p className="text-green-400 text-sm">No suspicious indicators detected.</p>
              ) : (
                <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                  {indicators.map((ind, i) => (
                    <div key={i} className={`p-3 rounded-lg border-l-4 ${SEV_STYLE[ind.severity] || SEV_STYLE.low}`}>
                      <div className="flex items-center gap-2">
                        <p className="font-bold text-sm">{ind.title}</p>
                        <span className={`ml-auto px-2 py-0.5 rounded text-xs font-semibold ${SEV_BADGE[ind.severity] || SEV_BADGE.low}`}>
                          {ind.severity}
                        </span>
                      </div>
                      <p className="text-xs mt-1 opacity-80">{ind.detail}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <StructureCard structure={result.structure} />
        </div>
      )}

      {/* Empty state */}
      {!result && !scanning && (
        <div ref={revealEmpty} className="glass-card p-12 text-center space-y-2">
          <p className="text-gray-400 text-lg">Enter a suspicious URL to identify its phishing kit.</p>
          <p className="text-gray-600 text-sm">
            The fingerprinter fetches the page and matches HTML/JS against{' '}
            <button onClick={handleToggleDb} className="text-purple-400 hover:text-purple-300 underline">
              14 known kit families
            </button>.
          </p>
        </div>
      )}
    </div>
  );
}
