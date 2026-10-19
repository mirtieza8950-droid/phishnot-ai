import { useReveal } from '../hooks/useReveal';
import { useThreatIntel } from '../hooks/useThreatIntel';

// ── Threat-level styles ───────────────────────────────────────────────────────

const LEVEL_STYLE = {
  malicious:    'bg-red-900/60 text-red-300 border border-red-700',
  suspicious:   'bg-orange-900/50 text-orange-300 border border-orange-700',
  clean:        'bg-green-900/40 text-green-300 border border-green-700',
  not_found:    'bg-gray-800 text-gray-400 border border-gray-700',
  unconfigured: 'bg-gray-800/50 text-gray-600 border border-gray-800',
  timeout:      'bg-yellow-900/30 text-yellow-500 border border-yellow-800',
  error:        'bg-gray-800/50 text-gray-500 border border-gray-700',
};
const LEVEL_LABEL = {
  malicious: 'Malicious', suspicious: 'Suspicious', clean: 'Clean',
};
const OVERALL_COLOR = {
  malicious: 'text-red-400', suspicious: 'text-orange-400', clean: 'text-green-400',
};

// ── Detection bar (VirusTotal) ────────────────────────────────────────────────

function DetectionBar({ malicious, total }) {
  if (!total) return null;
  const pct  = Math.round((malicious / total) * 100);
  const color = malicious >= 5 ? 'bg-red-500' : malicious >= 1 ? 'bg-orange-500' : 'bg-green-500';
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className={malicious > 0 ? 'text-red-400 font-bold' : 'text-green-400'}>
          {malicious}/{total} engines
        </span>
        <span className="text-gray-500">{pct}%</span>
      </div>
      <div className="w-full bg-gray-800 rounded-full h-1.5">
        <div className={`h-1.5 rounded-full transition-all duration-700 ${color}`}
          style={{ width: `${Math.max(pct, malicious > 0 ? 2 : 0)}%` }} />
      </div>
    </div>
  );
}

// ── Per-feed card ─────────────────────────────────────────────────────────────

function FeedCard({ title, logo, feed, children }) {
  const status = feed?.status ?? 'error';
  const level  = feed?.threat_level ?? (status === 'not_found' ? 'not_found' : status);

  return (
    <div className="bg-black/20 rounded-xl p-4 space-y-3 border border-gray-800/60">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-base">{logo}</span>
          <span className="text-sm font-bold text-white">{title}</span>
        </div>
        <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${LEVEL_STYLE[level] ?? LEVEL_STYLE.error}`}>
          {status === 'unconfigured' ? 'No API key'
            : status === 'timeout'  ? 'Timed out'
            : status === 'not_found'? 'Not found'
            : status === 'error'    ? 'Error'
            : LEVEL_LABEL[level] ?? level}
        </span>
      </div>

      {status === 'unconfigured' && (
        <p className="text-xs text-gray-600">{feed.message}</p>
      )}
      {status === 'error' && feed?.message && (
        <p className="text-xs text-gray-600">{feed.message}</p>
      )}
      {status === 'timeout' && (
        <p className="text-xs text-yellow-600">Request exceeded 6 s timeout. Try again.</p>
      )}
      {status === 'not_found' && (
        <p className="text-xs text-gray-500">URL not in database.</p>
      )}
      {status === 'found' && children}

      {feed?.report_url && status === 'found' && (
        <a href={feed.report_url} target="_blank" rel="noopener noreferrer"
          className="inline-block text-xs text-purple-400 hover:text-purple-300 underline mt-1">
          View full report ↗
        </a>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ThreatIntelCard({ url }) {
  const reveal = useReveal();
  const { data, loading, error } = useThreatIntel(url);

  if (!url) return null;

  const overall = data?.overall_threat_level ?? 'clean';
  const vt  = data?.virustotal  ?? {};
  const otx = data?.otx         ?? {};
  const pt  = data?.phishtank   ?? {};

  return (
    <div ref={reveal} className="glass-card p-6 space-y-5 col-span-full">
      {/* Header */}
      <div className="flex items-center gap-3 flex-wrap">
        <h3 className="text-lg font-bold text-white">Threat Intelligence</h3>
        {loading && (
          <span className="flex items-center gap-1.5 text-xs text-gray-400">
            <span className="animate-spin h-3.5 w-3.5 border-2 border-purple-500 border-t-transparent rounded-full" />
            Querying feeds…
          </span>
        )}
        {data && !loading && (
          <>
            <span className={`px-3 py-1 rounded-full text-sm font-bold border ${LEVEL_STYLE[overall] ?? LEVEL_STYLE.clean}`}>
              {LEVEL_LABEL[overall] ?? overall}
            </span>
            {data.cached && (
              <span className="text-xs text-gray-600 ml-auto">cached result</span>
            )}
          </>
        )}
        {error && <span className="text-xs text-red-400">{error}</span>}
      </div>

      {/* Feed cards — skeleton while loading */}
      {(loading || data) && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">

          {/* VirusTotal */}
          <FeedCard title="VirusTotal" logo="🔬" feed={loading ? { status: 'loading' } : vt}>
            <DetectionBar malicious={vt.malicious} total={vt.total_engines} />
            {vt.suspicious > 0 && (
              <p className="text-xs text-yellow-400">{vt.suspicious} engine(s) flagged suspicious</p>
            )}
            {vt.categories?.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1">
                {vt.categories.slice(0, 3).map(c => (
                  <span key={c} className="text-xs bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">{c}</span>
                ))}
              </div>
            )}
            {vt.reputation !== undefined && (
              <p className="text-xs text-gray-500">Community score: {vt.reputation}</p>
            )}
          </FeedCard>

          {/* AlienVault OTX */}
          <FeedCard title="AlienVault OTX" logo="👁" feed={loading ? { status: 'loading' } : otx}>
            {otx.pulse_count !== undefined && (
              <div className="flex items-center gap-2">
                <span className={`text-2xl font-black ${otx.pulse_count > 0 ? 'text-red-400' : 'text-green-400'}`}>
                  {otx.pulse_count}
                </span>
                <span className="text-xs text-gray-500">threat pulse(s)</span>
              </div>
            )}
            {otx.tags?.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {otx.tags.slice(0, 5).map(t => (
                  <span key={t} className="text-xs bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">{t}</span>
                ))}
              </div>
            )}
            {otx.malware_families?.length > 0 && (
              <p className="text-xs text-red-400">
                Malware: {otx.malware_families.join(', ')}
              </p>
            )}
            {(otx.country || otx.asn) && (
              <p className="text-xs text-gray-500">
                {[otx.country, otx.asn].filter(Boolean).join(' · ')}
              </p>
            )}
          </FeedCard>

          {/* PhishTank */}
          <FeedCard title="PhishTank" logo="🎣" feed={loading ? { status: 'loading' } : pt}>
            {pt.in_database !== undefined && (
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className={pt.in_database ? 'text-red-400' : 'text-green-400'}>
                    {pt.in_database ? '✓' : '✗'}
                  </span>
                  <span className="text-xs text-gray-300">
                    {pt.in_database ? 'In phishing database' : 'Not in database'}
                  </span>
                </div>
                {pt.in_database && (
                  <div className="flex items-center gap-2">
                    <span className={pt.verified ? 'text-red-400' : 'text-yellow-400'}>
                      {pt.verified ? '✓' : '⏳'}
                    </span>
                    <span className="text-xs text-gray-300">
                      {pt.verified ? 'Verified phishing' : 'Pending verification'}
                    </span>
                  </div>
                )}
                {pt.verified_at && (
                  <p className="text-xs text-gray-500">
                    Verified: {pt.verified_at?.slice(0, 10)}
                  </p>
                )}
              </div>
            )}
          </FeedCard>

        </div>
      )}
    </div>
  );
}
