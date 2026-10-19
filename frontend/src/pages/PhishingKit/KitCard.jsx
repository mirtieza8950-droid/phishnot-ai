import { useReveal } from '../../hooks/useReveal';

function ConfidenceBar({ value }) {
  const color = value >= 80 ? 'bg-red-500' : value >= 50 ? 'bg-orange-500' : value >= 25 ? 'bg-yellow-500' : 'bg-gray-500';
  return (
    <div className="w-full bg-gray-800 rounded-full h-2 mt-1">
      <div className={`h-2 rounded-full transition-all duration-700 ${color}`} style={{ width: `${value}%` }} />
    </div>
  );
}

export default function KitCard({ kitName, meta, confidence, scores }) {
  const reveal = useReveal();
  return (
    <div ref={reveal} className="glass-card p-6 space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-widest text-gray-500 font-semibold">Kit Identified</p>
          <h3 className="text-2xl font-black text-white mt-1">{kitName}</h3>
          <span className="inline-block mt-1 px-2 py-0.5 bg-purple-900/50 border border-purple-700 text-purple-300 text-xs rounded font-semibold">
            {meta?.category || 'Phishing Kit'}
          </span>
        </div>
        <div className="text-right shrink-0">
          <p className={`text-4xl font-black ${confidence >= 80 ? 'text-red-400' : confidence >= 50 ? 'text-orange-400' : 'text-yellow-400'}`}>
            {confidence}%
          </p>
          <p className="text-xs text-gray-500 mt-1">Confidence</p>
          <ConfidenceBar value={confidence} />
        </div>
      </div>

      {meta?.description && <p className="text-sm text-gray-400 leading-relaxed">{meta.description}</p>}

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
        {meta?.targets?.length > 0 && (
          <div>
            <p className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-1">Targeted Brands</p>
            <div className="flex flex-wrap gap-1">
              {meta.targets.map(t => (
                <span key={t} className="px-2 py-0.5 bg-gray-800 text-gray-300 text-xs rounded border border-gray-700">{t}</span>
              ))}
            </div>
          </div>
        )}
        {meta?.threat_actors?.length > 0 && (
          <div>
            <p className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-1">Threat Actors</p>
            <div className="flex flex-wrap gap-1">
              {meta.threat_actors.map(a => (
                <span key={a} className="px-2 py-0.5 bg-red-900/30 text-red-300 text-xs rounded border border-red-800">{a}</span>
              ))}
            </div>
          </div>
        )}
        {meta?.first_seen && (
          <div>
            <p className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-1">First Seen</p>
            <p className="text-gray-300 text-sm font-bold">{meta.first_seen}</p>
          </div>
        )}
      </div>

      {Object.keys(scores).length > 1 && (
        <div>
          <p className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-2">All Partial Matches</p>
          <div className="space-y-1.5">
            {Object.entries(scores).map(([k, v]) => (
              <div key={k} className="flex items-center gap-3 text-xs">
                <span className={`w-36 truncate font-semibold ${k === kitName ? 'text-white' : 'text-gray-400'}`}>{k}</span>
                <div className="flex-1 bg-gray-800 rounded-full h-1.5">
                  <div className={`h-1.5 rounded-full ${k === kitName ? 'bg-purple-500' : 'bg-gray-600'}`}
                    style={{ width: `${Math.min(100, v)}%` }} />
                </div>
                <span className="text-gray-500 w-8 text-right">{v}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
