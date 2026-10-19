import { useReveal } from '../../hooks/useReveal';

export default function SummaryTab({ result }) {
  const reveal   = useReveal();
  const findings = result?.findings || [];

  return (
    <div ref={reveal} className="glass-card p-6 space-y-4">
      <h3 className="text-lg font-bold text-white">Findings</h3>
      {findings.length === 0 ? (
        <p className="text-green-400 text-sm">No suspicious behaviour detected.</p>
      ) : (
        <div className="space-y-2">
          {findings.map((f, i) => (
            <div key={i} className={`p-3 rounded-lg border-l-4 ${
              f.severity === 'critical' ? 'border-red-600 bg-red-950/20 text-red-300' :
              f.severity === 'high'     ? 'border-orange-600 bg-orange-950/20 text-orange-300' :
              f.severity === 'medium'   ? 'border-yellow-600 bg-yellow-950/20 text-yellow-300' :
                                          'border-gray-600 bg-gray-900/20 text-gray-400'
            }`}>
              <p className="font-bold text-sm">{f.title}</p>
              <p className="text-xs mt-1 opacity-80">{f.detail || f.description}</p>
            </div>
          ))}
        </div>
      )}
      <div className="mt-4 space-y-1.5 text-sm">
        <p className="text-gray-400">
          <span className="text-gray-500 mr-1">Scanned URL:</span>
          <span className="text-gray-300 break-all">{result.url || result.scanned_url || '—'}</span>
        </p>
        <p className="text-gray-400">
          <span className="text-gray-500 mr-1">Final URL:</span>
          <span className="text-gray-300 break-all">{result.final_url || '—'}</span>
        </p>
        <p className="text-gray-400">
          <span className="text-gray-500 mr-1">Page title:</span>
          <span className="text-gray-300">{result.page_title || '—'}</span>
        </p>
      </div>
    </div>
  );
}
