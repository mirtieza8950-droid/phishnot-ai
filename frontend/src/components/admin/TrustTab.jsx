import { useState, useEffect } from 'react';
import { getTrustStats } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

const scoreColor = (score) => {
  if (score >= 0.7) return 'text-green-400';
  if (score >= 0.4) return 'text-yellow-400';
  return 'text-red-400';
};

export default function TrustTab() {
  const [data, setData] = useState(null);
  const ref = useReveal();

  const load = async () => {
    try {
      const res = await getTrustStats();
      setData(res);
    } catch {
      setData({ summary: { total_submitters: 0, blocked_submitters: 0 }, submitters: [] });
    }
  };
  useEffect(() => { load(); }, []);

  return (
    <div ref={ref} className="glass-card p-6 space-y-4">
      <h3 className="text-lg font-bold text-white">Feedback Trust Scores</h3>
      <p className="text-sm text-gray-400">
        Submitters below 0.40 trust are blocked from influencing retraining. Scores degrade on rate-limit violations, contradictions, and all-disagreement patterns.
      </p>
      {data && (
        <>
          <div className="flex gap-6 text-sm">
            <span className="text-gray-300">Total submitters: <span className="text-white font-bold">{data.summary.total_submitters}</span></span>
            <span className="text-gray-300">Blocked: <span className="text-red-400 font-bold">{data.summary.blocked_submitters}</span></span>
          </div>
          <div className="max-h-80 overflow-y-auto space-y-2">
            {data.submitters.length === 0 && (
              <p className="text-gray-500 text-sm">No feedback submissions yet.</p>
            )}
            {data.submitters.map((s, i) => (
              <div key={i} className="bg-black/20 p-3 rounded-lg text-sm flex flex-wrap gap-4 items-center">
                <span className="text-gray-300 font-mono text-xs">{s.ip}</span>
                <span className={`font-bold ${scoreColor(s.avg_trust_score)}`}>
                  Trust: {(s.avg_trust_score * 100).toFixed(0)}%
                </span>
                <span className="text-gray-400">{s.total_submissions} submissions</span>
                <span className="text-yellow-500">{s.flagged_count} flagged</span>
                <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                  s.status === 'blocked' ? 'bg-red-900 text-red-300' : 'bg-green-900 text-green-300'
                }`}>{s.status}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
