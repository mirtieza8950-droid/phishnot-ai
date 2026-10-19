import { useState, useEffect } from 'react';
import { getFeedback, getQuarantine, approveFeedback, rejectFeedback, getFeedbackStats } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

export default function FeedbackTab() {
  const [feedback, setFeedback] = useState([]);
  const [quarantine, setQuarantine] = useState([]);
  const [stats, setStats] = useState(null);
  const [tab, setTab] = useState('all');
  const [loading, setLoading] = useState(false);
  const ref = useReveal();

  const loadAll = async () => {
    setLoading(true);
    try {
      const [fb, q, s] = await Promise.all([
        getFeedback(100),
        getQuarantine(50),
        getFeedbackStats(),
      ]);
      setFeedback(fb || []);
      setQuarantine(q || []);
      setStats(s || null);
    } catch (e) {
      console.error('Failed to load feedback data', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadAll(); }, []);

  const handleApprove = async (id) => {
    await approveFeedback(id);
    loadAll();
  };

  const handleReject = async (id) => {
    const reason = prompt('Rejection reason (optional):') || '';
    await rejectFeedback(id, reason);
    loadAll();
  };

  return (
    <div ref={ref} className="space-y-4">
      {/* Pipeline Stats */}
      {stats && (
        <div className="glass-card p-6">
          <h3 className="text-lg font-bold text-white mb-4">Self-Learning Pipeline</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <StatCard label="Total Feedback" value={stats.total_feedback} color="text-blue-400" />
            <StatCard label="Confirmed" value={stats.confirmed_corrections} color="text-green-400" />
            <StatCard label="Quarantined" value={stats.quarantined_count} color="text-yellow-400" />
            <StatCard label="Canary Traps" value={stats.canary_count} color="text-purple-400" />
            <StatCard label="Anomalies" value={stats.anomaly_count} color="text-red-400" />
            <StatCard label="Training Ready" value={stats.training_data_count} color="text-cyan-400" />
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="glass-card p-4">
        <div className="flex gap-2">
          {['all', 'quarantine'].map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 rounded-lg font-semibold text-sm transition ${
                tab === t ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {t.charAt(0).toUpperCase() + t.slice(1)} {t === 'quarantine' ? `(${quarantine.length})` : ''}
            </button>
          ))}
          <button
            onClick={loadAll}
            disabled={loading}
            className="ml-auto px-4 py-2 bg-gray-700 text-gray-300 rounded-lg text-sm hover:bg-gray-600"
          >
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* All Feedback */}
      {tab === 'all' && (
        <div className="glass-card p-6 space-y-3">
          <h3 className="text-lg font-bold text-white">Recent Feedback</h3>
          <div className="max-h-96 overflow-y-auto space-y-2">
            {feedback.map((f, i) => (
              <div key={i} className="bg-black/20 p-3 rounded-lg text-sm">
                <div className="flex justify-between items-start">
                  <div>
                    <span className={`px-2 py-0.5 rounded text-xs ${
                      f.user_label === 'phishing' ? 'bg-red-900 text-red-300' :
                      f.user_label === 'spam' ? 'bg-yellow-900 text-yellow-300' :
                      'bg-green-900 text-green-300'
                    }`}>{f.user_label}</span>
                    {f.user_label !== f.model_prediction && (
                      <span className="ml-2 text-xs text-gray-500">
                        (was {f.model_prediction})
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-gray-500">{f.timestamp}</div>
                </div>
                <div className="text-gray-400 text-xs mt-1 truncate">{f.preview || f.input_text}</div>
                <div className="flex gap-2 mt-1 text-xs">
                  <span className="text-gray-600">Trust: {(f.trust_score * 100).toFixed(0)}%</span>
                  {f.flagged ? <span className="text-red-500">Flagged</span> : null}
                  {f.quarantined ? <span className="text-yellow-500">Quarantined</span> : null}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Quarantine Queue */}
      {tab === 'quarantine' && (
        <div className="glass-card p-6 space-y-3">
          <h3 className="text-lg font-bold text-white">Quarantine Review Queue</h3>
          <p className="text-sm text-gray-400">
            These corrections need admin review before being used for training.
          </p>
          <div className="max-h-96 overflow-y-auto space-y-2">
            {quarantine.length === 0 && (
              <p className="text-gray-500 text-sm">No items in quarantine.</p>
            )}
            {quarantine.map((f, i) => (
              <div key={i} className="bg-black/30 p-4 rounded-lg text-sm border border-yellow-900/50">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-yellow-400 text-xs">Reason: {f.quarantine_reason}</span>
                    <div className="mt-1">
                      <span className="text-red-400">Model: {f.model_prediction}</span>
                      <span className="mx-2">→</span>
                      <span className="text-green-400">User: {f.user_label}</span>
                    </div>
                  </div>
                  <div className="text-xs text-gray-500">{f.timestamp}</div>
                </div>
                <div className="text-gray-400 text-xs mt-2 truncate">{f.input_text}</div>
                <div className="text-xs text-gray-500 mt-1">
                  Trust: {(f.trust_score * 100).toFixed(0)}% | IP: {f.submitter_ip}
                </div>
                <div className="flex gap-2 mt-3">
                  <button
                    onClick={() => handleApprove(f.id)}
                    className="px-4 py-1.5 bg-green-600 text-white text-xs font-bold rounded-lg hover:bg-green-500"
                  >
                    Approve
                  </button>
                  <button
                    onClick={() => handleReject(f.id)}
                    className="px-4 py-1.5 bg-red-600 text-white text-xs font-bold rounded-lg hover:bg-red-500"
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div className="bg-black/20 p-3 rounded-lg">
      <div className={`text-2xl font-bold ${color}`}>{value ?? '-'}</div>
      <div className="text-gray-400 text-xs">{label}</div>
    </div>
  );
}
