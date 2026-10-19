import { useState, useEffect } from 'react';
import { getAuditLog, verifyAuditChain } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

const EVENT_COLORS = {
  'scan.email':              'text-blue-400',
  'scan.url':                'text-cyan-400',
  'scan.image':              'text-purple-400',
  'admin.whitelist_add':     'text-green-400',
  'admin.whitelist_remove':  'text-yellow-400',
  'admin.retrain_triggered': 'text-orange-400',
  'feedback.submit':         'text-pink-400',
  'auth.login':              'text-emerald-400',
  'auth.logout':             'text-gray-400',
};

export default function AuditTab() {
  const [entries, setEntries] = useState([]);
  const [chainStatus, setChainStatus] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const ref = useReveal();

  const load = async () => {
    try {
      const res = await getAuditLog(200);
      setEntries(res.entries || []);
    } catch {
      setEntries([]);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const res = await verifyAuditChain();
      setChainStatus(res);
    } catch {
      setChainStatus({ valid: false, reason: 'Request failed' });
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <div ref={ref} className="glass-card p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-bold text-white">Audit Log</h3>
        <div className="flex gap-2">
          <button onClick={load} className="px-3 py-1.5 bg-gray-700 text-gray-300 text-sm rounded-lg hover:bg-gray-600">
            Refresh
          </button>
          <button
            onClick={handleVerify}
            disabled={verifying}
            className="px-3 py-1.5 bg-purple-700 text-white text-sm rounded-lg hover:bg-purple-600 disabled:opacity-50"
          >
            {verifying ? 'Verifying...' : 'Verify Chain'}
          </button>
        </div>
      </div>

      {chainStatus && (
        <div className={`p-3 rounded-lg text-sm font-semibold ${
          chainStatus.valid ? 'bg-green-900/40 text-green-300' : 'bg-red-900/40 text-red-300'
        }`}>
          {chainStatus.valid
            ? `Chain intact — ${chainStatus.checked} entries verified`
            : `Chain BROKEN at entry #${chainStatus.first_broken_id}: ${chainStatus.reason}`}
        </div>
      )}

      <p className="text-xs text-gray-500">
        Each entry is SHA-256 chained to the previous. Any modification breaks the chain and is detected by "Verify Chain".
      </p>

      <div className="max-h-96 overflow-y-auto space-y-1.5 font-mono text-xs">
        {entries.length === 0 && (
          <p className="text-gray-500">No audit events yet.</p>
        )}
        {entries.map((e) => (
          <div key={e.id} className="bg-black/20 px-3 py-2 rounded flex flex-wrap gap-3 items-start">
            <span className="text-gray-500 w-6 text-right shrink-0">#{e.id}</span>
            <span className="text-gray-400 shrink-0">{e.timestamp?.replace('T', ' ').replace('+00:00', 'Z').slice(0, 19)}</span>
            <span className={`font-bold shrink-0 ${EVENT_COLORS[e.event_type] || 'text-gray-300'}`}>
              {e.event_type}
            </span>
            <span className="text-gray-500 shrink-0">{e.actor}</span>
            <span className="text-gray-400 truncate max-w-xs">
              {Object.entries(e.details || {})
                .filter(([k]) => !['scan_id'].includes(k))
                .map(([k, v]) => `${k}=${String(v)}`)
                .join(' ')}
            </span>
            <span className="text-gray-700 text-xs ml-auto shrink-0 hidden xl:block" title="entry hash">
              {e.entry_hash?.slice(0, 10)}…
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
