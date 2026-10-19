import { useState, useEffect } from 'react';
import { getSystemHealth } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

function HealthBar({ label, pct, detail }) {
  const color = pct == null ? 'bg-gray-700'
    : pct >= 90 ? 'bg-red-500'
    : pct >= 70 ? 'bg-yellow-500'
    : 'bg-green-500';
  return (
    <div>
      <div className="flex justify-between text-xs text-gray-400 mb-1">
        <span>{label}</span>
        <span>{pct != null ? `${pct}%` : 'n/a'} {detail && <span className="text-gray-600">· {detail}</span>}</span>
      </div>
      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct ?? 0}%` }} />
      </div>
    </div>
  );
}

export default function HealthTab() {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(false);
  const ref = useReveal();

  const load = async () => {
    setLoading(true);
    try { const res = await getSystemHealth(); setHealth(res); } catch { /* ignore */ }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const fmtKb = (kb) => kb >= 1024 ? `${(kb / 1024).toFixed(1)} MB` : `${kb} KB`;

  return (
    <div ref={ref} className="glass-card p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-bold text-white">System Health</h3>
        <div className="flex items-center gap-3">
          {health && <span className="text-xs text-gray-500">Uptime: {health.uptime}</span>}
          <button onClick={load} disabled={loading}
            className="text-xs px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg disabled:opacity-50">
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {health && (
        <>
          <div className="space-y-3">
            <HealthBar
              label="CPU"
              pct={health.cpu.percent}
              detail={health.cpu.available ? null : 'psutil not installed'}
            />
            <HealthBar
              label="Memory"
              pct={health.memory.percent}
              detail={health.memory.available
                ? `${health.memory.used_mb} / ${health.memory.total_mb} MB`
                : 'psutil not installed'}
            />
            <HealthBar
              label="Disk"
              pct={health.disk.percent}
              detail={health.disk.available
                ? `${health.disk.used_gb} / ${health.disk.total_gb} GB`
                : 'psutil not installed'}
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <p className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-2">Database Rows</p>
              <div className="space-y-1.5 text-sm">
                {Object.entries(health.db_rows).map(([k, v]) => (
                  <div key={k} className="flex justify-between text-gray-400">
                    <span className="capitalize">{k}</span>
                    <span className="text-white font-mono">{v.toLocaleString()}</span>
                  </div>
                ))}
                <div className="flex justify-between text-gray-400">
                  <span>Audit log entries</span>
                  <span className="text-white font-mono">{health.audit_entries.toLocaleString()}</span>
                </div>
              </div>
            </div>

            <div>
              <p className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-2">File Sizes</p>
              <div className="space-y-1.5 text-sm">
                {Object.entries(health.files_kb).map(([name, kb]) => (
                  <div key={name} className="flex justify-between text-gray-400">
                    <span className="font-mono text-xs">{name}</span>
                    <span className="text-white font-mono">{fmtKb(kb)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div>
            <p className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-2">Model Status</p>
            <div className="flex flex-wrap gap-3 text-xs">
              <span className={`px-3 py-1 rounded-full font-semibold ${health.models.ensemble_loaded ? 'bg-green-900 text-green-300' : 'bg-red-900 text-red-300'}`}>
                Ensemble {health.models.ensemble_loaded ? 'Loaded' : 'Not Loaded'}
              </span>
              <span className={`px-3 py-1 rounded-full font-semibold ${health.models.meta_learner_active ? 'bg-purple-900 text-purple-300' : 'bg-gray-800 text-gray-400'}`}>
                Meta-Learner {health.models.meta_learner_active ? `Active (v${health.models.meta_version ?? '?'})` : 'Inactive'}
              </span>
              <span className="px-3 py-1 rounded-full bg-gray-800 text-gray-300 font-semibold">
                Device: {health.models.device}
              </span>
            </div>
          </div>
        </>
      )}

      {!health && !loading && (
        <p className="text-gray-500 text-sm">Click Refresh to load system metrics.</p>
      )}
    </div>
  );
}
