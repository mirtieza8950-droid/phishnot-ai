import { useState, useEffect } from 'react';
import { getAnalytics } from '../api/phishguard';
import { useReveal } from '../hooks/useReveal';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Legend,
} from 'recharts';

const PRED_COLORS = { phishing: '#ef4444', suspicious: '#f97316', spam: '#f59e0b', ham: '#22c55e', legitimate: '#22c55e' };
const FALLBACK_COLORS = ['#6c63ff', '#22c55e', '#ef4444', '#f59e0b', '#06b6d4', '#ec4899'];

const TOOLTIP_STYLE = {
  background: '#161a24', border: '1px solid #2e3347', borderRadius: 8,
  color: '#e4e6f0', fontSize: 12,
};

function StatCard({ label, value, color, sub }) {
  const ref = useReveal();
  return (
    <div ref={ref} className="glass-card p-6 text-center">
      <div className="text-5xl font-black mb-1" style={{ color }}>{value}</div>
      <div className="text-sm text-gray-400">{label}</div>
      {sub && <div className="text-xs text-gray-500 mt-1">{sub}</div>}
    </div>
  );
}

export default function Analytics() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const pieRef = useReveal();
  const barRef = useReveal();
  const breakdownRef = useReveal();

  useEffect(() => {
    getAnalytics().then(setData).catch(() => setData(null)).finally(() => setLoading(false));
  }, []);

  const refresh = () => {
    setLoading(true);
    getAnalytics().then(setData).catch(() => setData(null)).finally(() => setLoading(false));
  };

  if (loading) return <div className="text-center text-gray-400 py-20 animate-pulse">Loading analytics...</div>;

  if (!data || data.total === 0) {
    return (
      <div className="max-w-4xl mx-auto p-8 text-center space-y-4">
        <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Analytics Dashboard</h2>
        <div className="glass-card p-12 text-gray-400">
          <div className="text-4xl mb-3 opacity-30">—</div>
          <div>No scan data yet.</div>
          <div className="text-sm mt-1 opacity-60">Run some scans and come back.</div>
        </div>
      </div>
    );
  }

  const predData = Object.entries(data.by_prediction || {}).map(([name, value]) => ({ name, value }));
  const typeData = Object.entries(data.by_type || {}).map(([name, value]) => ({ name: name.toUpperCase(), value }));

  const threats = (data.by_prediction?.phishing || 0) + (data.by_prediction?.suspicious || 0) + (data.by_prediction?.spam || 0);
  const threatPct = data.total > 0 ? ((threats / data.total) * 100).toFixed(0) : 0;

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Analytics Dashboard</h2>
        <button onClick={refresh} className="px-3 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-lg text-sm transition">
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard label="Total Scans" value={data.total} color="var(--accent)" />
        <StatCard label="Avg Confidence" value={`${((data.avg_confidence || 0) * 100).toFixed(1)}%`} color="#22c55e" />
        <StatCard label="Threat Rate" value={`${threatPct}%`} color={threatPct > 50 ? '#ef4444' : '#f59e0b'}
          sub={`${threats} of ${data.total} scans flagged`} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div ref={pieRef} className="glass-card p-6">
          <h4 className="text-sm uppercase tracking-wider opacity-60 mb-4">Verdict Distribution</h4>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={predData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={95}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                labelLine={{ stroke: '#2e3347' }}>
                {predData.map((e, i) => (
                  <Cell key={i} fill={PRED_COLORS[e.name] || FALLBACK_COLORS[i % FALLBACK_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Legend formatter={v => <span style={{ color: '#8b8fa3', fontSize: 12 }}>{v}</span>} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div ref={barRef} className="glass-card p-6">
          <h4 className="text-sm uppercase tracking-wider opacity-60 mb-4">Scans by Input Type</h4>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={typeData} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
              <XAxis dataKey="name" stroke="#8b8fa3" tick={{ fontSize: 11 }} />
              <YAxis stroke="#8b8fa3" tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="value" fill="#6c63ff" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div ref={breakdownRef} className="glass-card p-6">
        <h4 className="text-sm uppercase tracking-wider opacity-60 mb-4">Threat Breakdown</h4>
        <div className="flex flex-wrap gap-4">
          {predData.sort((a, b) => b.value - a.value).map((d, i) => {
            const color = PRED_COLORS[d.name] || FALLBACK_COLORS[i % FALLBACK_COLORS.length];
            const pct = data.total > 0 ? ((d.value / data.total) * 100).toFixed(1) : 0;
            return (
              <div key={d.name} className="flex-1 min-w-28 p-5 rounded-xl text-center"
                style={{ background: `${color}18`, border: `1px solid ${color}35` }}>
                <div className="text-3xl font-black" style={{ color }}>{d.value}</div>
                <div className="text-xs text-gray-400 mt-1">{d.name.toUpperCase()}</div>
                <div className="text-xs opacity-50 mt-0.5">{pct}%</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
