import { useReveal } from '../../hooks/useReveal';
import MetricGrid from '../../components/MetricGrid';

export default function NetworkTab({ network = {} }) {
  const reveal = useReveal();
  const stats = [
    { label: 'Total Requests',    value: network.total_requests        ?? 0 },
    { label: 'Cross-Origin',      value: network.cross_origin_requests ?? 0, warn: (network.cross_origin_requests ?? 0) > 5, color: 'text-red-400' },
    { label: 'Data Exfiltration', value: network.data_exfiltration     ?? 0, warn: (network.data_exfiltration     ?? 0) > 0, color: 'text-red-400' },
  ];
  const urls = network.cross_origin_urls ?? [];
  return (
    <div ref={reveal} className="glass-card p-6 space-y-4">
      <h3 className="text-lg font-bold text-white">Network Requests</h3>
      <MetricGrid stats={stats} cols={3} />
      {urls.length > 0 && (
        <div className="mt-2 space-y-1">
          <p className="text-xs text-gray-500 font-semibold mb-1">Cross-Origin URLs:</p>
          {urls.map((u, i) => (
            <p key={i} className="text-xs font-mono text-gray-400 break-all bg-black/20 p-2 rounded">{u}</p>
          ))}
        </div>
      )}
    </div>
  );
}
