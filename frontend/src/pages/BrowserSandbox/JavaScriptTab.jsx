import { useReveal } from '../../hooks/useReveal';
import MetricGrid from '../../components/MetricGrid';

export default function JavaScriptTab({ javascript = {} }) {
  const reveal = useReveal();
  const stats = [
    { label: 'eval() calls',     value: javascript.eval_count     ?? 0, warn: (javascript.eval_count     ?? 0) > 0, color: 'text-red-400' },
    { label: 'document.write()', value: javascript.document_write ?? 0, warn: (javascript.document_write ?? 0) > 0, color: 'text-red-400' },
    { label: 'atob()/btoa()',    value: javascript.atob_btoa      ?? 0, warn: (javascript.atob_btoa      ?? 0) > 0, color: 'text-red-400' },
  ];
  const scripts = javascript.obfuscated_scripts ?? [];
  return (
    <div ref={reveal} className="glass-card p-6 space-y-4">
      <h3 className="text-lg font-bold text-white">JavaScript Analysis</h3>
      <MetricGrid stats={stats} cols={3} />
      <div className="mt-2 space-y-1">
        <p className="text-xs text-gray-500 font-semibold mb-1">Obfuscated inline scripts:</p>
        {scripts.length > 0 ? (
          scripts.map((src, i) => (
            <p key={i} className="text-xs font-mono text-gray-400 break-all bg-black/20 p-2 rounded">
              {src.slice(0, 200)}
            </p>
          ))
        ) : (
          <p className="text-green-400 text-sm">No obfuscated scripts detected.</p>
        )}
      </div>
    </div>
  );
}
