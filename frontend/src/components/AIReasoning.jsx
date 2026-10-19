import { useReveal } from '../hooks/useReveal';
export default function AIReasoning({ reasoning }) {
  const ref = useReveal();
  if (!reasoning) return null;
  return (
    <div ref={ref} className="glass-card p-6">
      <h4 className="text-sm uppercase tracking-wider opacity-60 mb-4">AI Reasoning</h4>
      {reasoning.summary && <p className="text-base mb-3">{reasoning.summary}</p>}
      {reasoning.consensus && <p className="text-sm text-gray-400 mb-3">{reasoning.consensus}</p>}
      {reasoning.risk_story && (
        <div className="p-3 bg-black/30 rounded-lg border-l-4 border-orange-500 mb-3">
          <strong>Attack Story:</strong> {reasoning.risk_story}
        </div>
      )}
      {reasoning.key_signals?.length > 0 && (
        <>
          <div className="text-xs text-purple-400 font-bold mt-3 mb-2">Key Signals</div>
          {reasoning.key_signals.map((s, i) => <div key={i} className="p-2 bg-black/30 rounded-lg border-l-4 border-purple-500 mb-2 text-sm">{s}</div>)}
        </>
      )}
      {reasoning.best_practices?.length > 0 && (
        <>
          <div className="text-xs text-green-400 font-bold mt-3 mb-2">Defense Steps</div>
          {reasoning.best_practices.map((p, i) => <div key={i} className="p-2 bg-black/30 rounded-lg border-l-4 border-green-500 mb-2 text-sm">{p}</div>)}
        </>
      )}
    </div>
  );
}

