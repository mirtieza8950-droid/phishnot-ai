import { useReveal } from '../hooks/useReveal';
export default function Probabilities({ probs }) {
  const ref = useReveal();
  return (
    <div ref={ref} className="glass-card p-6">
      <h4 className="text-sm uppercase tracking-wider opacity-60 mb-4">Neural Consensus</h4>
      {Object.entries(probs || {}).map(([k, v]) => (
        <div key={k} className="mb-3">
          <div className="flex justify-between text-sm font-bold mb-1">
            <span>{k.toUpperCase()}</span><span>{(v*100).toFixed(1)}%</span>
          </div>
          <div className="h-2 bg-gray-700 rounded-full">
            <div className="h-full rounded-full transition-all duration-1000" style={{ width: `${(v*100).toFixed(1)}%`, background: k==='ham'||k==='legitimate'?'var(--green)':'var(--red)' }} />
          </div>
        </div>
      ))}
    </div>
  );
}

