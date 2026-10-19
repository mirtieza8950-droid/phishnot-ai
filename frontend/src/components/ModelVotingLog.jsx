import { useReveal } from '../hooks/useReveal';
export default function ModelVotingLog({ votes }) {
  const ref = useReveal();
  return (
    <div ref={ref} className="glass-card p-6">
      <h4 className="text-sm uppercase tracking-wider opacity-60 mb-4">Model Voting</h4>
      {Object.entries(votes || {}).map(([name, m]) => (
        <div key={name} className="flex justify-between text-sm border-b border-gray-700/50 py-2">
          <span className="font-bold">{name.replace(/_/g, ' ').toUpperCase()}</span>
          <span className="font-black" style={{ color: (m.prediction==='ham'||m.prediction==='legitimate')?'var(--green)':'var(--red)' }}>{(m.prediction||'').toUpperCase()}</span>
        </div>
      ))}
    </div>
  );
}

