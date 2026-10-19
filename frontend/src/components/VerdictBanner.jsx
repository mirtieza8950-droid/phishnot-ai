import { useReveal } from '../hooks/useReveal';
export default function VerdictBanner({ prediction }) {
  const ref = useReveal();
  const pred = prediction?.toLowerCase();
  const isDanger = pred === 'phishing' || pred === 'spam' || pred === 'suspicious';
  return (
    <div ref={ref} className={`glass-card p-6 ${isDanger ? 'verdict-pulse' : ''}`}>
      <h4 className="text-sm uppercase tracking-wider opacity-60 mb-2">Verdict</h4>
      <div className="text-3xl font-black" style={{ color: isDanger ? 'var(--red)' : 'var(--green)' }}>
        {pred === 'suspicious' ? 'Suspicious' : prediction?.toUpperCase()}
      </div>
    </div>
  );
}

