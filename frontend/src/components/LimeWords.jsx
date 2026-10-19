import { useReveal } from '../hooks/useReveal';
export default function LimeWords({ explanation }) {
  const ref = useReveal();
  return (
    <div ref={ref} className="glass-card p-6">
      <h4 className="text-sm uppercase tracking-wider opacity-60 mb-4">LIME Top Words</h4>
      <div className="flex flex-wrap gap-2">
        {explanation?.map((item, i) => (
          <span key={i} className="px-3 py-1 rounded-full text-xs font-bold border" style={{ borderColor: item.weight>0?'var(--red)':'var(--green)', color: item.weight>0?'var(--red)':'var(--green)' }}>
            {item.word} <span className="opacity-60">{item.weight.toFixed(3)}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

