import { useState } from 'react';
import { useReveal } from '../hooks/useReveal';

export default function AIThinkingCard({ thinking }) {
  const [open, setOpen] = useState(true);
  const ref = useReveal();

  if (thinking === null) return null;

  const isLoading = thinking === '';
  const formatted = thinking.replace(/\n{3,}/g, '\n\n').trim();

  return (
    <div ref={ref} className="glass-card p-6">
      <div className="flex items-center justify-between cursor-pointer select-none"
        onClick={() => !isLoading && setOpen(o => !o)}>
        <h4 className="text-sm uppercase tracking-wider opacity-60">Step-by-Step AI Analysis</h4>
        {isLoading
          ? <span className="text-xs text-purple-400 animate-pulse">Analyzing...</span>
          : <span className="text-xs text-gray-500 font-mono">{open ? '▲ collapse' : '▼ expand'}</span>
        }
      </div>
      {isLoading && (
        <div className="mt-4 h-1.5 bg-gray-700 rounded-full overflow-hidden">
          <div className="h-full bg-purple-600 rounded-full animate-pulse w-2/3" />
        </div>
      )}
      {!isLoading && open && (
        <div className="mt-4 text-sm leading-relaxed text-gray-300 whitespace-pre-wrap">
          {formatted || 'No analysis available.'}
        </div>
      )}
    </div>
  );
}
