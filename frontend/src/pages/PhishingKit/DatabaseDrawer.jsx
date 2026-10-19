import { useReveal } from '../../hooks/useReveal';

export default function DatabaseDrawer({ kits, onClose }) {
  const reveal = useReveal();
  return (
    <div ref={reveal} className="glass-card p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-bold text-white">
          Kit Signature Database{' '}
          <span className="text-gray-500 font-normal text-sm">({kits.length} kits)</span>
        </h3>
        <button onClick={onClose} className="text-gray-500 hover:text-gray-300 text-sm">close ✕</button>
      </div>
      <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
        {kits.map(k => (
          <div key={k.id} className="bg-black/20 rounded-lg p-3 space-y-1">
            <div className="flex items-center gap-2">
              <span className="font-bold text-white text-sm">{k.id}</span>
              <span className="px-1.5 py-0.5 bg-purple-900/40 text-purple-400 text-xs rounded border border-purple-800">
                {k.category}
              </span>
              <span className="text-gray-600 text-xs ml-auto">{k.first_seen}</span>
            </div>
            <p className="text-xs text-gray-500">{k.description}</p>
            <div className="flex flex-wrap gap-1 mt-1">
              {k.targets.slice(0, 5).map(t => (
                <span key={t} className="text-xs px-1.5 py-0.5 bg-gray-800 text-gray-400 rounded">{t}</span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
