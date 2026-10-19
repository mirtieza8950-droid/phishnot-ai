import { useReveal } from '../hooks/useReveal';
export default function AnalystChatBox({ answer, onAsk, inputRef }) {
  const ref = useReveal();
  return (
    <div ref={ref} className="glass-card p-6">
      <h4 className="text-sm uppercase tracking-wider opacity-60 mb-4">Ask the Analyst</h4>
      <div className="flex gap-2">
        <input ref={inputRef} type="text" className="flex-1 bg-black/30 border border-gray-600 rounded-lg p-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-accent" placeholder="e.g., What should I do if I clicked this link?" />
        <button onClick={onAsk} className="px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white font-bold rounded-lg transition">ASK</button>
      </div>
      {answer && <div className={`mt-4 p-4 rounded-lg text-sm ${answer==='Thinking...'?'bg-gray-800/30 animate-pulse':'bg-black/30'}`}>{answer}</div>}
    </div>
  );
}

