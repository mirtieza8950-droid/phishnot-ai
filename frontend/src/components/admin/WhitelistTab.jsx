import { useState, useEffect } from 'react';
import { getWhitelist, addDomain, removeDomain } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

export default function WhitelistTab() {
  const [domains, setDomains] = useState([]);
  const [newDomain, setNewDomain] = useState('');
  const ref = useReveal();

  const load = async () => {
    const data = await getWhitelist();
    setDomains(data.domains || []);
  };
  useEffect(() => { load(); }, []);

  const handleAdd = async () => {
    if (!newDomain.trim()) return;
    await addDomain(newDomain.trim());
    setNewDomain('');
    load();
  };

  const handleRemove = async (domain) => {
    await removeDomain(domain);
    load();
  };

  return (
    <div ref={ref} className="glass-card p-6 space-y-4">
      <h3 className="text-lg font-bold text-white">Domain Whitelist</h3>
      <div className="flex gap-2">
        <input
          value={newDomain}
          onChange={e => setNewDomain(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAdd()}
          placeholder="e.g., deepseek.com"
          className="flex-1 bg-black/30 border border-gray-600 rounded-lg p-3 text-white"
        />
        <button onClick={handleAdd} className="px-6 py-3 bg-purple-600 text-white font-bold rounded-lg">
          Add
        </button>
      </div>
      <ul className="space-y-2 max-h-64 overflow-y-auto">
        {domains.map(d => (
          <li key={d} className="flex justify-between items-center py-1 border-b border-gray-700">
            <span className="text-sm text-gray-300">{d}</span>
            <button onClick={() => handleRemove(d)} className="text-red-400 hover:text-red-300 text-sm">Remove</button>
          </li>
        ))}
      </ul>
    </div>
  );
}
