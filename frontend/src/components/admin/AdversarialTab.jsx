import { useState } from 'react';
import { generateAdversarial, exportAdversarial, getAdversarialStats } from '../../api/phishguard';
import { useReveal } from '../../hooks/useReveal';

const ALL_STRATEGIES = [
  { id: 'homoglyph',         label: 'Homoglyph',         desc: 'Unicode lookalike chars (Cyrillic а for Latin a)' },
  { id: 'leetspeak',         label: 'Leetspeak',          desc: 'a→@ e→3 i→! o→0 s→$' },
  { id: 'punctuation_split', label: 'Punct. Split',       desc: 'verify → v.e.r.i.f.y' },
  { id: 'zero_width',        label: 'Zero-Width',         desc: 'Insert invisible U+200B between letters' },
  { id: 'case_flip',         label: 'Case Flip',          desc: 'RaNdOm CaSe cHaNgEs' },
  { id: 'benign_insertion',  label: 'Benign Insertion',   desc: 'Splice innocent filler phrases' },
  { id: 'url_encode',        label: 'URL Encode',         desc: 'Hex-encode chars inside URLs' },
  { id: 'whitespace_inject', label: 'Whitespace Inject',  desc: 'Split suspicious words with spaces' },
];

export default function AdversarialTab() {
  const [seedText, setSeedText]         = useState('');
  const [trueLabel, setTrueLabel]       = useState('phishing');
  const [strategies, setStrategies]     = useState(ALL_STRATEGIES.map(s => s.id));
  const [nPerStrat, setNPerStrat]       = useState(3);
  const [loading, setLoading]           = useState(false);
  const [results, setResults]           = useState(null);
  const [selected, setSelected]         = useState(new Set());
  const [exportMsg, setExportMsg]       = useState('');
  const [csvStats, setCsvStats]         = useState(null);
  const ref = useReveal();

  const toggleStrategy = (id) =>
    setStrategies(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    );

  const toggleSelect = (i) =>
    setSelected(prev => {
      const next = new Set(prev);
      next.has(i) ? next.delete(i) : next.add(i);
      return next;
    });

  const selectFooled = () => {
    if (!results) return;
    setSelected(new Set(results.variants.map((v, i) => v.fooled ? i : -1).filter(i => i >= 0)));
  };

  const handleGenerate = async () => {
    if (!seedText.trim()) return;
    setLoading(true);
    setResults(null);
    setSelected(new Set());
    setExportMsg('');
    try {
      const res = await generateAdversarial({
        text: seedText,
        true_label: trueLabel,
        strategies,
        n_per_strategy: nPerStrat,
      });
      setResults(res);
    } catch (e) {
      alert(e.message || 'Generation failed');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async () => {
    if (!results || selected.size === 0) return;
    const toExport = [...selected].map(i => results.variants[i]);
    try {
      const res = await exportAdversarial(toExport, trueLabel);
      setExportMsg(res.message);
      const stats = await getAdversarialStats();
      setCsvStats(stats);
    } catch (e) {
      setExportMsg('Export failed: ' + e.message);
    }
  };

  return (
    <div ref={ref} className="glass-card p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h3 className="text-lg font-bold text-white">Adversarial Training Data Generator</h3>
        {csvStats && (
          <span className="text-xs text-gray-500">
            CSV: {csvStats.rows} rows — {Object.entries(csvStats.labels).map(([k,v]) => `${k}: ${v}`).join(' · ')}
          </span>
        )}
      </div>

      <div className="space-y-2">
        <label className="text-xs text-gray-400 font-semibold uppercase tracking-wide">Seed Text</label>
        <textarea
          value={seedText}
          onChange={e => setSeedText(e.target.value)}
          rows={5}
          placeholder="Paste a phishing / spam email here…"
          className="w-full bg-black/30 border border-gray-600 rounded-lg p-3 text-sm text-white resize-y"
        />
        <div className="flex gap-4 items-center">
          <label className="text-xs text-gray-400">True label:</label>
          {['phishing', 'spam', 'ham'].map(l => (
            <label key={l} className="flex items-center gap-1.5 text-sm cursor-pointer">
              <input type="radio" name="label" value={l} checked={trueLabel === l}
                onChange={() => setTrueLabel(l)} className="accent-purple-500" />
              <span className={
                l === 'phishing' ? 'text-red-400' :
                l === 'spam'     ? 'text-orange-400' : 'text-green-400'
              }>{l}</span>
            </label>
          ))}
          <label className="text-xs text-gray-400 ml-4">Variants per strategy:</label>
          <select value={nPerStrat} onChange={e => setNPerStrat(Number(e.target.value))}
            className="bg-gray-800 text-gray-300 text-sm rounded px-2 py-1">
            {[1,2,3,5].map(n => <option key={n} value={n}>{n}</option>)}
          </select>
        </div>
      </div>

      <div>
        <label className="text-xs text-gray-400 font-semibold uppercase tracking-wide block mb-2">Strategies</label>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {ALL_STRATEGIES.map(s => (
            <label key={s.id}
              className={`flex items-start gap-2 p-2 rounded-lg border cursor-pointer text-xs transition ${
                strategies.includes(s.id)
                  ? 'border-purple-500 bg-purple-900/20 text-white'
                  : 'border-gray-700 bg-black/10 text-gray-500'
              }`}
              title={s.desc}
            >
              <input type="checkbox" checked={strategies.includes(s.id)}
                onChange={() => toggleStrategy(s.id)} className="mt-0.5 accent-purple-500 shrink-0" />
              <span>{s.label}</span>
            </label>
          ))}
        </div>
      </div>

      <button
        onClick={handleGenerate}
        disabled={loading || !seedText.trim() || strategies.length === 0}
        className="px-6 py-2.5 bg-purple-700 hover:bg-purple-600 text-white font-bold rounded-lg disabled:opacity-50 text-sm"
      >
        {loading ? 'Generating…' : 'Generate Variants'}
      </button>

      {results && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-4 text-sm">
            <span className="text-gray-300">{results.total} variants generated</span>
            <span className={`font-bold ${results.fooled > 0 ? 'text-red-400' : 'text-green-400'}`}>
              {results.fooled} fooled the model ({(results.fool_rate * 100).toFixed(0)}%)
            </span>
            <button onClick={selectFooled} className="text-xs text-purple-400 underline">
              Select all fooled
            </button>
            <button
              onClick={handleExport}
              disabled={selected.size === 0}
              className="ml-auto px-4 py-1.5 bg-green-700 hover:bg-green-600 text-white text-xs font-bold rounded-lg disabled:opacity-40"
            >
              Export {selected.size > 0 ? `(${selected.size})` : ''} to CSV
            </button>
          </div>

          {exportMsg && (
            <p className="text-xs text-green-400">{exportMsg}</p>
          )}

          <div className="max-h-96 overflow-y-auto space-y-1.5">
            {results.variants.map((v, i) => (
              <div
                key={i}
                onClick={() => toggleSelect(i)}
                className={`px-3 py-2 rounded-lg text-xs cursor-pointer border transition ${
                  selected.has(i)
                    ? 'border-purple-500 bg-purple-900/20'
                    : 'border-gray-800 bg-black/10 hover:border-gray-600'
                }`}
              >
                <div className="flex flex-wrap gap-3 items-center mb-1">
                  <span className="text-gray-500 font-mono bg-gray-900 px-1.5 py-0.5 rounded">
                    {v.strategy.replace(/_/g, ' ')}
                  </span>
                  {v.fooled && (
                    <span className="text-red-400 font-bold">FOOLED</span>
                  )}
                  <span className={`${
                    v.prediction === 'phishing' ? 'text-red-400' :
                    v.prediction === 'spam'     ? 'text-orange-400' : 'text-green-400'
                  }`}>
                    pred: {v.prediction}
                  </span>
                  <span className="text-gray-500">{(v.confidence * 100).toFixed(1)}% conf</span>
                </div>
                <p className="text-gray-400 break-all line-clamp-2">{v.text}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
