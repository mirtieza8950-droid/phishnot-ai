import { useState, useRef, useEffect } from 'react';
import { scanImage, aiThinking, askAnalyst, downloadReport, submitFeedback } from '../api/phishguard';
import VerdictBanner from '../components/VerdictBanner';
import RiskGauge from '../components/RiskGauge';
import Probabilities from '../components/Probabilities';
import ModelVotingLog from '../components/ModelVotingLog';
import AIReasoning from '../components/AIReasoning';
import LimeWords from '../components/LimeWords';
import AIThinkingCard from '../components/AIThinkingCard';
import AnalystChatBox from '../components/AnalystChatBox';
import { useReveal } from '../hooks/useReveal';

function QRResults({ qr }) {
  const ref = useReveal();
  if (!qr || (!qr.found && !qr.warning)) return null;
  return (
    <div ref={ref} className="glass-card p-4 col-span-full">
      <h4 className="text-xs uppercase tracking-wider opacity-60 mb-2">QR Code Detection</h4>
      {qr.warning && <div className="text-xs text-orange-400 mb-2">{qr.warning}</div>}
      {qr.codes?.map((c, i) => (
        <div key={i} className="text-xs bg-black/30 rounded px-3 py-2 mb-1">
          <span className="text-purple-400 font-bold mr-2">[{c.type}]</span>
          <span className="text-gray-300 font-mono break-all">{c.data}</span>
        </div>
      ))}
    </div>
  );
}

export default function ScanImage() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [thinking, setThinking] = useState(null);
  const [chatAnswer, setChatAnswer] = useState('');
  const [preview, setPreview] = useState(null);
  const chatInputRef = useRef(null);
  const fileInputRef = useRef(null);
  const dropRef = useRef(null);

  useEffect(() => {
    if (result) {
      const pred = (result.prediction || '').toLowerCase();
      document.body.classList.remove('verdict-ham', 'verdict-spam', 'verdict-phishing', 'verdict-legitimate', 'verdict-suspicious');
      if (pred) document.body.classList.add('verdict-' + pred);
    }
    return () => {
      document.body.classList.remove('verdict-ham', 'verdict-spam', 'verdict-phishing', 'verdict-legitimate', 'verdict-suspicious');
    };
  }, [result]);

  const processFile = async (file) => {
    if (!file) return;
    setPreview(URL.createObjectURL(file));
    setLoading(true);
    setResult(null);
    setThinking(null);
    setChatAnswer('');
    try {
      const data = await scanImage(file);
      setResult(data);
      if (data.extracted_text) {
        setThinking('');
        aiThinking(data.extracted_text, data.prediction)
          .then(t => setThinking(t.thinking || 'Analysis not available.'))
          .catch(() => setThinking('AI analysis unavailable.'));
      }
    } catch (err) { alert(err.message); }
    finally { setLoading(false); }
  };

  const onDrop = (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file && file.type.startsWith('image/')) processFile(file);
  };

  const handleAsk = async () => {
    const q = chatInputRef.current?.value?.trim();
    if (!q || !result) return;
    setChatAnswer('Thinking...');
    try {
      const res = await askAnalyst({ prediction: result.prediction, confidence: result.confidence,
        model_predictions: result.model_predictions, reasoning: result.reasoning,
        text: result.extracted_text || '', question: q });
      setChatAnswer(res.answer || 'No answer.');
    } catch { setChatAnswer('Error contacting AI.'); }
  };

  const handleReport = async () => {
    if (!result) return;
    try {
      const blob = await downloadReport({ prediction: result.prediction, confidence: result.confidence,
        model_predictions: result.model_predictions, reasoning: result.reasoning, scan_id: result.scan_id || '' });
      const u = URL.createObjectURL(blob);
      Object.assign(document.createElement('a'), { href: u, download: `report_img_${Date.now()}.pdf` }).click();
    } catch { alert('Report generation failed.'); }
  };

  const handleFeedback = async () => {
    if (!result) return;
    const label = prompt('Correct label? (ham/spam/phishing/legitimate)');
    if (!label) return;
    try {
      await submitFeedback({ scan_id: result.scan_id, user_label: label,
        model_prediction: result.prediction, input_text: result.extracted_text || '', input_type: 'image' });
      alert('Feedback saved!');
    } catch { alert('Feedback failed.'); }
  };

  const textRef = useReveal();

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-6">
      <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Screenshot Analyzer</h2>

      <div ref={dropRef}
        onClick={() => fileInputRef.current?.click()}
        onDrop={onDrop}
        onDragOver={e => e.preventDefault()}
        className="w-full border-2 border-dashed border-gray-700 rounded-xl p-8 text-center cursor-pointer hover:border-purple-500 transition-colors"
        style={{ minHeight: 160 }}>
        {preview ? (
          <img src={preview} alt="Preview" className="max-h-48 mx-auto rounded-lg object-contain" />
        ) : (
          <div className="text-gray-500 select-none">
            <div className="text-5xl mb-3 opacity-40">+</div>
            <div className="text-base">Click to upload or drag & drop screenshot</div>
            <div className="text-sm mt-1 opacity-60">PNG, JPG, WEBP, BMP</div>
          </div>
        )}
      </div>
      <input ref={fileInputRef} type="file" accept="image/*"
        onChange={e => processFile(e.target.files[0])} className="hidden" />

      {loading && <div className="text-center text-gray-400 animate-pulse">Running OCR + Neural Analysis...</div>}

      {result && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {result.extracted_text && (
            <div ref={textRef} className="glass-card p-4 col-span-full">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs uppercase tracking-wider opacity-60">Extracted Text</h4>
                <span className="text-xs text-gray-500">{result.char_count} chars</span>
              </div>
              <pre className="text-xs text-gray-300 bg-black/30 p-3 rounded-lg max-h-36 overflow-y-auto whitespace-pre-wrap break-words font-mono">
                {result.extracted_text}
              </pre>
            </div>
          )}

          <QRResults qr={result.qr_detection} />

          <VerdictBanner prediction={result.prediction} />
          <RiskGauge score={result.reasoning?.risk_score ?? Math.round(result.confidence * 100)}
            level={result.reasoning?.risk_level ?? 'N/A'} />
          <Probabilities probs={result.all_probabilities} />
          <ModelVotingLog votes={result.model_predictions} />
          <div className="col-span-full"><AIReasoning reasoning={result.reasoning} /></div>
          {result.explanation?.length > 0 && (
            <div className="col-span-full"><LimeWords explanation={result.explanation} /></div>
          )}

          <div className="col-span-full flex flex-wrap items-center gap-3 text-sm">
            <span className="text-gray-400">Accurate?</span>
            <button onClick={() => submitFeedback({ scan_id: result.scan_id, user_label: result.prediction,
              model_prediction: result.prediction, input_text: result.extracted_text || '', input_type: 'image' })
              .then(() => alert('Thanks!')).catch(() => alert('Failed.'))}
              className="px-3 py-1 rounded bg-green-900/30 text-green-400 hover:bg-green-900/50 text-xs font-semibold">Yes</button>
            <button onClick={handleFeedback} className="px-3 py-1 rounded bg-red-900/30 text-red-400 hover:bg-red-900/50 text-xs font-semibold">No</button>
            <button onClick={handleReport} className="ml-auto px-3 py-1 rounded bg-purple-600 text-white text-xs font-semibold hover:bg-purple-700">Download Report</button>
          </div>

          {thinking && <div className="col-span-full"><AIThinkingCard thinking={thinking} /></div>}
          <div className="col-span-full"><AnalystChatBox answer={chatAnswer} onAsk={handleAsk} inputRef={chatInputRef} /></div>
        </div>
      )}
    </div>
  );
}
