import { useState, useRef, useEffect, useCallback } from 'react';
import { scanEmail, aiThinking, askAnalyst, downloadReport, submitFeedback } from '../api/phishguard';
import VerdictBanner from '../components/VerdictBanner';
import RiskGauge from '../components/RiskGauge';
import Probabilities from '../components/Probabilities';
import ModelVotingLog from '../components/ModelVotingLog';
import AIReasoning from '../components/AIReasoning';
import LimeWords from '../components/LimeWords';
import AIThinkingCard from '../components/AIThinkingCard';
import AnalystChatBox from '../components/AnalystChatBox';

export default function ScanEmail() {
  const [text, setText] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [thinking, setThinking] = useState(null);   // null=not started, ''=loading, string=done
  const [chatAnswer, setChatAnswer] = useState('');
  const chatInputRef = useRef(null);
  const emlInputRef = useRef(null);

  const handleEmlUpload = useCallback((e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => setText(evt.target.result || '');
    reader.readAsText(file, 'utf-8');
    e.target.value = '';  // allow re-upload of same file
  }, []);

  useEffect(() => {
    if (result) {
      const pred = (result.prediction || '').toLowerCase();
      document.body.classList.remove('verdict-ham','verdict-spam','verdict-phishing','verdict-legitimate','verdict-suspicious');
      if (pred) document.body.classList.add('verdict-' + pred);
    }
    return () => {
      document.body.classList.remove('verdict-ham','verdict-spam','verdict-phishing','verdict-legitimate','verdict-suspicious');
    };
  }, [result]);

  const handleScan = async () => {
    setLoading(true);
    setResult(null);
    setThinking(null);
    setChatAnswer('');
    try {
      const data = await scanEmail(text);
      setResult(data);
      setThinking('');  // show loading state
      aiThinking(text, data.prediction)
        .then(t => setThinking(t.thinking || 'Analysis not available.'))
        .catch(() => setThinking('AI analysis unavailable. Check local model or API key.'));
    } catch (e) { alert(e.message); }
    finally { setLoading(false); }
  };

  const handleAsk = async () => {
    const question = chatInputRef.current?.value?.trim();
    if (!question || !result) return;
    setChatAnswer('Thinking...');
    try {
      const payload = { prediction: result.prediction, confidence: result.confidence, model_predictions: result.model_predictions, explanation: result.explanation, reasoning: result.reasoning, text, question };
      const res = await askAnalyst(payload);
      setChatAnswer(res.answer || 'No answer received.');
    } catch (e) { setChatAnswer('Error contacting AI.'); }
  };

  const handleDownloadReport = async () => {
    if (!result) return;
    try {
      const blob = await downloadReport({ prediction: result.prediction, confidence: result.confidence, model_predictions: result.model_predictions, reasoning: result.reasoning, scan_id: result.scan_id || '' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `phishguard_report_${result.scan_id || Date.now()}.pdf`; a.click();
    } catch (e) { alert('Failed to generate report.'); }
  };

  const handleFeedback = async (type) => {
    if (!result) return;
    const userLabel = type === 'correct' ? result.prediction : prompt('What should it be? (ham/spam/phishing/legitimate)');
    if (!userLabel) return;
    try {
      await submitFeedback({ scan_id: result.scan_id, user_label: userLabel,
        model_prediction: result.prediction, input_text: text, input_type: 'email' });
      alert('Feedback saved. Thank you!');
    } catch { alert('Feedback submission failed.'); }
  };

  return (
    <div className="max-w-5xl mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Email Scanner</h2>
        <button onClick={() => emlInputRef.current?.click()}
          className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-semibold rounded-lg transition border border-gray-700">
          Upload .eml File
        </button>
        <input ref={emlInputRef} type="file" accept=".eml,.txt,message/rfc822"
          onChange={handleEmlUpload} className="hidden" />
      </div>
      <textarea value={text} onChange={e => setText(e.target.value)} rows={8}
        className="w-full bg-gray-900/80 border border-gray-700 rounded-xl p-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-accent font-mono text-sm"
        placeholder="Paste email content here, or upload a .eml file above..." />
      <button onClick={handleScan} disabled={loading || !text.trim()}
        className="w-full py-4 bg-purple-600 hover:bg-purple-700 text-white font-extrabold rounded-xl transition disabled:opacity-50">
        {loading ? 'Scanning...' : 'INITIATE NEURAL SCAN'}
      </button>

      {loading && <div className="text-center text-gray-400 mt-4 animate-pulse">Initializing Neural Defense...</div>}

      {result && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
          <VerdictBanner prediction={result.prediction} />
          <RiskGauge score={result.reasoning?.risk_score ?? Math.round(result.confidence * 100)} level={result.reasoning?.risk_level ?? 'N/A'} />
          <Probabilities probs={result.all_probabilities} />
          <ModelVotingLog votes={result.model_predictions} />
          <div className="col-span-full"><AIReasoning reasoning={result.reasoning} /></div>
          {result.explanation?.length > 0 && <div className="col-span-full"><LimeWords explanation={result.explanation} text={text} /></div>}
          <div className="col-span-full flex items-center gap-3 text-sm">
            <span className="text-gray-400">Was this accurate?</span>
            <button onClick={() => handleFeedback('correct')} className="px-3 py-1 rounded bg-green-900/30 text-green-400 hover:bg-green-900/50 text-xs font-semibold">Yes</button>
            <button onClick={() => handleFeedback('incorrect')} className="px-3 py-1 rounded bg-red-900/30 text-red-400 hover:bg-red-900/50 text-xs font-semibold">No</button>
            <button onClick={handleDownloadReport} className="ml-2 px-3 py-1 rounded bg-purple-600 text-white text-xs font-semibold hover:bg-purple-700">Download Report</button>
          </div>
          {thinking && <div className="col-span-full"><AIThinkingCard thinking={thinking} /></div>}
          <div className="col-span-full"><AnalystChatBox answer={chatAnswer} onAsk={handleAsk} inputRef={chatInputRef} /></div>
        </div>
      )}
    </div>
  );
}



