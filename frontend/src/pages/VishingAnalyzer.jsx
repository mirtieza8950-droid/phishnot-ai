import { useState, useRef, useEffect, useCallback } from 'react';
import { uploadVishingAudio, getVishingStatus, getVishingResult } from '../api/phishguard';
import { useReveal } from '../hooks/useReveal';

// ── Style maps ────────────────────────────────────────────────────────────────

const SEV_BORDER = {
  critical: 'border-l-4 border-red-600 bg-red-950/20 text-red-300',
  high:     'border-l-4 border-orange-600 bg-orange-950/20 text-orange-300',
  medium:   'border-l-4 border-yellow-600 bg-yellow-950/20 text-yellow-300',
  low:      'border-l-4 border-gray-600 bg-gray-900/20 text-gray-400',
};
const SEV_BADGE = {
  critical: 'bg-red-900/60 text-red-300 border border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border border-orange-700',
  medium:   'bg-yellow-900/40 text-yellow-300 border border-yellow-700',
  low:      'bg-gray-800 text-gray-400 border border-gray-700',
};
const SCORE_COLOR = s =>
  s >= 8 ? 'text-red-400' : s >= 6 ? 'text-orange-400' : s >= 4 ? 'text-yellow-400' : 'text-green-400';

const ACCEPT = '.wav,.mp3,.m4a,.ogg,.flac,.webm,.mp4,.aac,.opus';

// ── Highlighted transcript ────────────────────────────────────────────────────

function HighlightedTranscript({ text, phrases }) {
  if (!text) return null;

  if (!phrases?.length) {
    return <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">{text}</p>;
  }

  // Build a sorted list of non-overlapping match ranges
  const ranges = [];
  for (const phrase of phrases) {
    try {
      const re = new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      let m;
      while ((m = re.exec(text)) !== null) {
        const overlaps = ranges.some(r => m.index < r.end && m.index + m[0].length > r.start);
        if (!overlaps) ranges.push({ start: m.index, end: m.index + m[0].length, phrase: m[0] });
      }
    } catch (_) {}
  }
  ranges.sort((a, b) => a.start - b.start);

  const parts = [];
  let cursor = 0;
  for (const { start, end, phrase } of ranges) {
    if (start > cursor) parts.push(<span key={cursor}>{text.slice(cursor, start)}</span>);
    parts.push(
      <mark key={start} className="bg-red-900/50 text-red-200 rounded px-0.5 not-italic font-semibold">
        {phrase}
      </mark>
    );
    cursor = end;
  }
  if (cursor < text.length) parts.push(<span key={cursor}>{text.slice(cursor)}</span>);

  return (
    <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">{parts}</p>
  );
}

// ── File drop zone ────────────────────────────────────────────────────────────

function DropZone({ onFile, disabled }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragging(false);
    if (disabled) return;
    const file = e.dataTransfer.files[0];
    if (file) onFile(file);
  }, [disabled, onFile]);

  return (
    <div
      onDragOver={e => { e.preventDefault(); if (!disabled) setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => !disabled && inputRef.current?.click()}
      className={`relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
        disabled   ? 'opacity-40 cursor-not-allowed' :
        dragging   ? 'border-purple-400 bg-purple-900/20' :
                     'border-gray-600 hover:border-gray-400 hover:bg-gray-800/30'
      }`}
    >
      <input ref={inputRef} type="file" accept={ACCEPT} className="hidden"
        onChange={e => { const f = e.target.files?.[0]; if (f) onFile(f); e.target.value = ''; }} />
      <div className="text-4xl mb-3">🎙️</div>
      <p className="text-gray-300 font-semibold text-sm">
        {dragging ? 'Drop audio here' : 'Drop audio file or click to browse'}
      </p>
      <p className="text-gray-600 text-xs mt-1">WAV · MP3 · M4A · OGG · FLAC · WEBM · MP4 · max 25 MB</p>
    </div>
  );
}

// ── Browser recorder ──────────────────────────────────────────────────────────

function Recorder({ onRecording, disabled }) {
  const [recording,   setRecording]   = useState(false);
  const [elapsed,     setElapsed]     = useState(0);
  const [supported,   setSupported]   = useState(true);
  const [error,       setError]       = useState('');
  const mediaRef  = useRef(null);
  const timerRef  = useRef(null);
  const chunksRef = useRef([]);

  useEffect(() => {
    if (!navigator.mediaDevices?.getUserMedia) setSupported(false);
    return () => {
      clearInterval(timerRef.current);
      mediaRef.current?.stream?.getTracks().forEach(t => t.stop());
    };
  }, []);

  const startRec = async () => {
    setError('');
    chunksRef.current = [];
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const rec = new MediaRecorder(stream);
      rec.ondataavailable = e => { if (e.data.size > 0) chunksRef.current.push(e.data); };
      rec.onstop = () => {
        stream.getTracks().forEach(t => t.stop());
        const blob = new Blob(chunksRef.current, { type: 'audio/webm' });
        const file = new File([blob], `recording_${Date.now()}.webm`, { type: 'audio/webm' });
        onRecording(file);
      };
      rec.start(250);
      mediaRef.current = { rec, stream };
      setRecording(true);
      setElapsed(0);
      timerRef.current = setInterval(() => setElapsed(p => p + 1), 1000);
    } catch (e) {
      setError('Microphone access denied. Allow microphone permission in your browser.');
    }
  };

  const stopRec = () => {
    clearInterval(timerRef.current);
    mediaRef.current?.rec?.stop();
    setRecording(false);
  };

  if (!supported) return (
    <p className="text-xs text-gray-600">Live recording is not supported in this browser.</p>
  );

  const fmt = s => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;

  return (
    <div className="space-y-3">
      {recording ? (
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-red-400">
            <span className="animate-pulse h-3 w-3 rounded-full bg-red-500" />
            <span className="text-sm font-bold font-mono">{fmt(elapsed)}</span>
            <span className="text-xs text-gray-500">Recording…</span>
          </div>
          <button onClick={stopRec}
            className="px-4 py-2 bg-red-700 hover:bg-red-600 text-white font-bold rounded-lg text-sm transition touch-manipulation">
            Stop & Analyze
          </button>
        </div>
      ) : (
        <button onClick={startRec} disabled={disabled}
          className="flex items-center gap-2 px-5 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 font-semibold rounded-lg text-sm disabled:opacity-50 transition touch-manipulation min-h-[44px]">
          <span>🎤</span> Record Live Call
        </button>
      )}
      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function VishingAnalyzer() {
  const [file,       setFile]       = useState(null);
  const [jobId,      setJobId]      = useState(null);
  const [processing, setProcessing] = useState(false);
  const [elapsed,    setElapsed]    = useState(0);
  const [result,     setResult]     = useState(null);
  const [error,      setError]      = useState('');
  const [showFull,   setShowFull]   = useState(false);
  const pollRef  = useRef(null);
  const timerRef = useRef(null);

  const revealInput   = useReveal();
  const revealRecord  = useReveal();
  const revealScore   = useReveal();
  const revealTranscript = useReveal();
  const revealFindings   = useReveal();
  const revealEntities   = useReveal();
  const revealRecs       = useReveal();

  useEffect(() => () => {
    clearInterval(pollRef.current);
    clearInterval(timerRef.current);
  }, []);

  const startPoll = (jid) => {
    setElapsed(0);
    timerRef.current = setInterval(() => setElapsed(p => p + 1), 1000);
    pollRef.current  = setInterval(async () => {
      try {
        const status = await getVishingStatus(jid);
        if (status.status === 'done') {
          clearInterval(pollRef.current);
          clearInterval(timerRef.current);
          const data = await getVishingResult(jid);
          setResult(data);
          setProcessing(false);
        } else if (status.status === 'error') {
          clearInterval(pollRef.current);
          clearInterval(timerRef.current);
          setError(status.error || 'Transcription failed');
          setProcessing(false);
        }
      } catch (e) {
        clearInterval(pollRef.current);
        clearInterval(timerRef.current);
        setError(e.message);
        setProcessing(false);
      }
    }, 2500);
  };

  const handleFile = (f) => {
    setFile(f);
    setResult(null);
    setError('');
  };

  const handleAnalyze = async () => {
    if (!file) return;
    setProcessing(true);
    setResult(null);
    setError('');
    try {
      const { job_id } = await uploadVishingAudio(file);
      setJobId(job_id);
      startPoll(job_id);
    } catch (e) {
      setError(e.message || 'Upload failed');
      setProcessing(false);
    }
  };

  const findings   = result?.findings   ?? [];
  const entities   = result?.entities   ?? {};
  const phrases    = result?.matched_phrases ?? [];
  const recs       = result?.recommendations ?? [];
  const transcript = result?.transcript ?? '';
  const hasEntities = (entities.phone_numbers?.length || entities.dollar_amounts?.length || entities.urls_mentioned?.length);

  const reset = () => { setFile(null); setResult(null); setError(''); setJobId(null); };

  return (
    <div className="max-w-4xl mx-auto p-4 sm:p-6 space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Vishing Analyzer</h2>
        <p className="text-gray-500 text-sm mt-1 leading-relaxed">
          Upload a suspicious call recording or record directly in your browser.
          Whisper transcribes the audio; the engine detects IRS scams, tech-support fraud,
          bank impersonation, gift-card demands, arrest threats, and more.
        </p>
      </div>

      {/* Input section */}
      <div ref={revealInput} className="glass-card p-6 space-y-5">
        <DropZone onFile={handleFile} disabled={processing} />

        {/* Divider */}
        <div className="flex items-center gap-3">
          <div className="flex-1 h-px bg-gray-700" />
          <span className="text-xs text-gray-600 uppercase tracking-widest">or</span>
          <div className="flex-1 h-px bg-gray-700" />
        </div>

        <div ref={revealRecord}>
          <Recorder onRecording={handleFile} disabled={processing} />
        </div>

        {/* Selected file info */}
        {file && (
          <div className="flex items-center gap-3 bg-black/20 rounded-lg px-4 py-3">
            <span className="text-2xl">🎵</span>
            <div className="flex-1 min-w-0">
              <p className="text-sm text-white font-semibold truncate">{file.name}</p>
              <p className="text-xs text-gray-500">{(file.size / 1024).toFixed(0)} KB</p>
            </div>
            <button onClick={reset} className="text-gray-500 hover:text-gray-300 text-sm px-2">✕</button>
          </div>
        )}

        {error && (
          <div className="bg-red-950/30 border border-red-800 rounded-lg p-4">
            <p className="text-red-400 text-sm font-semibold mb-1">Error</p>
            <p className="text-red-300 text-xs leading-relaxed whitespace-pre-wrap">{error}</p>
          </div>
        )}

        <button onClick={handleAnalyze} disabled={processing || !file}
          className="w-full py-3.5 bg-purple-700 hover:bg-purple-600 text-white font-bold rounded-xl text-sm disabled:opacity-50 transition touch-manipulation min-h-[48px]">
          {processing ? (
            <span className="flex items-center justify-center gap-3">
              <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
              Transcribing… ({elapsed}s)
            </span>
          ) : 'Transcribe & Analyze'}
        </button>

        {processing && (
          <p className="text-center text-xs text-gray-500">
            Transcription typically takes 10–30 seconds depending on audio length.
          </p>
        )}
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Score + threat type */}
          <div ref={revealScore} className="glass-card p-6 flex flex-wrap gap-8 items-center">
            <div className="text-center">
              <p className={`text-5xl font-black ${SCORE_COLOR(result.risk_score)}`}>
                {result.risk_score}/10
              </p>
              <p className="text-xs text-gray-500 uppercase tracking-wide mt-1">Risk Score</p>
            </div>
            {result.threat_type && (
              <span className={`px-4 py-1.5 rounded-full border text-sm font-bold ${
                result.risk_score >= 7 ? 'bg-red-900/50 text-red-300 border-red-700' :
                result.risk_score >= 4 ? 'bg-orange-900/50 text-orange-300 border-orange-700' :
                                         'bg-gray-800 text-gray-300 border-gray-700'
              }`}>
                {result.threat_type}
              </span>
            )}
            <div className="ml-auto text-right text-xs text-gray-600 space-y-0.5">
              {result.transcription_time_s && <p>Transcribed in {result.transcription_time_s}s</p>}
              {result.transcript_length    && <p>{result.transcript_length} characters</p>}
            </div>
          </div>

          {/* Two-col: findings + entities */}
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
            {/* Findings — wider column */}
            <div ref={revealFindings} className="glass-card p-6 space-y-3 lg:col-span-3">
              <h3 className="text-base font-bold text-white">
                Findings <span className="text-gray-500 font-normal text-sm">({findings.length})</span>
              </h3>
              {findings.length === 0 ? (
                <p className="text-green-400 text-sm">No vishing indicators detected.</p>
              ) : (
                <div className="space-y-2">
                  {findings.map((f, i) => (
                    <div key={i} className={`p-3 rounded-lg ${SEV_BORDER[f.severity] || SEV_BORDER.low}`}>
                      <div className="flex items-start gap-2 mb-1">
                        <p className="font-bold text-sm flex-1">{f.title}</p>
                        <span className={`shrink-0 text-xs px-2 py-0.5 rounded font-semibold ${SEV_BADGE[f.severity] || SEV_BADGE.low}`}>
                          {f.severity}
                        </span>
                      </div>
                      <p className="text-xs opacity-80 leading-relaxed">{f.detail}</p>
                      {f.matched_phrases?.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {f.matched_phrases.map((p, j) => (
                            <span key={j} className="text-xs bg-black/30 text-gray-400 font-mono px-1.5 py-0.5 rounded">
                              "{p}"
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Entities — narrower column */}
            <div ref={revealEntities} className="glass-card p-6 space-y-4 lg:col-span-2">
              <h3 className="text-base font-bold text-white">Entities Detected</h3>
              {!hasEntities ? (
                <p className="text-gray-500 text-sm">No notable entities extracted.</p>
              ) : (
                <>
                  {entities.phone_numbers?.length > 0 && (
                    <EntityGroup icon="📞" label="Phone Numbers" items={entities.phone_numbers} />
                  )}
                  {entities.dollar_amounts?.length > 0 && (
                    <EntityGroup icon="💰" label="Amounts Mentioned" items={entities.dollar_amounts} warn />
                  )}
                  {entities.urls_mentioned?.length > 0 && (
                    <EntityGroup icon="🔗" label="URLs in Call" items={entities.urls_mentioned} warn />
                  )}
                </>
              )}
            </div>
          </div>

          {/* Transcript */}
          <div ref={revealTranscript} className="glass-card p-6 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white">Transcript</h3>
              <div className="flex items-center gap-3">
                {phrases.length > 0 && (
                  <span className="text-xs text-gray-500">{phrases.length} phrase(s) highlighted</span>
                )}
                <button onClick={() => setShowFull(v => !v)}
                  className="text-xs text-purple-400 hover:text-purple-300">
                  {showFull ? 'Collapse' : 'Expand'}
                </button>
              </div>
            </div>
            <div className={`bg-black/30 rounded-xl p-4 overflow-y-auto transition-all ${showFull ? '' : 'max-h-48'}`}>
              <HighlightedTranscript text={transcript} phrases={phrases} />
            </div>
          </div>

          {/* Recommendations */}
          {recs.length > 0 && (
            <div ref={revealRecs} className="glass-card p-6 space-y-3">
              <h3 className="text-base font-bold text-white">What To Do</h3>
              <div className="space-y-2.5">
                {recs.map((r, i) => (
                  <div key={i} className="flex gap-2.5 text-sm text-yellow-300/90">
                    <span className="shrink-0 text-yellow-500 mt-0.5">→</span>
                    <p className="leading-relaxed">{r}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function EntityGroup({ icon, label, items, warn = false }) {
  return (
    <div className="space-y-1.5">
      <p className="text-xs text-gray-500 uppercase tracking-wide font-semibold">{icon} {label}</p>
      {items.map((item, i) => (
        <p key={i} className={`text-xs font-mono break-all px-2 py-1 rounded bg-black/20 ${warn ? 'text-orange-300' : 'text-gray-300'}`}>
          {item}
        </p>
      ))}
    </div>
  );
}
