import { useState } from 'react';
import { analyzeSms, analyzeDeeplink, analyzeMobileUrl } from '../api/phishguard';
import { useReveal } from '../hooks/useReveal';

// ── Shared styles ─────────────────────────────────────────────────────────────

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
  s >= 8 ? 'text-red-400' : s >= 6 ? 'text-orange-400' : s >= 4 ? 'text-yellow-400' : s >= 2 ? 'text-blue-400' : 'text-green-400';

// ── Shared sub-components ─────────────────────────────────────────────────────

function ScoreCard({ score, threatType, children }) {
  const revealCard = useReveal();
  return (
    <div ref={revealCard} className="glass-card p-5 flex flex-wrap gap-6 items-center">
      <div className="text-center min-w-[4rem]">
        <p className={`text-5xl font-black ${SCORE_COLOR(score)}`}>{score}/10</p>
        <p className="text-xs text-gray-500 uppercase tracking-wide mt-1">Risk Score</p>
      </div>
      {threatType && (
        <span className={`self-start px-3 py-1.5 rounded-full border text-sm font-semibold ${
          score >= 7 ? 'bg-red-900/50 text-red-300 border-red-700' :
          score >= 4 ? 'bg-orange-900/50 text-orange-300 border-orange-700' :
                       'bg-gray-800 text-gray-300 border-gray-700'
        }`}>
          {threatType}
        </span>
      )}
      {children}
    </div>
  );
}

function FindingList({ findings }) {
  if (!findings?.length) return <p className="text-green-400 text-sm">No suspicious indicators detected.</p>;
  return (
    <div className="space-y-2">
      {findings.map((f, i) => (
        <div key={i} className={`p-3 rounded-lg ${SEV_BORDER[f.severity] || SEV_BORDER.low}`}>
          <div className="flex items-start gap-2">
            <p className="font-bold text-sm flex-1">{f.title}</p>
            <span className={`shrink-0 text-xs px-2 py-0.5 rounded font-semibold ${SEV_BADGE[f.severity] || SEV_BADGE.low}`}>
              {f.severity}
            </span>
          </div>
          <p className="text-xs mt-1 opacity-80 leading-relaxed">{f.detail}</p>
        </div>
      ))}
    </div>
  );
}

function Recs({ items }) {
  if (!items?.length) return null;
  return (
    <div className="space-y-2">
      {items.map((r, i) => (
        <div key={i} className="flex gap-2 text-sm text-yellow-300/90">
          <span className="shrink-0 text-yellow-500 mt-0.5">→</span>
          <p className="leading-relaxed">{r}</p>
        </div>
      ))}
    </div>
  );
}

function AnalyzeButton({ loading, disabled, onClick, label, loadingLabel = 'Analyzing…' }) {
  return (
    <button onClick={onClick} disabled={loading || disabled}
      className="w-full sm:w-auto px-6 py-3 bg-purple-700 hover:bg-purple-600 active:bg-purple-800 text-white font-bold rounded-xl text-sm disabled:opacity-50 transition touch-manipulation min-h-[48px]">
      {loading ? (
        <span className="flex items-center justify-center gap-2">
          <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
          {loadingLabel}
        </span>
      ) : label}
    </button>
  );
}

// ── SMS / Smishing tab ────────────────────────────────────────────────────────

function SmsTab() {
  const revealInput  = useReveal();
  const revealResult = useReveal();
  const [text,    setText]    = useState('');
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState('');

  const analyze = async () => {
    if (!text.trim()) return;
    setLoading(true); setResult(null); setError('');
    try {
      setResult(await analyzeSms(text));
    } catch (e) {
      setError(e.message || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      <div ref={revealInput} className="glass-card p-5 space-y-4">
        <p className="text-xs text-gray-500 leading-relaxed">
          Paste the full SMS / iMessage text. Detects delivery scams, bank impersonation,
          OTP relay attacks, prize fraud, urgency manipulation, and URL shortener abuse.
        </p>
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          rows={5}
          placeholder={"Your USPS package is on hold. Update delivery details:\nhttps://bit.ly/3xQp2k"}
          className="w-full bg-black/30 border border-gray-600 rounded-xl p-3 text-white text-sm placeholder-gray-600 resize-y leading-relaxed"
          disabled={loading}
        />
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <AnalyzeButton loading={loading} disabled={!text.trim()} onClick={analyze} label="Analyze SMS" />
          {text && !loading && (
            <button onClick={() => { setText(''); setResult(null); }}
              className="text-sm text-gray-500 hover:text-gray-300 py-2 touch-manipulation">
              Clear
            </button>
          )}
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      {result && (
        <div className="space-y-4">
          <ScoreCard score={result.risk_score} threatType={result.threat_type}>
            {result.indicators?.impersonated_brand && (
              <div className="text-center">
                <p className="text-sm font-bold text-red-300">{result.indicators.impersonated_brand}</p>
                <p className="text-xs text-gray-500">Impersonated Brand</p>
              </div>
            )}
            <div className="flex gap-4 flex-wrap">
              {[
                { label: 'URLs', value: result.url_count, warn: result.url_count > 0 },
                { label: 'Shorteners', value: result.indicators?.has_url_shortener ? '✓' : '—', warn: result.indicators?.has_url_shortener },
                { label: 'OTP Theft', value: result.indicators?.otp_theft_attempt ? '⚠' : '—', warn: result.indicators?.otp_theft_attempt },
              ].map(({ label, value, warn }) => (
                <div key={label} className="text-center">
                  <p className={`text-lg font-black ${warn ? 'text-red-400' : 'text-gray-500'}`}>{value}</p>
                  <p className="text-xs text-gray-500">{label}</p>
                </div>
              ))}
            </div>
          </ScoreCard>

          {result.urls_found?.length > 0 && (
            <div ref={useReveal()} className="glass-card p-5 space-y-2">
              <h3 className="text-sm font-bold text-white">URLs in Message</h3>
              {result.urls_found.map((u, i) => (
                <p key={i} className="text-xs font-mono text-gray-400 break-all bg-black/20 p-2 rounded-lg">{u}</p>
              ))}
            </div>
          )}

          <div ref={useReveal()} className="glass-card p-5 space-y-3">
            <h3 className="text-sm font-bold text-white">Findings ({result.findings?.length ?? 0})</h3>
            <FindingList findings={result.findings} />
          </div>

          {result.recommendations?.length > 0 && (
            <div ref={useReveal()} className="glass-card p-5 space-y-3">
              <h3 className="text-sm font-bold text-white">What To Do</h3>
              <Recs items={result.recommendations} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Deep Link tab ─────────────────────────────────────────────────────────────

function DeepLinkTab() {
  const revealInput  = useReveal();
  const revealResult = useReveal();
  const [link,    setLink]    = useState('');
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState('');

  const analyze = async () => {
    if (!link.trim()) return;
    setLoading(true); setResult(null); setError('');
    try {
      setResult(await analyzeDeeplink(link));
    } catch (e) {
      setError(e.message || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      <div ref={revealInput} className="glass-card p-5 space-y-4">
        <p className="text-xs text-gray-500 leading-relaxed">
          Paste any deep link or URI — <code className="font-mono bg-black/30 px-1 rounded">intent://</code>,
          {' '}<code className="font-mono bg-black/30 px-1 rounded">market://</code>,
          {' '}<code className="font-mono bg-black/30 px-1 rounded">javascript:</code>,
          {' '}custom app schemes, or HTTPS universal links.
        </p>
        <input
          value={link}
          onChange={e => setLink(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !loading && analyze()}
          placeholder="intent://scan/#Intent;scheme=zxing;package=com.evil.app;end"
          className="w-full bg-black/30 border border-gray-600 rounded-xl p-3 text-white text-sm placeholder-gray-600 font-mono"
          disabled={loading}
        />
        <AnalyzeButton loading={loading} disabled={!link.trim()} onClick={analyze} label="Analyze Deep Link" />
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      {result && (
        <div ref={revealResult} className="space-y-4">
          <ScoreCard score={result.risk_score} threatType={result.threat_type}>
            <div className="text-center">
              <p className="text-lg font-bold font-mono text-purple-300">{result.scheme}://</p>
              <p className="text-xs text-gray-500">Scheme</p>
            </div>
          </ScoreCard>

          <div className="glass-card p-5 space-y-3">
            <h3 className="text-sm font-bold text-white">Findings ({result.findings?.length ?? 0})</h3>
            <FindingList findings={result.findings} />
          </div>

          {result.recommendations?.length > 0 && (
            <div className="glass-card p-5 space-y-3">
              <h3 className="text-sm font-bold text-white">What To Do</h3>
              <Recs items={result.recommendations} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Mobile URL tab ────────────────────────────────────────────────────────────

function MobileUrlTab() {
  const revealInput  = useReveal();
  const revealResult = useReveal();
  const [url,     setUrl]     = useState('');
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState('');

  const analyze = async () => {
    if (!url.trim()) return;
    setLoading(true); setResult(null); setError('');
    try {
      setResult(await analyzeMobileUrl(url));
    } catch (e) {
      setError(e.message || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      <div ref={revealInput} className="glass-card p-5 space-y-4">
        <p className="text-xs text-gray-500 leading-relaxed">
          Analyze a URL for mobile-specific phishing patterns: URL shorteners, high-risk TLDs,
          brand-as-subdomain tricks, smishing keyword combinations, and Darcula/PhaaS landing-page indicators.
        </p>
        <input
          value={url}
          onChange={e => setUrl(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !loading && analyze()}
          placeholder="https://usps.package-update.xyz/confirm"
          className="w-full bg-black/30 border border-gray-600 rounded-xl p-3 text-white text-sm placeholder-gray-600"
          disabled={loading}
        />
        <AnalyzeButton loading={loading} disabled={!url.trim()} onClick={analyze} label="Analyze URL" />
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      {result && (
        <div ref={revealResult} className="space-y-4">
          <ScoreCard score={result.risk_score} threatType={result.threat_type}>
            <p className="text-xs font-mono text-gray-500 break-all max-w-xs">{result.url}</p>
          </ScoreCard>

          <div className="glass-card p-5 space-y-3">
            <h3 className="text-sm font-bold text-white">Findings ({result.findings?.length ?? 0})</h3>
            <FindingList findings={result.findings} />
          </div>

          {result.recommendations?.length > 0 && (
            <div className="glass-card p-5 space-y-3">
              <h3 className="text-sm font-bold text-white">What To Do</h3>
              <Recs items={result.recommendations} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'sms',      label: '💬 SMS / Smishing'  },
  { id: 'deeplink', label: '🔗 Deep Link'        },
  { id: 'url',      label: '📱 Mobile URL'       },
];

export default function MobilePhishing() {
  const [tab, setTab] = useState('sms');

  return (
    <div className="max-w-2xl mx-auto px-4 py-6 space-y-6">
      <div>
        <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>Mobile Phishing Detection</h2>
        <p className="text-gray-500 text-sm mt-1 leading-relaxed">
          Detects SMS/smishing attacks, Android intent and app-scheme abuse,
          and mobile-optimized phishing URL patterns. Fully usable on mobile browsers.
        </p>
      </div>

      {/* Tab bar — touch-friendly */}
      <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-hide">
        {TABS.map(({ id, label }) => (
          <button key={id} onClick={() => setTab(id)}
            className={`shrink-0 px-4 py-2.5 rounded-xl font-semibold text-sm transition touch-manipulation min-h-[44px] ${
              tab === id ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700 active:bg-gray-600'
            }`}>
            {label}
          </button>
        ))}
      </div>

      {tab === 'sms'      && <SmsTab />}
      {tab === 'deeplink' && <DeepLinkTab />}
      {tab === 'url'      && <MobileUrlTab />}
    </div>
  );
}
