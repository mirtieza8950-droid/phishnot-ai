import { useState } from 'react';
import { analyzeOAuthUrl, analyzeOAuthEmail } from '../api/phishguard';
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
  s >= 8 ? 'text-red-400' : s >= 6 ? 'text-orange-400' : s >= 4 ? 'text-yellow-400' : s >= 2 ? 'text-blue-400' : 'text-green-400';
const THREAT_COLOR = t =>
  !t ? 'bg-green-900/40 text-green-300 border-green-700' :
  t.includes('AiTM') || t.includes('Hijack') ? 'bg-red-900/60 text-red-300 border-red-700' :
  'bg-orange-900/50 text-orange-300 border-orange-700';

// ── Shared sub-components ─────────────────────────────────────────────────────

function FindingList({ findings }) {
  if (!findings?.length) return <p className="text-green-400 text-sm">No suspicious indicators detected.</p>;
  return (
    <div className="space-y-2">
      {findings.map((f, i) => (
        <div key={i} className={`p-3 rounded-lg ${SEV_BORDER[f.severity] || SEV_BORDER.low}`}>
          <div className="flex items-center gap-2 mb-1">
            <p className="font-bold text-sm">{f.title}</p>
            <span className={`ml-auto text-xs px-2 py-0.5 rounded font-semibold ${SEV_BADGE[f.severity] || SEV_BADGE.low}`}>
              {f.severity}
            </span>
          </div>
          <p className="text-xs opacity-80">{f.detail}</p>
        </div>
      ))}
    </div>
  );
}

function Recommendations({ items }) {
  if (!items?.length) return null;
  return (
    <div className="space-y-1.5">
      {items.map((r, i) => (
        <div key={i} className="flex gap-2 text-sm text-yellow-300">
          <span className="shrink-0 text-yellow-500">→</span>
          <p>{r}</p>
        </div>
      ))}
    </div>
  );
}

// ── URL Analyzer ──────────────────────────────────────────────────────────────

function UrlAnalyzer() {
  const revealInput  = useReveal();
  const revealResult = useReveal();
  const [url,      setUrl]      = useState('');
  const [loading,  setLoading]  = useState(false);
  const [result,   setResult]   = useState(null);
  const [error,    setError]    = useState('');

  const analyze = async () => {
    const u = url.trim();
    if (!u) return;
    setLoading(true); setResult(null); setError('');
    try {
      setResult(await analyzeOAuthUrl(u));
    } catch (e) {
      setError(e.message || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const params = result?.oauth_params;

  return (
    <div className="space-y-5">
      {/* Input */}
      <div ref={revealInput} className="glass-card p-6 space-y-3">
        <p className="text-xs text-gray-500">
          Paste any URL — an OAuth authorization link, a callback with a <code className="font-mono">code=</code> parameter,
          or a link that may contain tokens.
        </p>
        <div className="flex gap-2">
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && !loading && analyze()}
            placeholder="https://accounts.googl3.com/o/oauth2/auth?scope=mail.readwrite&..."
            className="flex-1 bg-black/30 border border-gray-600 rounded-lg p-3 text-white text-sm placeholder-gray-600"
            disabled={loading}
          />
          <button onClick={analyze} disabled={loading || !url.trim()}
            className="px-6 py-3 bg-purple-700 hover:bg-purple-600 text-white font-bold rounded-lg text-sm disabled:opacity-50 transition">
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                Analyzing…
              </span>
            ) : 'Analyze'}
          </button>
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      {/* Results */}
      {result && (
        <div ref={revealResult} className="space-y-4">
          {/* Score + threat type */}
          <div className="glass-card p-6 flex flex-wrap gap-8 items-center">
            <div className="text-center">
              <p className={`text-5xl font-black ${SCORE_COLOR(result.risk_score)}`}>
                {result.risk_score}/10
              </p>
              <p className="text-xs text-gray-500 uppercase tracking-wide mt-1">Risk Score</p>
            </div>
            <div className="space-y-2">
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Threat Type</p>
                <span className={`px-3 py-1 rounded-full border text-sm font-semibold ${THREAT_COLOR(result.threat_type)}`}>
                  {result.threat_type || 'None detected'}
                </span>
              </div>
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Provider</p>
                <span className={`px-3 py-1 rounded-full border text-sm font-semibold ${
                  result.provider?.legitimate
                    ? 'bg-green-900/40 text-green-300 border-green-700'
                    : result.provider?.name
                      ? 'bg-red-900/40 text-red-300 border-red-700'
                      : 'bg-gray-800 text-gray-400 border-gray-700'
                }`}>
                  {result.provider?.name || 'Unknown / Not OAuth'}
                  {result.provider?.legitimate && ' ✓'}
                </span>
              </div>
            </div>
            <div className="ml-auto text-xs text-gray-600 max-w-xs break-all">{result.url}</div>
          </div>

          {/* Two-column: OAuth params + findings */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {/* OAuth Parameter Breakdown */}
            <div className="glass-card p-6 space-y-4">
              <h3 className="text-base font-bold text-white">OAuth Parameters</h3>
              {!result.is_oauth_url ? (
                <p className="text-gray-500 text-sm">No OAuth parameters detected in this URL.</p>
              ) : (
                <div className="space-y-3 text-sm">
                  {params?.response_type && (
                    <Row label="Response Type" value={params.response_type} />
                  )}
                  {params?.client_id && (
                    <Row label="Client ID" value={params.client_id} mono />
                  )}
                  {params?.redirect_uri && (
                    <Row label="Redirect URI"
                      value={params.redirect_uri}
                      warn={params.redirect_uri_flags?.length > 0}
                      mono />
                  )}
                  {params?.redirect_uri_flags?.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {params.redirect_uri_flags.map((f, i) => (
                        <span key={i} className="text-xs bg-orange-900/30 text-orange-300 border border-orange-800 rounded px-2 py-0.5">{f}</span>
                      ))}
                    </div>
                  )}
                  {params?.has_pkce && (
                    <Row label="PKCE" value="code_challenge present ✓" color="text-green-400" />
                  )}

                  {/* Scopes */}
                  {params?.all_scopes?.length > 0 && (
                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wide mb-2">Requested Scopes</p>
                      <div className="flex flex-wrap gap-1.5">
                        {params.all_scopes.map((s, i) => {
                          const risky = params.risky_scopes?.find(r => r.scope === s);
                          return (
                            <span key={i} className={`text-xs rounded px-2 py-0.5 font-mono border ${
                              risky?.risk === 'critical' ? 'bg-red-900/40 text-red-300 border-red-700' :
                              risky?.risk === 'high'     ? 'bg-orange-900/40 text-orange-300 border-orange-700' :
                              risky?.risk === 'medium'   ? 'bg-yellow-900/30 text-yellow-300 border-yellow-700' :
                                                           'bg-gray-800 text-gray-400 border-gray-700'
                            }`}>
                              {s.length > 50 ? s.slice(s.lastIndexOf('/') + 1) : s}
                              {risky ? ` ⚠` : ''}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Tokens found */}
              {result.tokens_found?.length > 0 && (
                <div className="mt-4 space-y-2">
                  <p className="text-xs text-gray-500 uppercase tracking-wide font-semibold">Tokens / Codes in URL</p>
                  {result.tokens_found.map((t, i) => (
                    <div key={i} className="flex items-center gap-3 bg-black/30 rounded px-3 py-2 text-xs">
                      <span className={`font-mono ${SEV_BADGE[t.risk] ? 'text-red-300' : 'text-gray-400'} px-1.5 py-0.5 rounded border ${SEV_BADGE[t.risk] || ''}`}>
                        {t.param}
                      </span>
                      <span className="text-gray-500 font-mono truncate">{t.value}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Findings */}
            <div className="glass-card p-6 space-y-4">
              <h3 className="text-base font-bold text-white">Findings ({result.findings?.length ?? 0})</h3>
              <FindingList findings={result.findings} />
            </div>
          </div>

          {/* Recommendations */}
          {result.recommendations?.length > 0 && (
            <div className="glass-card p-6 space-y-3">
              <h3 className="text-base font-bold text-white">Recommendations</h3>
              <Recommendations items={result.recommendations} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ label, value, mono, warn, color }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-gray-500 uppercase tracking-wide">{label}</span>
      <span className={`text-sm break-all ${mono ? 'font-mono' : ''} ${warn ? 'text-orange-300' : (color || 'text-gray-300')}`}>
        {value}
      </span>
    </div>
  );
}

// ── Email Scanner ─────────────────────────────────────────────────────────────

function EmailScanner() {
  const revealInput  = useReveal();
  const revealResult = useReveal();
  const [text,    setText]    = useState('');
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState('');

  const scan = async () => {
    const t = text.trim();
    if (!t) return;
    setLoading(true); setResult(null); setError('');
    try {
      setResult(await analyzeOAuthEmail(t));
    } catch (e) {
      setError(e.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      <div ref={revealInput} className="glass-card p-6 space-y-3">
        <p className="text-xs text-gray-500">
          Paste the raw email body. The scanner extracts all OAuth authorization URLs,
          detects consent-phishing language, and flags any JWT or Bearer tokens.
        </p>
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          rows={8}
          placeholder="Paste email content here…"
          className="w-full bg-black/30 border border-gray-600 rounded-lg p-3 text-white text-sm placeholder-gray-600 font-mono resize-y"
          disabled={loading}
        />
        <div className="flex items-center gap-3">
          <button onClick={scan} disabled={loading || !text.trim()}
            className="px-6 py-3 bg-purple-700 hover:bg-purple-600 text-white font-bold rounded-lg text-sm disabled:opacity-50 transition">
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                Scanning…
              </span>
            ) : 'Scan Email'}
          </button>
          {text && <button onClick={() => { setText(''); setResult(null); }} className="text-xs text-gray-500 hover:text-gray-300">Clear</button>}
        </div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>

      {result && (
        <div ref={revealResult} className="space-y-4">
          {/* Overall verdict */}
          <div className="glass-card p-6 flex flex-wrap gap-8 items-center">
            <div className="text-center">
              <p className={`text-5xl font-black ${SCORE_COLOR(result.overall_risk_score)}`}>
                {result.overall_risk_score}/10
              </p>
              <p className="text-xs text-gray-500 uppercase tracking-wide mt-1">Risk Score</p>
            </div>
            <div className="space-y-1.5 text-sm">
              <div className="flex gap-4">
                <Stat label="OAuth URLs found" value={result.urls_found} />
                <Stat label="Consent patterns" value={result.consent_patterns_matched} warn={result.consent_patterns_matched > 0} />
                <Stat label="JWTs in body" value={result.jwts_in_body} warn={result.jwts_in_body > 0} />
                <Stat label="Bearer tokens" value={result.bearer_tokens_in_body} warn={result.bearer_tokens_in_body > 0} />
              </div>
              <p className={`text-sm font-semibold mt-2 ${SCORE_COLOR(result.overall_risk_score)}`}>
                {result.verdict}
              </p>
            </div>
          </div>

          {/* Body findings */}
          {result.body_findings?.length > 0 && (
            <div className="glass-card p-6 space-y-3">
              <h3 className="text-base font-bold text-white">Email Body Findings</h3>
              <FindingList findings={result.body_findings} />
            </div>
          )}

          {/* Per-URL results */}
          {result.url_analyses?.length > 0 && (
            <div className="glass-card p-6 space-y-4">
              <h3 className="text-base font-bold text-white">
                Embedded OAuth URLs ({result.url_analyses.length})
              </h3>
              <div className="space-y-3">
                {result.url_analyses.map((u, i) => (
                  <div key={i} className={`rounded-lg border p-4 space-y-2 ${
                    u.risk_score >= 7 ? 'border-red-800 bg-red-950/10' :
                    u.risk_score >= 4 ? 'border-orange-800 bg-orange-950/10' :
                                        'border-gray-700 bg-black/10'
                  }`}>
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className={`text-lg font-black ${SCORE_COLOR(u.risk_score)}`}>{u.risk_score}/10</span>
                      {u.threat_type && (
                        <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${THREAT_COLOR(u.threat_type)}`}>
                          {u.threat_type}
                        </span>
                      )}
                      {u.provider?.name && (
                        <span className={`text-xs px-2 py-0.5 rounded border ${
                          u.provider.legitimate ? 'text-green-400 border-green-700' : 'text-red-400 border-red-700'
                        }`}>
                          {u.provider.name}
                        </span>
                      )}
                      <span className="text-xs font-mono text-gray-500 truncate max-w-xs">{u.url}</span>
                    </div>
                    {u.findings?.length > 0 && (
                      <div className="space-y-1 mt-2">
                        {u.findings.map((f, j) => (
                          <p key={j} className="text-xs text-gray-400">
                            <span className={`font-bold ${
                              f.severity === 'critical' ? 'text-red-400' :
                              f.severity === 'high'     ? 'text-orange-400' : 'text-yellow-400'
                            }`}>
                              [{f.severity}]
                            </span>{' '}
                            {f.title}
                          </p>
                        ))}
                      </div>
                    )}
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

function Stat({ label, value, warn }) {
  return (
    <div className="text-center">
      <p className={`text-xl font-black ${warn ? 'text-red-400' : 'text-white'}`}>{value}</p>
      <p className="text-xs text-gray-500">{label}</p>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

const MODES = ['URL / Link', 'Email / Text'];

export default function OAuthDetector() {
  const [mode, setMode] = useState('URL / Link');

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <div>
        <h2 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>OAuth & Token Theft Detector</h2>
        <p className="text-gray-500 text-sm mt-1">
          Detects fake consent screens, token/code exposure in URLs, AiTM proxy indicators,
          dangerous OAuth scope combinations, and consent-phishing language in emails.
          Pure static analysis — no page fetching.
        </p>
      </div>

      {/* Mode tabs */}
      <div className="flex gap-2">
        {MODES.map(m => (
          <button key={m} onClick={() => setMode(m)}
            className={`px-5 py-2.5 rounded-lg font-semibold text-sm transition ${
              mode === m ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}>
            {m}
          </button>
        ))}
      </div>

      {mode === 'URL / Link'   && <UrlAnalyzer />}
      {mode === 'Email / Text' && <EmailScanner />}
    </div>
  );
}
