const API = '/api/v1';

async function _post(path, body) {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
}

async function _get(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
}

export const scanEmail = (text, explain = true) =>
  _post('/scan/email', { text, explain });

export const scanUrl = (url) =>
  _post('/scan/url', { url });

export async function scanImage(file) {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${API}/scan/image?explain=true`, { method: 'POST', body: form });
  if (!res.ok) throw new Error(`Scan failed: ${res.status}`);
  return res.json();
}

export async function scanQR(file) {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${API}/scan/qr`, { method: 'POST', body: form });
  if (!res.ok) throw new Error(`QR scan failed: ${res.status}`);
  return res.json();
}

export const batchScan = (items) =>
  _post('/batch/', items);

export const askAnalyst = (payload) =>
  _post('/scan/ask', payload);

export const aiThinking = (text, prediction) =>
  _post('/scan/thinking', { text, prediction });

export const visualForensics = (image_base64) =>
  _post('/scan/visual', { image_base64 });

export const scanHeaders = (raw_headers) =>
  _post('/scan/headers', { raw_headers });

export const traceRedirects = (url, max_hops = 12) =>
  _post('/scan/trace', { url, max_hops });

export async function downloadReport(scanData) {
  const res = await fetch(`${API}/scan/report/pdf`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(scanData),
  });
  if (!res.ok) throw new Error(`Report failed: ${res.status}`);
  return res.blob();
}

export const getHistory = (limit = 50) =>
  _get(`/history/?limit=${limit}`);

export const getAnalytics = () =>
  _get('/history/analytics');

export const verifyAdmin = (password) =>
  _post('/admin/verify', { password });

export const getWhitelist = () =>
  _get('/admin/whitelist');

export const addDomain = (domain) =>
  _post('/admin/whitelist', { domain });

export async function removeDomain(domain) {
  const res = await fetch(`${API}/admin/whitelist?domain=${encodeURIComponent(domain)}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error(`Remove failed: ${res.status}`);
  return res.json();
}

export const getFeedback = (limit = 50) =>
  _get(`/admin/feedback?limit=${limit}`);

export const submitFeedback = (payload) =>
  _post('/admin/feedback', payload);

export const retrainModel = () =>
  _post('/admin/retrain', {});

export const getTrustStats = () =>
  _get('/admin/trust');

// ── Self-learning system ─────────────────────────────────────────────────────

export const getQuarantine = (limit = 50) =>
  _get(`/admin/feedback/quarantine?limit=${limit}`);

export const approveFeedback = (feedbackId) =>
  _post(`/admin/feedback/${feedbackId}/approve`, {});

export const rejectFeedback = (feedbackId, reason = '') =>
  _post(`/admin/feedback/${feedbackId}/reject`, { reason });

export const getFeedbackStats = () =>
  _get('/admin/feedback/stats');

export const getConfirmedCorrections = () =>
  _get('/admin/feedback/confirmed');

export const triggerSelfLearning = () =>
  _post('/admin/self-learning/run', {});

export const getSelfLearningStatus = () =>
  _get('/admin/self-learning/status');

export const triggerMetaRetrain = () =>
  _post('/admin/self-learning/run-now', {});

export const triggerLoRAFinetune = () =>
  _post('/lora/finetune', {});

export const getAuditLog = (limit = 100) =>
  _get(`/audit/log?limit=${limit}`);

export const verifyAuditChain = () =>
  _get('/audit/verify');

export const triggerEval = (maxSamples = 500) =>
  _post(`/eval/run?max_samples=${maxSamples}`, {});

export const getEvalStatus = () =>
  _get('/eval/status');

export const getEvalResults = () =>
  _get('/eval/results');

export const getAdversarialStrategies = () =>
  _get('/adversarial/strategies');

export const generateAdversarial = (payload) =>
  _post('/adversarial/generate', payload);

export const exportAdversarial = (variants, trueLabel) =>
  _post('/adversarial/export', { variants, true_label: trueLabel });

export const getAdversarialStats = () =>
  _get('/adversarial/stats');

export const getUsers = () =>
  _get('/admin/users');

export const setUserRole = (userId, role) =>
  fetch(`${API}/admin/users/${userId}/role`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role }),
  }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });

export const setUserStatus = (userId, disabled) =>
  fetch(`${API}/admin/users/${userId}/status?disabled=${disabled}`, {
    method: 'PATCH',
  }).then(r => { if (!r.ok) throw new Error(r.status); return r.json(); });

export const getSystemHealth = () =>
  _get('/admin/health');

export const checkDmarc = (domain) =>
  _post('/brand/dmarc', { domain });

export const startLookalikeScan = (domain) =>
  _post('/brand/lookalikes/scan', { domain });

export const getLookalikeScanStatus = (domain) =>
  _get(`/brand/lookalikes/status/${encodeURIComponent(domain)}`);

export const getLookalikePreview = (domain) =>
  _get(`/brand/lookalikes/preview/${encodeURIComponent(domain)}`);

export const getCTLogs = (domain, maxResults = 300) =>
  _get(`/brand/ct/${encodeURIComponent(domain)}?max_results=${maxResults}`);

export async function uploadVishingAudio(file) {
  const form = new FormData();
  form.append('file', file);
  const res = await fetch(`${API}/vishing/analyze`, { method: 'POST', body: form });
  if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
  return res.json();
}

export const getVishingStatus = (jobId) =>
  _get(`/vishing/status/${jobId}`);

export const getVishingResult = (jobId) =>
  _get(`/vishing/result/${jobId}`);

export const lookupThreatIntel = (url) =>
  _get(`/threat-intel/lookup?url=${encodeURIComponent(url)}`);

export const analyzeSms = (text) =>
  _post('/mobile/analyze-sms', { text });

export const analyzeDeeplink = (link) =>
  _post('/mobile/analyze-deeplink', { link });

export const analyzeMobileUrl = (url) =>
  _post('/mobile/analyze-url', { url });

export const analyzeOAuthUrl = (url) =>
  _post('/oauth/analyze-url', { url });

export const analyzeOAuthEmail = (text) =>
  _post('/oauth/analyze-email', { text });

export const getOAuthProviders = () =>
  _get('/oauth/providers');

export const triggerIngest = (options) =>
  _post('/training/ingest', options);

export const getIngestStatus = () =>
  _get('/training/ingest/status');

export const triggerUrlRetrain = () =>
  _post('/training/url-model/retrain', {});

export const getUrlRetrainStatus = () =>
  _get('/training/url-model/status');

export const fingerprintKit = (url) =>
  _post('/brand/kit/fingerprint', { url });

export const getKitSignatures = () =>
  _get('/brand/kit/signatures');

export const startSandboxScan = (url) =>
  _post('/sandbox/scan', { url });

export const getSandboxStatus = (jobId) =>
  _get(`/sandbox/status/${jobId}`);

export const getSandboxResult = (jobId) =>
  _get(`/sandbox/result/${jobId}`);
