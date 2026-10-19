"""
Vishing (Voice Phishing) Analysis Engine.

Transcription backend priority (each tried in order, first success wins):
  1. Groq Whisper API     - fastest;   requires GROQ_API_KEY (already used for chat)
  2. OpenAI Whisper API   - cloud;     requires OPENAI_API_KEY
  3. Local transformers   - offline;   uses already-installed transformers + soundfile
                            (handles WAV/FLAC/OGG; add ffmpeg for MP3/WEBM)
  4. Local openai-whisper - offline;   requires `pip install openai-whisper` + ffmpeg

All backends share the same analysis engine below.
"""

import os
import re
import time
from urllib.parse import urlparse

from app.core.config import settings


# ── Transcription backends ──────────────────────────────────────────────────────

def _transcribe_groq(audio_path: str) -> str:
    if not settings.GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY not set")
    from openai import OpenAI
    client = OpenAI(
        api_key=settings.GROQ_API_KEY,
        base_url="https://api.groq.com/openai/v1",
    )
    with open(audio_path, "rb") as f:
        # Use default response format - returns a Transcription object with .text
        result = client.audio.transcriptions.create(
            model="whisper-large-v3-turbo",
            file=f,
        )
    return result.text.strip()


def _transcribe_openai(audio_path: str) -> str:
    api_key = getattr(settings, "OPENAI_API_KEY", None)
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    from openai import OpenAI
    client = OpenAI(api_key=api_key)
    with open(audio_path, "rb") as f:
        result = client.audio.transcriptions.create(model="whisper-1", file=f)
    return result.text.strip()


def _transcribe_transformers(audio_path: str) -> str:
    """
    Local Whisper via the already-installed `transformers` library.
    Audio loading uses `soundfile` (WAV/FLAC/OGG) or Python's built-in
    `wave` module (WAV only - no extra deps required).
    """
    import numpy as np
    from transformers import pipeline

    # ------ audio loading ------
    audio_np = None
    sample_rate = 16_000

    # Try soundfile first (handles WAV, FLAC, OGG, AIFF)
    try:
        import soundfile as sf
        audio_np, sample_rate = sf.read(audio_path, dtype="float32", always_2d=False)
        if audio_np.ndim > 1:           # stereo -> mono
            audio_np = audio_np.mean(axis=1)
    except ImportError:
        pass
    except Exception:
        audio_np = None

    # Fall back to stdlib wave (WAV only, no extra deps)
    if audio_np is None:
        try:
            import wave
            with wave.open(audio_path, "rb") as wf:
                raw   = wf.readframes(wf.getnframes())
                sr    = wf.getframerate()
                ch    = wf.getnchannels()
                sw    = wf.getsampwidth()
            dtype = {1: np.int8, 2: np.int16, 4: np.int32}.get(sw, np.int16)
            arr   = np.frombuffer(raw, dtype=dtype).astype(np.float32)
            arr  /= float(np.iinfo(dtype).max)
            if ch > 1:
                arr = arr.reshape(-1, ch).mean(axis=1)
            audio_np    = arr
            sample_rate = sr
        except Exception as exc:
            raise RuntimeError(
                f"Cannot load audio without soundfile. "
                f"Run: pip install soundfile\n(Original error: {exc})"
            )

    # Resample to 16 kHz if needed (simple linear interpolation)
    if sample_rate != 16_000:
        n_target = int(len(audio_np) * 16_000 / sample_rate)
        audio_np = np.interp(
            np.linspace(0, len(audio_np) - 1, n_target),
            np.arange(len(audio_np)),
            audio_np,
        ).astype(np.float32)

    # ------ transcription ------
    pipe = pipeline(
        "automatic-speech-recognition",
        model="openai/whisper-base",
        device=-1,   # CPU
    )
    result = pipe({"array": audio_np, "sampling_rate": 16_000})
    return result["text"].strip()


def _transcribe_local_whisper(audio_path: str) -> str:
    try:
        import whisper as _whisper
    except ImportError:
        raise RuntimeError(
            "openai-whisper not installed. Run: pip install openai-whisper\n"
            "Also install ffmpeg: https://ffmpeg.org/download.html"
        )
    model = _whisper.load_model("base")
    return model.transcribe(audio_path, fp16=False)["text"].strip()


def transcribe(audio_path: str) -> str:
    """
    Try each backend in priority order and return the first successful transcript.
    Collects all errors for a helpful message if everything fails.
    """
    backends = [
        _transcribe_groq,
        _transcribe_openai,
        _transcribe_transformers,
        _transcribe_local_whisper,
    ]
    errors = []
    for fn in backends:
        try:
            text = fn(audio_path)
            if text:
                return text
        except Exception as exc:
            errors.append(f"  [{fn.__name__}]: {exc}")

    raise RuntimeError(
        "All transcription backends failed:\n" + "\n".join(errors) + "\n\n"
        "Quick fix - set GROQ_API_KEY in .env (free at console.groq.com). "
        "Groq offers Whisper as a free API and it's already wired up. "
        "Alternatively: pip install soundfile  (for local WAV/FLAC/OGG transcription without ffmpeg)."
    )


# ── Pattern library ─────────────────────────────────────────────────────────────

_P = re.I

_IRS = re.compile(
    r'\b(irs\b|internal revenue service|tax\s+(?:audit|debt|owe|warrant|lawsuit|criminal|arrest|lien|fraud|evasion)|'
    r'federal\s+tax\s+(?:lien|warrant|case)|back\s+taxes?)\b', _P,
)
_SSA = re.compile(
    r'\b(social\s+security(?:\s+(?:number|administration|benefit|card))?|'
    r'ssa\b|medicare|medicaid|'
    r'(?:social\s+security|ssa).*?(?:suspend|comprom|fraud|criminal|warrant|arrest))\b', _P,
)
_TECH = re.compile(
    r'\b(microsoft|apple\s+(?:support|id|icloud)|windows\s+(?:support|error|virus|hack|license)|'
    r'(?:your\s+)?(?:computer|device|phone|laptop|pc).*?(?:virus|hack|infect|comprom|breach|error|problem|detected)|'
    r'tech(?:nical)?\s+support|remote\s+(?:access|assist|control)|our\s+(?:technician|engineer)|'
    r'malware\s+(?:detected|found|removed))\b', _P,
)
_BANK = re.compile(
    r'\b(suspicious\s+(?:activity|transaction|charge|login|access|attempt)|'
    r'(?:your\s+)?account.*?(?:frozen|suspend|block|close|comprom|breach|hack|lock)|'
    r'transfer.*?(?:safe|secure|protect).*?account|'
    r'unauthorized\s+(?:charge|transaction|access|login)|'
    r'fraud\s+(?:department|alert|prevention|unit)|'
    r'verify\s+(?:your\s+)?(?:account|identity|information|card|pin))\b', _P,
)
_GIFT_CARD = re.compile(
    r'\b(gift\s+card|itunes\s*(?:card|gift)?|google\s+play\s*(?:card|gift)?|'
    r'amazon\s+gift|walmart\s+gift|target\s+gift|best\s+buy\s+gift|steam\s+gift|'
    r'ebay\s+gift|vanilla\s+(?:card|gift)|reload\s+(?:card|pack)|'
    r'prepaid\s+(?:card|debit|visa|mastercard)|green\s+dot|moneypak|'
    r'scratch.*?card|activation\s+code)\b', _P,
)
_WIRE = re.compile(
    r'\b(wire\s+transfer|western\s+union|moneygram|'
    r'(?:bitcoin|ethereum|crypto(?:currency)?|usdt|tether)\s*(?:wallet|address|payment)?|'
    r'cryptocurrency\s+payment|send.*?(?:bitcoin|crypto)|'
    r'international\s+(?:wire|transfer|payment)|'
    r'zelle|venmo|cashapp|paypal\s+(?:friend|family))\b', _P,
)
_ARREST = re.compile(
    r'\b(arrest(?:ed|ing|warrant)?|warrant\s+(?:issued|out|for\s+your\s+arrest)|'
    r'lawsuit.*?filed|legal\s+action|court\s+order|'
    r'(?:police|federal|law\s+enforcement)\s+(?:officer|agent|detective)|'
    r'sheriff|marshal|immigration\s+(?:officer|agent|enforcement)|'
    r'deportation|homeland\s+security|fbi\s+agent|dea\s+agent|'
    r'charges\s+(?:filed|against\s+you)|criminal\s+charges)\b', _P,
)
_PERSONAL = re.compile(
    r'\b(social\s+security\s+number|(?:your\s+)?ssn\b|'
    r'(?:full\s+)?date\s+of\s+birth|credit\s+card\s+number|'
    r'(?:bank\s+)?account\s+number|routing\s+number|'
    r'pin\s+(?:number|code)|mother(?:\'s)?\s+maiden\s+(?:name)?|'
    r'driver(?:\'s)?\s+licen[sc]e\s+number|passport\s+number|'
    r'medical\s+(?:id|number|insurance\s+number)|medicare\s+(?:id|number))\b', _P,
)
_URGENCY = re.compile(
    r'\b(urgent(?:ly)?|immediately|right\s+now|'
    r'within\s+(?:the\s+next\s+)?\d+\s*(?:hours?|minutes?)|'
    r'today\s+only|last\s+(?:chance|warning|notice)|final\s+(?:warning|notice|opportunity)|'
    r'do\s+not\s+(?:hang\s+up|disconnect|ignore|delay)|'
    r'stay\s+on\s+the\s+line|time\s+(?:is\s+)?running\s+out|act\s+now|'
    r'emergency\s+(?:situation|matter)|this\s+is\s+your\s+(?:last|final))\b', _P,
)
_ROBOCALL = re.compile(
    r'\b(press\s+(?:\d|one|two|three|zero|pound|star)|'
    r'dial\s+(?:\d|one|two|zero)|'
    r'to\s+speak\s+(?:with|to)\s+(?:a\s+)?(?:live\s+)?(?:representative|agent|operator)|'
    r'to\s+(?:remove|opt\s+out|be\s+removed)\s+from\s+(?:our\s+)?list|'
    r'this\s+(?:call\s+)?(?:may\s+be\s+)?(?:is\s+being\s+)?recorded|'
    r'important\s+(?:message|notice|announcement)|'
    r'you\s+have\s+been\s+(?:selected|chosen|identified))\b', _P,
)
_LOTTERY = re.compile(
    r'\b((?:you(?:\'ve)?|congratulations)\s+(?:have\s+)?won|'
    r'prize\s+(?:claim|winner|amount|money)|'
    r'lottery\s+(?:winner|prize)|sweepstakes|'
    r'claim\s+(?:your\s+)?(?:prize|reward|winnings)|'
    r'selected\s+as\s+(?:a\s+)?winner)\b', _P,
)
_UTILITY = re.compile(
    r'\b((?:electric(?:ity)?|gas|water|power|utility)\s+(?:will\s+be\s+)?(?:disconnect|cut\s+off|shut\s+off|suspend)|'
    r'service\s+(?:terminat|suspend|disconnect|interrupt)|'
    r'final\s+(?:notice|warning)\s+(?:(?:for|before)\s+)?(?:payment|disconnect|shutoff)|'
    r'overdue\s+(?:balance|bill|payment|account))\b', _P,
)

_PHONE_RE = re.compile(r'(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})')
_MONEY_RE = re.compile(r'\$\s*[\d,]+(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s*(?:dollars?|USD)\b', _P)
_URL_RE   = re.compile(r'https?://[^\s]+|www\.[^\s]+', _P)


# ── Analysis ────────────────────────────────────────────────────────────────────

def _find(pattern: re.Pattern, text: str) -> list[str]:
    return list({m.group(0) for m in pattern.finditer(text)})


def analyze_transcript(text: str) -> dict:
    findings: list[dict] = []
    score = 0
    all_matched: list[str] = []

    def _hit(pattern, label, severity, pts, detail):
        phrases = _find(pattern, text)
        if phrases:
            nonlocal score
            score += pts
            all_matched.extend(phrases)
            findings.append({
                "severity": severity,
                "title": label,
                "detail": detail,
                "matched_phrases": phrases[:6],
            })

    _hit(_ARREST,    "Arrest / Legal Threat",                  "critical", 40,
         "Caller claims you face arrest, warrants, or legal action. "
         "No legitimate agency demands payment by phone to avoid arrest.")
    _hit(_GIFT_CARD, "Gift Card Payment Demand",                "critical", 50,
         "Caller is demanding payment via gift cards. "
         "Gift cards are untraceable - no government agency or business accepts them as payment.")
    _hit(_WIRE,      "Wire Transfer / Cryptocurrency Demand",   "critical", 50,
         "Caller is requesting a wire transfer or cryptocurrency payment. "
         "These are irreversible - the hallmark of phone scams.")
    _hit(_PERSONAL,  "Personal / Financial Information Requested", "critical", 50,
         "Caller is asking for sensitive personal or financial data. "
         "Never provide SSN, credit card, account numbers, or PINs over an unsolicited call.")
    _hit(_IRS,       "IRS / Tax Authority Impersonation",       "high", 40,
         "The IRS contacts taxpayers by mail first - never by unsolicited phone calls demanding payment.")
    _hit(_SSA,       "Social Security Administration Impersonation", "high", 40,
         "The SSA never threatens suspension of your number or demands immediate payment by phone.")
    _hit(_TECH,      "Tech Support Scam",                       "high", 35,
         "Microsoft, Apple, and Google never make unsolicited support calls.")
    _hit(_BANK,      "Bank / Financial Fraud Impersonation",    "high", 35,
         "Call your bank directly using the number on your card - not the number this caller gave you.")
    _hit(_LOTTERY,   "Prize / Lottery Scam",                    "high", 30,
         "Unsolicited prize notifications by phone are universally fraudulent.")
    _hit(_UTILITY,   "Utility Disconnection Threat",            "high", 25,
         "Utility companies send written notices and never demand gift-card payment.")
    _hit(_URGENCY,   "Urgency / Pressure Language",             "medium", 20,
         "Pressure tactics are used to stop you from verifying the call or seeking advice.")
    _hit(_ROBOCALL,  "Robocall / Automated Call Markers",       "medium", 15,
         "Call contains automated-system prompts typical of vishing campaign infrastructure.")

    phones  = list(set(_PHONE_RE.findall(text)))[:6]
    amounts = list(set(_MONEY_RE.findall(text)))[:6]
    urls    = list(set(_URL_RE.findall(text)))[:4]

    titles = " ".join(f["title"] for f in findings).lower()
    threat_type = (
        "IRS / Tax Scam"              if "irs" in titles else
        "Social Security Scam"        if "social security" in titles else
        "Tech Support Scam"           if "tech support" in titles else
        "Bank Fraud"                  if "bank" in titles else
        "Arrest / Extortion Scam"     if "arrest" in titles else
        "Gift Card Scam"              if "gift card" in titles else
        "Cryptocurrency Scam"         if "wire" in titles else
        "Prize / Lottery Scam"        if "prize" in titles else
        "Utility Scam"                if "utility" in titles else
        "Voice Phishing (Vishing)"    if findings else
        None
    )

    return {
        "risk_score":      min(10, round(score / 10)),
        "threat_type":     threat_type,
        "findings":        findings,
        "matched_phrases": list(dict.fromkeys(all_matched)),
        "entities": {
            "phone_numbers":  phones,
            "dollar_amounts": amounts,
            "urls_mentioned": urls,
        },
        "recommendations": _recommendations(findings),
    }


def _recommendations(findings: list[dict]) -> list[str]:
    recs = []
    titles = " ".join(f["title"] for f in findings).lower()
    if "gift card" in titles or "wire" in titles:
        recs.append("Do not send gift cards, wire transfers, or cryptocurrency - they are untraceable and unrecoverable.")
    if "irs" in titles or "social security" in titles:
        recs.append("Hang up and call the agency directly at irs.gov or ssa.gov. Government agencies always contact you by mail first.")
    if "arrest" in titles:
        recs.append("Law enforcement never demands payment over the phone to avoid arrest. Hang up and report to your local police.")
    if "tech support" in titles:
        recs.append("Never allow remote access from an unsolicited caller. Hang up and contact the company through their official website.")
    if "bank" in titles:
        recs.append("Contact your bank using the number on the back of your card - never use a number the caller gave you.")
    if "personal" in titles:
        recs.append("If you provided personal details, place a fraud alert with Experian, Equifax, or TransUnion and monitor your accounts.")
    if not recs:
        recs.append("Hang up on unsolicited calls requesting money or personal information. Verify through official channels before acting.")
    recs.append("Report vishing calls: FTC at reportfraud.ftc.gov (US) - Action Fraud at actionfraud.police.uk (UK).")
    return recs


# ── Full pipeline ────────────────────────────────────────────────────────────────

def analyze_audio(audio_path: str) -> dict:
    t0         = time.monotonic()
    transcript = transcribe(audio_path)
    elapsed    = round(time.monotonic() - t0, 1)
    analysis   = analyze_transcript(transcript)
    return {
        "transcript":           transcript,
        "transcript_length":    len(transcript),
        "transcription_time_s": elapsed,
        **analysis,
    }
