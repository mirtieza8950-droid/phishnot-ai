"""
FastAPI application for Email Phishing/Spam Detection and URL Phishing Detection.
Run with: uvicorn app:app --reload
Open docs: http://127.0.0.1:8000/docs
"""
import os
import io
import uuid
import logging
import re
import json
import sqlite3
import base64
import warnings
from datetime import datetime
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse
from contextlib import contextmanager

warnings.filterwarnings("ignore")
os.environ["TRANSFORMERS_VERBOSITY"] = "error"
logging.getLogger("transformers").setLevel(logging.ERROR)

import numpy as np
import joblib
import torch
import torch.nn as nn
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Query, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from transformers import DistilBertTokenizer, DistilBertModel
from lime.lime_text import LimeTextExplainer
from sqlalchemy.orm import Session

# Optional: OpenAI client for AI chat
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None
    print("openai not installed. AI chat endpoint will be disabled. Install with: pip install openai")

# Optional: python-docx for forensic reports
try:
    from docx import Document
    from docx.shared import RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import qn
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False
    print("python-docx not installed. Report generation disabled. Install with: pip install python-docx")

# ===============================
# Database Setup (optional - app works without DB)
# ===============================
DB_AVAILABLE = False
get_db = None
ScanRecord = None
engine = None
Base = None

try:
    from config import get_settings  # noqa: F401
    from database import engine as _engine, get_db as _get_db, Base as _Base
    from models import ScanRecord as _ScanRecord
    engine = _engine
    Base = _Base
    ScanRecord = _ScanRecord
    get_db = _get_db
    Base.metadata.create_all(bind=engine)
    DB_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Database disabled ({e}). History/Analytics endpoints will return empty results.")
except Exception as e:
    print(f"Warning: Database setup failed ({e}). History/Analytics endpoints will return empty results.")

def db_dep():
    if DB_AVAILABLE and get_db is not None:
        yield from get_db()
    else:
        yield None

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# OCR Setup
try:
    from PIL import Image
    import pytesseract
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False
    logger.warning("OCR disabled. Install pytesseract + Pillow + Tesseract binary.")

MODELS_DIR = "models"
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ===============================
# Model Definitions
# ===============================
class CNNTransformerHybrid(nn.Module):
    def __init__(self, vocab_size, embed_dim=256, num_classes=3,
                 num_filters=128, kernel_sizes=[3, 4, 5],
                 nhead=4, num_transformer_layers=2, max_len=256):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_embedding = nn.Embedding(max_len, embed_dim)
        self.convs = nn.ModuleList([
            nn.Conv1d(embed_dim, num_filters, kernel_size=k, padding=k // 2)
            for k in kernel_sizes
        ])
        self.cnn_bn = nn.LayerNorm(num_filters * len(kernel_sizes))
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim, nhead=nhead, dim_feedforward=512,
            dropout=0.1, batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_transformer_layers)
        combined_dim = num_filters * len(kernel_sizes) + embed_dim
        self.classifier = nn.Sequential(
            nn.Linear(combined_dim, 256), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(256, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, num_classes)
        )

    def forward(self, input_ids, attention_mask=None):
        batch_size, seq_len = input_ids.shape
        positions = torch.arange(seq_len, device=input_ids.device).unsqueeze(0).expand(batch_size, -1)
        x = self.embedding(input_ids) + self.pos_embedding(positions)
        x_cnn = x.permute(0, 2, 1)
        conv_outs = [torch.max(torch.relu(conv(x_cnn)), dim=2)[0] for conv in self.convs]
        cnn_out = self.cnn_bn(torch.cat(conv_outs, dim=1))
        src_key_padding_mask = (attention_mask == 0) if attention_mask is not None else None
        trans_out = self.transformer_encoder(x, src_key_padding_mask=src_key_padding_mask).mean(dim=1)
        return self.classifier(torch.cat([cnn_out, trans_out], dim=1))


class DistilBertDenseClassifier(nn.Module):
    def __init__(self, num_classes=3):
        super().__init__()
        self.distilbert = DistilBertModel.from_pretrained('distilbert-base-uncased')
        hidden_size = self.distilbert.config.hidden_size
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, 256), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(256, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, num_classes)
        )

    def forward(self, input_ids, attention_mask=None):
        outputs = self.distilbert(input_ids=input_ids, attention_mask=attention_mask)
        cls_output = outputs.last_hidden_state[:, 0, :]
        return self.classifier(cls_output)


# ===============================
# Load All Models
# ===============================
print("Loading models...")
tfidf = joblib.load(os.path.join(MODELS_DIR, 'tfidf_vectorizer.pkl'))
lr_model = joblib.load(os.path.join(MODELS_DIR, 'logistic_regression.pkl'))
svm_model = joblib.load(os.path.join(MODELS_DIR, 'svm_model.pkl'))
ensemble_config = joblib.load(os.path.join(MODELS_DIR, 'ensemble_config.pkl'))

LABEL_MAP = ensemble_config['label_map']
LABEL_MAP_REVERSE = ensemble_config['label_map_reverse']
WEIGHTS = ensemble_config['weights']
REORDER_IDX = ensemble_config['reorder_idx']
MAX_LEN = ensemble_config['max_len']
VOCAB_SIZE = ensemble_config['vocab_size']
tokenizer = DistilBertTokenizer.from_pretrained(os.path.join(MODELS_DIR, 'distilbert_tokenizer'))

distilbert_model = DistilBertDenseClassifier(num_classes=3)
distilbert_model.load_state_dict(torch.load(os.path.join(MODELS_DIR, 'distilbert_dense.pth'), map_location=DEVICE))
distilbert_model.to(DEVICE).eval()

cnn_transformer = CNNTransformerHybrid(vocab_size=VOCAB_SIZE, embed_dim=256, num_classes=3)
cnn_transformer.load_state_dict(torch.load(os.path.join(MODELS_DIR, 'cnn_transformer.pth'), map_location=DEVICE))
cnn_transformer.to(DEVICE).eval()

url_model = joblib.load(os.path.join(MODELS_DIR, 'url_phishing_model.pkl'))

# Meta-learner (stacking)
meta_model = None
meta_le = None
use_meta_learner = False
META_PATH = os.path.join(MODELS_DIR, 'meta_learner.pkl')
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, 'meta_label_encoder.pkl')
if os.path.exists(META_PATH) and os.path.exists(LABEL_ENCODER_PATH):
    meta_model = joblib.load(META_PATH)
    meta_le = joblib.load(LABEL_ENCODER_PATH)
    use_meta_learner = True
    print("[OK]  Meta-learner loaded. Stacking ensemble active.")
else:
    print("[INFO]  Meta-learner not found. Using weighted average ensemble.")

# Local Vision Model (Qwen2-VL-2B)
vision_model = None
vision_processor = None
VISION_MODEL_ID = "Qwen/Qwen2-VL-2B-Instruct"

def init_vision_model():
    global vision_model, vision_processor
    try:
        from transformers import Qwen2VLForConditionalGeneration, AutoProcessor, BitsAndBytesConfig

        # Proper 4‑bit quantization config
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4"
        )

        vision_model = Qwen2VLForConditionalGeneration.from_pretrained(
            VISION_MODEL_ID,
            torch_dtype=torch.float16,
            device_map="auto",
            quantization_config=bnb_config
        )
        vision_processor = AutoProcessor.from_pretrained(VISION_MODEL_ID)
        print("[OK]  Local vision model ready (Qwen2-VL-2B).")
    except Exception as e:
        print(f"[INFO]  Local vision model not available: {e}")

# Uncomment the next line to load the vision model at startup

init_vision_model()

print("All models loaded successfully!")
lime_explainer = LimeTextExplainer(class_names=list(LABEL_MAP.keys()))

# ===============================
# FastAPI App
# ===============================
app = FastAPI(title="PhishGuard AI", description="Neural Email & URL Phishing Detection", version="4.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ===============================
# Request/Response Models
# ===============================
class EmailRequest(BaseModel):
    text: str
    explain: bool = True

class URLRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    prediction: str
    confidence: float
    all_probabilities: dict
    model_predictions: dict
    explanation: Optional[list] = None
    reasoning: Optional[dict] = None
    scan_id: str = ""
    warning: Optional[str] = None

class ImageResponse(BaseModel):
    extracted_text: str
    char_count: int
    prediction: str
    confidence: float
    all_probabilities: dict
    model_predictions: dict
    explanation: Optional[list] = None
    reasoning: Optional[dict] = None
    scan_id: str = ""
    warning: Optional[str] = None

class URLResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    features: dict
    all_probabilities: dict
    model_predictions: dict
    scan_id: str = ""
    warning: Optional[str] = None
    reasoning: Optional[dict] = None

class AskRequest(BaseModel):
    prediction: str
    confidence: float
    model_predictions: dict
    explanation: Optional[list] = None
    reasoning: Optional[dict] = None
    text: Optional[str] = None
    question: str

class FeedbackRequest(BaseModel):
    scan_id: str
    user_label: str
    model_prediction: str
    input_text: str

class WhitelistRequest(BaseModel):
    domain: str

class VisualRequest(BaseModel):
    image_base64: str
    url_hint: Optional[str] = None

class ReportRequest(BaseModel):
    prediction: str
    confidence: float
    model_predictions: dict
    reasoning: Optional[dict] = None
    scan_id: str = ""

# Import URL feature extractor
from url_feature_extractor import extract_url_features, get_feature_names

# ===============================
# Helpers: Risk & Attack
# ===============================
URGENCY_PATTERNS = re.compile(
    r'(urgent|immediate|alert|verify|confirm|suspend|limited|expire|'
    r'action required|click here|login|account|password|update|secure)',
    re.IGNORECASE
)
SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.cc', '.pw', '.club', '.work'}
HOMOGLYPH_PATTERNS = re.compile(r'[αа⍺ａ]')

def compute_risk_score(prediction: str, confidence: float, text: str, url_features: dict = None) -> dict:
    base_score = confidence * 100
    risk_boost = 0
    if URGENCY_PATTERNS.search(text):
        risk_boost += 15
    if HOMOGLYPH_PATTERNS.search(text):
        risk_boost += 20
    if url_features:
        if url_features.get('domain_age_days', 365) < 30:
            risk_boost += 20
        if url_features.get('suspicious_tld', False):
            risk_boost += 15
        if url_features.get('entropy', 0) > 3.5:
            risk_boost += 10
    risk_score = min(base_score + risk_boost, 100)
    if prediction in ("ham", "legitimate"):
        risk_score = min(risk_score, 30)
        level = "Low"
    else:
        if risk_score >= 80: level = "Critical"
        elif risk_score >= 60: level = "High"
        elif risk_score >= 40: level = "Medium"
        else: level = "Low"
    return {"score": round(risk_score, 1), "level": level}

ATTACK_TYPE_KEYWORDS = {
    "Credential Harvesting": r'(login|sign.?in|password|verify account|update.*account|credential)',
    "Invoice/Billing Scam": r'(invoice|payment|billing|receipt|order|transaction)',
    "Tech Support Scam": r'(support|tech|help.?desk|security alert|virus|threat)',
    "Job Offer Scam": r'(job|hiring|recruit|salary|position|interview)',
    "Prize/Giveaway Scam": r'(winner|prize|won|claim|reward|congratulation)',
}

def classify_attack(text: str) -> str:
    for attack, pattern in ATTACK_TYPE_KEYWORDS.items():
        if re.search(pattern, text, re.IGNORECASE):
            return attack
    return "Generic Phishing"

def extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().replace('www.', '')
    except:
        return ""

# ===============================
# Dynamic Domain Whitelist
# ===============================
WHITELIST_FILE = os.path.join(MODELS_DIR, "domain_whitelist.json")

def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "r") as f:
            return set(json.load(f))
    default = {"deepseek.com", "chat.deepseek.com", "google.com", "microsoft.com", "github.com", "paypal.com", "amazon.com"}
    save_whitelist(default)
    return default

def save_whitelist(domains):
    with open(WHITELIST_FILE, "w") as f:
        json.dump(sorted(list(domains)), f, indent=2)

TRUSTED_DOMAINS = load_whitelist()

# ===============================
# Feedback Database
# ===============================
FEEDBACK_DB = "feedback.db"

def init_feedback_db():
    conn = sqlite3.connect(FEEDBACK_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            user_label TEXT,
            model_prediction TEXT,
            input_text TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Add missing columns if needed
    try:
        conn.execute("ALTER TABLE feedback ADD COLUMN input_type TEXT DEFAULT 'email'")
    except:
        pass
    try:
        conn.execute("ALTER TABLE feedback ADD COLUMN timestamp DATETIME DEFAULT CURRENT_TIMESTAMP")
    except:
        pass
    conn.commit()
    conn.close()

@contextmanager
def get_feedback_conn():
    conn = sqlite3.connect(FEEDBACK_DB)
    try:
        yield conn
    finally:
        conn.close()

init_feedback_db()

# ===============================
# Prediction Helpers
# ===============================
def _model_breakdown(probs_row, weight):
    idx = int(np.argmax(probs_row))
    return {
        'prediction': LABEL_MAP_REVERSE[idx],
        'confidence': round(float(probs_row[idx]), 4),
        'weight': weight,
        'probabilities': {LABEL_MAP_REVERSE[i]: round(float(probs_row[i]), 4) for i in range(3)}
    }

def predict_email_ensemble(text: str):
    text_tfidf = tfidf.transform([text])
    lr_probs = lr_model.predict_proba(text_tfidf)[:, REORDER_IDX]
    svm_probs = svm_model.predict_proba(text_tfidf)[:, REORDER_IDX]
    
    encoding = tokenizer(text, padding='max_length', truncation=True, max_length=MAX_LEN, return_tensors='pt')
    input_ids = encoding['input_ids'].to(DEVICE)
    attention_mask = encoding['attention_mask'].to(DEVICE)

    with torch.no_grad():
        db_logits = distilbert_model(input_ids, attention_mask)
        db_probs = torch.softmax(db_logits, dim=-1).cpu().numpy()
        ct_logits = cnn_transformer(input_ids, attention_mask)
        ct_probs = torch.softmax(ct_logits, dim=-1).cpu().numpy()

    if use_meta_learner and meta_model is not None:
        stacked = np.concatenate([lr_probs[0], svm_probs[0], db_probs[0], ct_probs[0]]).reshape(1, -1)
        try:
            final_probs = meta_model.predict_proba(stacked)[0]
            ensemble_probs = np.zeros((1, 3))
            for i, cls in enumerate(meta_model.classes_):
                ensemble_probs[0, cls] = final_probs[i]
        except Exception as e:
            logger.warning(f"Meta-learner failed, falling back: {e}")
            ensemble_probs = (WEIGHTS['lr'] * lr_probs + WEIGHTS['svm'] * svm_probs +
                              WEIGHTS['distilbert'] * db_probs + WEIGHTS['cnn_transformer'] * ct_probs)
    else:
        ensemble_probs = (WEIGHTS['lr'] * lr_probs + WEIGHTS['svm'] * svm_probs +
                          WEIGHTS['distilbert'] * db_probs + WEIGHTS['cnn_transformer'] * ct_probs)
    
    pred_idx = int(np.argmax(ensemble_probs[0]))
    pred_label = LABEL_MAP_REVERSE[pred_idx]
    confidence = float(ensemble_probs[0][pred_idx])
    all_probs = {LABEL_MAP_REVERSE[i]: round(float(ensemble_probs[0][i]), 4) for i in range(3)}
    model_preds = {
        'logistic_regression': _model_breakdown(lr_probs[0], WEIGHTS['lr']),
        'svm': _model_breakdown(svm_probs[0], WEIGHTS['svm']),
        'distilbert_dense': _model_breakdown(db_probs[0], WEIGHTS['distilbert']),
        'cnn_transformer': _model_breakdown(ct_probs[0], WEIGHTS['cnn_transformer']),
    }
    return pred_label, confidence, all_probs, model_preds

def get_lime_explanation(text: str, num_features=10):
    def predict_fn(texts):
        return lr_model.predict_proba(tfidf.transform(texts))[:, REORDER_IDX]
    exp = lime_explainer.explain_instance(text, predict_fn, num_features=num_features, num_samples=300)
    return [{"word": w, "weight": round(wt, 4)} for w, wt in exp.as_list()]

CLASS_SUMMARIES = {
    'ham': "This email appears legitimate. No strong spam/phishing indicators found.",
    'spam': "Unsolicited commercial messaging - unwanted but likely not malicious.",
    'phishing': "Patterns typical of phishing - likely attempts to steal credentials or spread malware.",
}
BEST_PRACTICES = {
    'ham': [
        "Verify sender address carefully.",
        "Hover over links before clicking.",
        "Contact sender through separate channel if suspicious.",
    ],
    'spam': [
        "Don't click 'unsubscribe' in suspicious emails.",
        "Mark as spam in your email client.",
        "Don't reply or auto-reply.",
    ],
    'phishing': [
        "DO NOT click any links or download attachments.",
        "Never enter passwords via email links.",
        "Verify urgency claims through official channels.",
        "Report to IT/security team.",
        "If clicked, change passwords and enable 2FA immediately.",
    ],
}

def generate_reasoning(prediction, confidence, model_predictions, lime_features, text="", risk_info=None):
    summary = CLASS_SUMMARIES.get(prediction, "")
    preds = [info['prediction'] for info in model_predictions.values()]
    n_agree = preds.count(prediction)
    n_total = len(preds)

    if n_agree == n_total:
        consensus = f"All {n_total} models agree - strong consensus."
    elif n_agree >= n_total - 1:
        consensus = f"{n_agree} of {n_total} models agree - solid consensus."
    else:
        dissenting = [m.replace('_', ' ').title() for m, info in model_predictions.items()
                      if info['prediction'] != prediction]
        consensus = f"Models split: {n_agree}/{n_total} chose '{prediction}'. Dissenting: {', '.join(dissenting)}."

    if confidence >= 0.85: conf_note = "High confidence."
    elif confidence >= 0.6: conf_note = "Moderate confidence - consider context."
    else: conf_note = "Low confidence - mixed signals."

    key_signals = []
    if lime_features:
        positive = [f for f in lime_features if f['weight'] > 0][:5]
        negative = [f for f in lime_features if f['weight'] < 0][:3]
        if positive:
            parts = [f'"{item["word"]}"' for item in positive]
            key_signals.append(f"Words pushing toward '{prediction}': {', '.join(parts)}")
        if negative:
            parts = [f'"{item["word"]}"' for item in negative]
            key_signals.append(f"Words arguing against: {', '.join(parts)}")
        if not key_signals:
            key_signals.append("No strongly weighted words.")
    else:
        key_signals.append("Enable LIME to see word‑level signals.")

    attack_type = classify_attack(text) if text else None
    risk_story = ""
    if prediction == "phishing":
        risk_story = f"This appears to be a **{attack_type}** attempt. "
        if attack_type == "Credential Harvesting":
            risk_story += "The attacker likely aims to steal login details by impersonating a trusted service."
        elif attack_type == "Invoice/Billing Scam":
            risk_story += "The attacker tries to trick you into paying a fake invoice."
        else:
            risk_story += "The attacker uses social engineering to manipulate you."
    elif prediction == "spam":
        risk_story = "Unsolicited but likely not malicious - mass marketing spam."
    else:
        risk_story = "No malicious intent detected."
    if risk_info:
        risk_story += f" | Risk Score: {risk_info['score']}/100 ({risk_info['level']})"

    return {
        "summary": summary,
        "consensus": consensus,
        "confidence_note": conf_note,
        "key_signals": key_signals,
        "best_practices": BEST_PRACTICES.get(prediction, []),
        "attack_type": attack_type,
        "risk_story": risk_story,
        "risk_score": risk_info.get('score') if risk_info else None,
        "risk_level": risk_info.get('level') if risk_info else None,
    }

def save_scan_to_db(db, input_type, preview, prediction, confidence, breakdown):
    if db is None or ScanRecord is None:
        return ""
    try:
        scan_id = str(uuid.uuid4())
        record = ScanRecord(
            id=scan_id,
            timestamp=datetime.utcnow(),
            input_type=input_type,
            input_preview=preview[:200],
            prediction=prediction,
            confidence=float(confidence),
            model_breakdown=breakdown,
        )
        db.add(record)
        db.commit()
        return scan_id
    except Exception as e:
        logger.warning(f"Failed to save scan: {e}")
        try: db.rollback()
        except: pass
        return ""

# ===============================
# AI Chat Client (Groq + OpenRouter + Google)
# ===============================
ai_client = None
AI_PROVIDER = None
AI_MODEL = None

def init_ai_client():
    global ai_client, AI_PROVIDER, AI_MODEL

    if os.getenv("GROQ_API_KEY") and OpenAI is not None:
        ai_client = OpenAI(
            api_key=os.getenv("GROQ_API_KEY"),
            base_url="https://api.groq.com/openai/v1"
        )
        AI_PROVIDER = "groq"
        AI_MODEL = "llama-3.3-70b-versatile"
        print("[OK]  Groq AI chat ready (free Llama 3.3).")
        return

    if os.getenv("OPENROUTER_API_KEY") and OpenAI is not None:
        ai_client = OpenAI(
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1"
        )
        AI_PROVIDER = "openrouter"
        AI_MODEL = "deepseek/deepseek-chat-v3-0324"
        print("[OK]  OpenRouter AI chat ready.")
        return

    if os.getenv("GOOGLE_API_KEY") and OpenAI is not None:
        ai_client = OpenAI(
            api_key=os.getenv("GOOGLE_API_KEY"),
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
        )
        AI_PROVIDER = "google"
        AI_MODEL = "gemini-1.5-flash"
        print("[OK]  Google AI chat ready.")
        return

    ai_client = None
    AI_PROVIDER = None
    AI_MODEL = None
    print("[INFO]  AI chat not configured. Set GROQ_API_KEY, OPENROUTER_API_KEY, or GOOGLE_API_KEY.")

init_ai_client()

def build_scan_context(prediction, confidence, model_preds, lime_features, risk_info, text):
    ctx = f"Prediction: {prediction} (confidence: {confidence:.2%})\n"
    if risk_info:
        ctx += f"Risk Score: {risk_info['score']}/100 ({risk_info['level']})\n"
    if model_preds:
        ctx += "Model votes:\n"
        for name, info in model_preds.items():
            ctx += f"- {name}: {info['prediction']} (conf {info['confidence']})\n"
    if lime_features and lime_features[:5]:
        ctx += "Top LIME words:\n"
        for f in lime_features[:5]:
            ctx += f"- {f['word']} (weight {f['weight']})\n"
    ctx += f"Text snippet: {text[:200]}\n"
    return ctx

def ask_llm_about_scan(context, question):
    if not ai_client or not AI_MODEL:
        return "AI assistant not configured. Set GROQ_API_KEY, OPENROUTER_API_KEY, or GOOGLE_API_KEY."
    try:
        response = ai_client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": (
                    "You are a friendly and knowledgeable cybersecurity assistant embedded in a phishing detection tool called PhishGuard AI. "
                    "You have access to the scan context (prediction, confidence, risk score, model votes, LIME words) and you should use it to answer questions about the email or URL that was scanned. "
                    "If the user asks something unrelated to the current scan (like 'how are you?' or 'tell me a joke'), you should respond naturally and helpfully, just like a general chatbot. "
                    "Be concise but warm. If you don't know something, say so politely."
                )},
                {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"}
            ],
            max_tokens=300,
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.warning(f"LLM query failed: {e}")
        return f"Sorry, I couldn't process that: {e}"

# ===============================
# Forensic Report Generator
# ===============================
def generate_forensic_report(scan_data, output_path="phishguard_report.docx"):
    """Generate a professional DOCX forensic report."""
    if not DOCX_AVAILABLE:
        logger.error("python-docx not installed")
        return None
    
    try:
        d = scan_data
        doc = Document()
        
        section = doc.sections[0]
        section.page_width = Inches(8.5)
        section.page_height = Inches(11)
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)
        
        style = doc.styles['Normal']
        font = style.font
        font.name = 'Arial'
        font.size = Pt(11)
        font.color.rgb = RGBColor(0x22, 0x22, 0x22)
        
        # Header
        header_para = doc.add_paragraph()
        header_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = header_para.add_run("~ PHISHGUARD AI")
        run.font.size = Pt(24)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0x6C, 0x63, 0xFF)
        
        subtitle = doc.add_paragraph()
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = subtitle.add_run("Neural Forensic Analysis Report")
        run.font.size = Pt(14)
        run.font.color.rgb = RGBColor(0x8B, 0x8F, 0xA3)
        
        meta = doc.add_paragraph()
        meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = meta.add_run(f"Scan ID: {d.get('scan_id', 'N/A')} | Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(0x8B, 0x8F, 0xA3)
        
        doc.add_paragraph()
        
        # Verdict Banner (simple colored text, no shading)
        pred = d.get('prediction', 'unknown').upper()
        confidence = d.get('confidence', 0) * 100
        risk_score = d.get('reasoning', {}).get('risk_score', 0)
        risk_level = d.get('reasoning', {}).get('risk_level', 'N/A')
        
        if pred == "PHISHING":
            verdict_color = RGBColor(0xEF, 0x44, 0x44)
        elif pred == "SPAM":
            verdict_color = RGBColor(0xF5, 0x9E, 0x0B)
        else:
            verdict_color = RGBColor(0x22, 0xC5, 0x5E)
        
        banner = doc.add_paragraph()
        banner.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = banner.add_run(f"VERDICT: {pred}")
        run.font.size = Pt(20)
        run.font.bold = True
        run.font.color.rgb = verdict_color
        
        doc.add_paragraph()
        
        # Executive Summary
        doc.add_heading('Executive Summary', level=1)
        summary_table = doc.add_table(rows=3, cols=2)
        summary_table.style = 'Table Grid'
        cells_data = [
            ("Confidence", f"{confidence:.1f}%"),
            ("Risk Score", f"{risk_score}/100"),
            ("Risk Level", risk_level),
        ]
        for i, (label, value) in enumerate(cells_data):
            row = summary_table.rows[i]
            row.cells[0].text = label
            row.cells[0].paragraphs[0].runs[0].font.bold = True
            row.cells[1].text = value
        
        doc.add_paragraph()
        
        # Model Consensus
        doc.add_heading('Model Consensus', level=1)
        model_preds = d.get('model_predictions', {})
        model_table = doc.add_table(rows=len(model_preds)+1, cols=3)
        model_table.style = 'Table Grid'
        for j, header in enumerate(['Model', 'Verdict', 'Confidence']):
            cell = model_table.rows[0].cells[j]
            cell.text = header
            cell.paragraphs[0].runs[0].font.bold = True
        for i, (model_name, info) in enumerate(model_preds.items(), 1):
            model_table.rows[i].cells[0].text = model_name.replace('_', ' ').title()
            model_table.rows[i].cells[1].text = info['prediction'].upper()
            model_table.rows[i].cells[2].text = f"{info['confidence']:.1%}"
        
        doc.add_paragraph()
        
        # Attack Analysis
        reasoning = d.get('reasoning', {})
        if reasoning.get('risk_story'):
            doc.add_heading('Attack Analysis', level=1)
            story = reasoning['risk_story'].replace('**', '').replace(' | Risk Score:', '\n\nRisk Score:')
            doc.add_paragraph(story)
        
        doc.add_paragraph()
        
        # Recommendations
        practices = reasoning.get('best_practices', [])
        if practices:
            doc.add_heading('Recommended Actions', level=1)
            for action in practices:
                doc.add_paragraph(action, style='List Bullet')
        
        doc.add_paragraph()
        
        # Footer
        footer_para = doc.add_paragraph()
        footer_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = footer_para.add_run("This is an automated security analysis. Always verify findings with professional security tools.")
        run.font.size = Pt(8)
        run.font.italic = True
        run.font.color.rgb = RGBColor(0x8B, 0x8F, 0xA3)
        
        doc.save(output_path)
        logger.info(f"Report saved to {output_path}")
        return output_path
    
    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        return None

from fpdf import FPDF

def generate_forensic_report_pdf(scan_data, output_path="phishguard_report.pdf"):
    """Generate a professional PDF forensic report."""
    d = scan_data
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(108, 99, 255)
    pdf.cell(0, 12, "PHISHGUARD AI", ln=True, align="C")
    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(139, 143, 163)
    pdf.cell(0, 8, "Neural Forensic Analysis Report", ln=True, align="C")
    pdf.cell(0, 6, f"Scan ID: {d.get('scan_id', 'N/A')} | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", ln=True, align="C")
    pdf.ln(6)
    
    # Verdict Banner
    pred = d.get('prediction', 'unknown').upper()
    confidence = d.get('confidence', 0) * 100
    risk_score = d.get('reasoning', {}).get('risk_score', 0)
    risk_level = d.get('reasoning', {}).get('risk_level', 'N/A')
    
    if pred == "PHISHING":
        r, g, b = 239, 68, 68
    elif pred == "SPAM":
        r, g, b = 245, 158, 11
    else:
        r, g, b = 34, 197, 94
    
    pdf.set_fill_color(r, g, b)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 14, f"VERDICT: {pred}", ln=True, align="C", fill=True)
    pdf.ln(4)
    
    # Executive Summary
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Executive Summary", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"Confidence: {confidence:.1f}%", ln=True)
    pdf.cell(0, 7, f"Risk Score: {risk_score}/100 ({risk_level})", ln=True)
    pdf.ln(4)
    
    # Model Consensus
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Model Consensus", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for model, info in d.get('model_predictions', {}).items():
        pdf.cell(0, 6, f"{model.replace('_', ' ').title()}: {info['prediction'].upper()} (conf: {info['confidence']:.1%})", ln=True)
    pdf.ln(4)
    
    # Attack Analysis
    reasoning = d.get('reasoning', {})
    if reasoning.get('risk_story'):
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Attack Analysis", ln=True)
        pdf.set_font("Helvetica", "", 10)
        story = reasoning['risk_story'].replace('**', '').replace(' | Risk Score:', '')
        pdf.multi_cell(0, 6, story)
        pdf.ln(3)
    
    # Recommendations
    practices = reasoning.get('best_practices', [])
    if practices:
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Recommended Actions", ln=True)
        pdf.set_font("Helvetica", "", 10)
        for i, p in enumerate(practices, 1):
            pdf.cell(0, 6, f"{i}. {p}", ln=True)
    
    # Footer
    pdf.ln(8)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(139, 143, 163)
    pdf.cell(0, 6, "This is an automated security analysis. Always verify with professional tools.", ln=True, align="C")
    
    pdf.output(output_path)
    return output_path

import whois
from datetime import datetime, timedelta

# Simple cache: domain -> (age_days, timestamp)
_whois_cache = {}

def get_domain_age_days(domain: str) -> Optional[int]:
    """Return domain age in days, or None if unavailable. Uses a 1-hour cache."""
    domain = domain.lower().strip()
    now = datetime.utcnow()

    # Check cache
    if domain in _whois_cache:
        age, timestamp = _whois_cache[domain]
        if now - timestamp < timedelta(hours=1):
            return age

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if creation_date is None:
            age = None
        else:
            # Handle lists (some WHOIS returns multiple dates)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(creation_date, datetime):
                age = (now - creation_date).days
            else:
                age = None
    except Exception:
        age = None

    # Cache the result
    _whois_cache[domain] = (age, datetime.utcnow())
    return age

# ===============================
# Endpoints
# ===============================
@app.post("/predict/email", response_model=ScanResponse)
def predict_email(request: EmailRequest, db: Session = Depends(db_dep)):
    pred_label, confidence, all_probs, model_preds = predict_email_ensemble(request.text)
    explanation = get_lime_explanation(request.text) if request.explain else None
    risk_info = compute_risk_score(pred_label, confidence, request.text)
    reasoning = generate_reasoning(pred_label, confidence, model_preds, explanation,
                                   text=request.text, risk_info=risk_info)
    scan_id = save_scan_to_db(db, "email", request.text, pred_label, confidence, model_preds)
    return ScanResponse(
        prediction=pred_label, confidence=round(confidence, 4),
        all_probabilities=all_probs, model_predictions=model_preds,
        explanation=explanation, reasoning=reasoning, scan_id=scan_id, warning=None
    )

@app.post("/predict/url", response_model=URLResponse)
def predict_url(request: URLRequest, db: Session = Depends(db_dep)):
    domain = extract_domain(request.url)
    if domain in TRUSTED_DOMAINS:
        label = "legitimate"
        confidence = 1.0
        risk_info = {"score": 0.0, "level": "Low"}
        breakdown = {
            'gradient_boosting': {
                'prediction': label, 'confidence': 1.0, 'weight': 1.0,
                'probabilities': {'legitimate': 1.0, 'phishing': 0.0}
            }
        }
        reasoning = generate_reasoning(label, confidence, breakdown, None, text=request.url, risk_info=risk_info)
        scan_id = save_scan_to_db(db, "url", request.url, label, confidence, breakdown)
        return URLResponse(
            url=request.url, prediction=label, confidence=1.0, features={},
            all_probabilities={'legitimate': 1.0, 'phishing': 0.0},
            model_predictions=breakdown, scan_id=scan_id, warning=None, reasoning=reasoning
        )

    features = extract_url_features(request.url)
    # Live WHOIS domain age
    domain = extract_domain(request.url)
    age_days = get_domain_age_days(domain)
    if age_days is not None:
        features['domain_age_days'] = age_days
    else:
        features['domain_age_days'] = 365  # fallback if lookup fails
    X = np.array([[features[f] for f in get_feature_names()]])
    pred = int(url_model.predict(X)[0])
    proba = url_model.predict_proba(X)[0]
    label = "phishing" if pred == 1 else "legitimate"
    confidence = float(proba[pred])
    if label == "phishing" and confidence < 0.8:
        label = "suspicious"
    
    risk_info = compute_risk_score(label, confidence, request.url, url_features=features)
    breakdown = {
        'gradient_boosting': {
            'prediction': label, 'confidence': round(confidence, 4), 'weight': 1.0,
            'probabilities': {
                'legitimate': round(float(proba[0]), 4),
                'phishing': round(float(proba[1]), 4),
            },
        },
    }
    reasoning = generate_reasoning(label, confidence, breakdown, None, text=request.url, risk_info=risk_info)
    if age_days is not None and age_days < 30:
        reasoning['risk_story'] = (
            f"Domain registered only {age_days} days ago. " + reasoning.get('risk_story', '')
        )
    scan_id = save_scan_to_db(db, "url", request.url, label, confidence, breakdown)
    return URLResponse(
        url=request.url, prediction=label, confidence=round(confidence, 4),
        features=features,
        all_probabilities={'legitimate': round(float(proba[0]), 4), 'phishing': round(float(proba[1]), 4)},
        model_predictions=breakdown, scan_id=scan_id, warning=None, reasoning=reasoning
    )

@app.post("/predict/image", response_model=ImageResponse)
async def predict_image(file: UploadFile = File(...), explain: bool = Query(True), db: Session = Depends(db_dep)):
    if not OCR_AVAILABLE:
        raise HTTPException(503, "OCR Not Installed")
    image_bytes = await file.read()
    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    extracted = pytesseract.image_to_string(img).strip()
    if len(extracted) < 10:
        raise HTTPException(422, "No text found.")
    
    pred_label, confidence, all_probs, model_preds = predict_email_ensemble(extracted)
    explanation = get_lime_explanation(extracted) if explain else None
    risk_info = compute_risk_score(pred_label, confidence, extracted)
    reasoning = generate_reasoning(pred_label, confidence, model_preds, explanation,
                                   text=extracted, risk_info=risk_info)
    scan_id = save_scan_to_db(db, "image", extracted, pred_label, confidence, model_preds)
    return ImageResponse(
        extracted_text=extracted, char_count=len(extracted),
        prediction=pred_label, confidence=round(confidence, 4),
        all_probabilities=all_probs, model_predictions=model_preds,
        explanation=explanation, reasoning=reasoning, scan_id=scan_id, warning=None
    )

@app.post("/predict/batch")
async def predict_batch(items: List[Dict[str, Any]], db: Session = Depends(db_dep)):
    results = []
    for idx, item in enumerate(items):
        try:
            if "text" in item:
                pred_label, confidence, all_probs, model_preds = predict_email_ensemble(item["text"])
                risk_info = compute_risk_score(pred_label, confidence, item["text"])
                reasoning = generate_reasoning(pred_label, confidence, model_preds, None, text=item["text"], risk_info=risk_info)
                scan_id = save_scan_to_db(db, "email", item["text"], pred_label, confidence, model_preds)
                results.append({
                    "index": idx, "type": "email",
                    "prediction": pred_label, "confidence": round(confidence, 4),
                    "risk_score": risk_info["score"], "risk_level": risk_info["level"],
                    "scan_id": scan_id, "warning": None
                })
            elif "url" in item:
                domain = extract_domain(item["url"])
                if domain in TRUSTED_DOMAINS:
                    label = "legitimate"
                    confidence = 1.0
                    risk_info = {"score": 0.0, "level": "Low"}
                else:
                    features = extract_url_features(item["url"])
                    X = np.array([[features[f] for f in get_feature_names()]])
                    pred = int(url_model.predict(X)[0])
                    proba = url_model.predict_proba(X)[0]
                    label = "phishing" if pred == 1 else "legitimate"
                    confidence = float(proba[pred])
                    if label == "phishing" and confidence < 0.8:
                        label = "suspicious"
                    risk_info = compute_risk_score(label, confidence, item["url"], url_features=features)
                scan_id = save_scan_to_db(db, "url", item["url"], label, confidence, {})
                results.append({
                    "index": idx, "type": "url",
                    "prediction": label, "confidence": round(confidence, 4),
                    "risk_score": risk_info["score"], "risk_level": risk_info["level"],
                    "scan_id": scan_id, "warning": None
                })
            else:
                results.append({"index": idx, "error": "item must have 'text' or 'url'"})
        except Exception as e:
            logger.warning(f"Batch item {idx} failed: {e}")
            results.append({"index": idx, "error": str(e)})
    return {"total": len(items), "results": results}

@app.post("/ask")
def ask_analyst(request: AskRequest):
    risk_info = None
    if request.reasoning:
        risk_info = {
            "score": request.reasoning.get("risk_score"),
            "level": request.reasoning.get("risk_level")
        }
    context = build_scan_context(
        request.prediction, request.confidence, request.model_predictions,
        request.explanation, risk_info, request.text or ""
    )
    answer = ask_llm_about_scan(context, request.question)
    return {"question": request.question, "answer": answer}

class ThinkingRequest(BaseModel):
    text: str
    prediction: Optional[str] = None

@app.post("/thinking")
def get_ai_thinking(request: ThinkingRequest):
    if not ai_client or not AI_MODEL:
        return {"thinking": "AI assistant not configured."}

    prompt = (
        "You are a cybersecurity expert. Analyze this email step‑by‑step for phishing indicators. "
        "Look for: urgency, credential requests, suspicious links, grammar, sender impersonation. "
        "Explain your reasoning in plain English, as if teaching a colleague. Keep it under 200 words.\n\n"
        f"Email:\n{request.text}\n"
    )
    if request.prediction:
        prompt += f"\nThe ensemble classifier predicts: {request.prediction}. "

    try:
        response = ai_client.chat.completions.create(
            model=AI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=250,
            temperature=0.3
        )
        return {"thinking": response.choices[0].message.content}
    except Exception as e:
        logger.warning(f"AI thinking failed: {e}")
        return {"thinking": "Could not generate reasoning."}

@app.post("/predict/visual")
async def predict_visual(request: VisualRequest):
    if vision_model is None or vision_processor is None:
        return {"analysis": "Local vision model not loaded. Set init_vision_model() to load at startup."}
    
    try:
        image_bytes = base64.b64decode(request.image_base64)
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception:
        return {"analysis": "Invalid image data."}
    
    prompt = (
        "Analyze this screenshot for phishing indicators. Look for: "
        "1. Brand impersonation (fake logos, similar domain names) "
        "2. Suspicious UI elements (fake URL bars, missing lock icons) "
        "3. Urgency or fear-inducing language in the text "
        "4. Password or credential request fields "
        "5. Poor grammar or design quality "
        "Be concise but specific. If the page looks legitimate, say so. Limit your response to 150 words."
    )
    
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "image", "image": image},
                {"type": "text", "text": prompt}
            ]
        }
    ]
    
    try:
        text = vision_processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = vision_processor(text=[text], images=[image], return_tensors="pt").to(vision_model.device)
        generated_ids = vision_model.generate(**inputs, max_new_tokens=200)
        generated_ids_trimmed = [
            out_ids[len(in_ids):] for in_ids, out_ids in zip(inputs.input_ids, generated_ids)
        ]
        answer = vision_processor.batch_decode(generated_ids_trimmed, skip_special_tokens=True)[0]
        return {"analysis": answer.strip()}
    except Exception as e:
        logger.warning(f"Local vision analysis failed: {e}")
        return {"analysis": "Could not analyze the screenshot at this moment."}

@app.post("/report")
def generate_report(request: ReportRequest):
    if not DOCX_AVAILABLE:
        raise HTTPException(503, "Report generation requires python-docx. Install with: pip install python-docx")
    report_path = generate_forensic_report(request.dict())
    if report_path is None:
        raise HTTPException(500, "Failed to generate report.")
    return FileResponse(
        report_path,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=f"phishguard_report_{request.scan_id or 'scan'}.docx"
    )
@app.post("/report/pdf")
def generate_report_pdf(request: ReportRequest):
    report_path = generate_forensic_report_pdf(request.dict())
    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"phishguard_report_{request.scan_id or 'scan'}.pdf"
    )

# ===============================
# Feedback & Admin Endpoints
# ===============================
@app.post("/feedback")
def submit_feedback(fb: FeedbackRequest):
    with get_feedback_conn() as conn:
        conn.execute(
            "INSERT INTO feedback (scan_id, user_label, model_prediction, input_text) VALUES (?, ?, ?, ?)",
            (fb.scan_id, fb.user_label, fb.model_prediction, fb.input_text)
        )
        conn.commit()
    return {"message": "Feedback recorded"}

@app.get("/admin/feedback")
def get_feedback(limit: int = 50):
    with get_feedback_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, scan_id, user_label, model_prediction, input_text, timestamp FROM feedback ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [{"id": r["id"], "scan_id": r["scan_id"], "user_label": r["user_label"],
             "model_prediction": r["model_prediction"], "preview": r["input_text"][:100] if r["input_text"] else "",
             "timestamp": r["timestamp"]} for r in rows]

@app.get("/admin/whitelist")
def get_whitelist():
    return {"domains": sorted(list(TRUSTED_DOMAINS))}

@app.post("/admin/whitelist")
def add_to_whitelist(req: WhitelistRequest):
    domain = req.domain.strip().lower()
    if not domain:
        raise HTTPException(400, "Domain cannot be empty")
    if "://" in domain:
        domain = extract_domain(domain)
    TRUSTED_DOMAINS.add(domain)
    save_whitelist(TRUSTED_DOMAINS)
    return {"message": f"Added {domain}", "domains": sorted(list(TRUSTED_DOMAINS))}

@app.delete("/admin/whitelist")
def remove_from_whitelist(domain: str):
    domain = domain.strip().lower()
    if domain in TRUSTED_DOMAINS:
        TRUSTED_DOMAINS.remove(domain)
        save_whitelist(TRUSTED_DOMAINS)
        return {"message": f"Removed {domain}", "domains": sorted(list(TRUSTED_DOMAINS))}
    raise HTTPException(404, f"Domain {domain} not in whitelist")

def retrain_meta():
    global meta_model, use_meta_learner

    val_path = "validation_data.csv"
    if not os.path.exists(val_path):
        logger.warning("validation_data.csv not found - cannot retrain with full class coverage.")
        return

    import pandas as pd
    val_df = pd.read_csv(val_path)
    base_texts = val_df["clean_text"].fillna("").tolist()
    base_labels = val_df["label"].tolist()

    base_X = []
    base_y = []
    for text, label in zip(base_texts, base_labels):
        if label not in LABEL_MAP:
            continue
        text_tfidf = tfidf.transform([text])
        lr_probs = lr_model.predict_proba(text_tfidf)[:, REORDER_IDX][0]
        svm_probs = svm_model.predict_proba(text_tfidf)[:, REORDER_IDX][0]
        encoding = tokenizer(text, padding='max_length', truncation=True, max_length=MAX_LEN, return_tensors='pt')
        with torch.no_grad():
            db_logits = distilbert_model(encoding['input_ids'].to(DEVICE), encoding['attention_mask'].to(DEVICE))
            db_probs = torch.softmax(db_logits, dim=-1).cpu().numpy()[0]
            ct_logits = cnn_transformer(encoding['input_ids'].to(DEVICE), encoding['attention_mask'].to(DEVICE))
            ct_probs = torch.softmax(ct_logits, dim=-1).cpu().numpy()[0]
        base_X.append(np.concatenate([lr_probs, svm_probs, db_probs, ct_probs]))
        base_y.append(LABEL_MAP[label])

    with get_feedback_conn() as conn:
        rows = conn.execute(
            "SELECT input_text, user_label FROM feedback WHERE user_label != model_prediction"
        ).fetchall()

    new_texts = []
    new_labels = []
    for row in rows:
        text, label = row[0], row[1]
        if label in LABEL_MAP:
            new_texts.append(text)
            new_labels.append(label)

    for text, label in zip(new_texts, new_labels):
        text_tfidf = tfidf.transform([text])
        lr_probs = lr_model.predict_proba(text_tfidf)[:, REORDER_IDX][0]
        svm_probs = svm_model.predict_proba(text_tfidf)[:, REORDER_IDX][0]
        encoding = tokenizer(text, padding='max_length', truncation=True, max_length=MAX_LEN, return_tensors='pt')
        with torch.no_grad():
            db_logits = distilbert_model(encoding['input_ids'].to(DEVICE), encoding['attention_mask'].to(DEVICE))
            db_probs = torch.softmax(db_logits, dim=-1).cpu().numpy()[0]
            ct_logits = cnn_transformer(encoding['input_ids'].to(DEVICE), encoding['attention_mask'].to(DEVICE))
            ct_probs = torch.softmax(ct_logits, dim=-1).cpu().numpy()[0]
        base_X.append(np.concatenate([lr_probs, svm_probs, db_probs, ct_probs]))
        base_y.append(LABEL_MAP[label])

    if not base_X:
        logger.info("No data for retraining.")
        return

    X_all = np.array(base_X)
    y_all = np.array(base_y)

    from xgboost import XGBClassifier
    new_meta = XGBClassifier(
        n_estimators=100, max_depth=3, learning_rate=0.1,
        use_label_encoder=False, eval_metric='mlogloss', random_state=42
    )
    new_meta.fit(X_all, y_all)
    joblib.dump(new_meta, META_PATH)

    meta_model = new_meta
    use_meta_learner = True
    logger.info(f"Meta-learner retrained on {len(base_texts)} validation + {len(new_texts)} feedback samples.")

@app.post("/admin/retrain")
def trigger_retrain(background_tasks: BackgroundTasks):
    background_tasks.add_task(retrain_meta)
    return {"message": "Retraining started in background. The new meta-learner will be active within a minute."}

# ===============================
# Standard Endpoints
# ===============================
@app.get("/history")
def get_history(limit: int = Query(20), db: Session = Depends(db_dep)):
    if db is None or ScanRecord is None:
        return []
    try:
        records = db.query(ScanRecord).order_by(ScanRecord.timestamp.desc()).limit(limit).all()
        return [{
            "id": r.id, "timestamp": r.timestamp.isoformat(),
            "type": r.input_type, "preview": r.input_preview,
            "prediction": r.prediction, "confidence": r.confidence,
            "feedback": getattr(r, 'feedback', None),
        } for r in records]
    except Exception as e:
        logger.warning(f"history query failed: {e}")
        return []

@app.get("/analytics/summary")
def get_analytics_summary(db: Session = Depends(db_dep)):
    if db is None or ScanRecord is None:
        return {
            "total_scans": 0, "avg_confidence": 0.0,
            "distribution": {"ham": 0, "spam": 0, "phishing": 0, "legitimate": 0},
            "recent_scans": []
        }
    try:
        records = db.query(ScanRecord).all()
        if not records:
            return {
                "total_scans": 0, "avg_confidence": 0.0,
                "distribution": {"ham": 0, "spam": 0, "phishing": 0, "legitimate": 0},
                "recent_scans": []
            }
        dist = {"ham": 0, "spam": 0, "phishing": 0, "legitimate": 0}
        for r in records:
            if r.prediction in dist:
                dist[r.prediction] += 1
        return {
            "total_scans": len(records),
            "avg_confidence": sum(r.confidence for r in records) / len(records),
            "distribution": dist,
            "recent_scans": sorted([{
                "timestamp": r.timestamp.isoformat(), "confidence": r.confidence,
            } for r in records], key=lambda x: x["timestamp"], reverse=True)[:50],
        }
    except Exception as e:
        logger.warning(f"analytics query failed: {e}")
        return {
            "total_scans": 0, "avg_confidence": 0.0,
            "distribution": {"ham": 0, "spam": 0, "phishing": 0, "legitimate": 0},
            "recent_scans": []
        }

@app.get("/app")
def serve_frontend():
    return FileResponse("frontend.html")

@app.get("/")
def root():
    return {
        "message": "PhishGuard AI API",
        "frontend": "/app",
        "docs": "/docs",
        "endpoints": {
            "/predict/email": "POST - Classify email",
            "/predict/url": "POST - Check URL",
            "/predict/image": "POST - Classify screenshot (OCR)",
            "/predict/batch": "POST - Batch scan",
            "/predict/visual": "POST - AI visual forensics",
            "/ask": "POST - Ask AI analyst",
            "/report": "POST - Download forensic report",
            "/history": "GET - Recent scans",
            "/analytics/summary": "GET - Aggregate stats",
        },
        "database_enabled": DB_AVAILABLE,
        "ocr_enabled": OCR_AVAILABLE,
        "meta_learner_active": use_meta_learner,
        "ai_chat_provider": AI_PROVIDER,
        "ai_chat_model": AI_MODEL,
    }

@app.get("/health")
def health():
    return {"status": "ok", "db": DB_AVAILABLE, "ocr": OCR_AVAILABLE}