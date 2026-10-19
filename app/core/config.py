import os, torch
from typing import Optional
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MODELS_DIR: str = "models"
    FRONTEND_FILE: str = "frontend.html"
    VALIDATION_DATA: str = "validation_data.csv"
    TFIDF_PATH: str = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")
    LR_PATH: str = os.path.join(MODELS_DIR, "logistic_regression.pkl")
    RF_PATH: str = os.path.join(MODELS_DIR, "rf_model.pkl")
    ENSEMBLE_CONFIG_PATH: str = os.path.join(MODELS_DIR, "ensemble_config.pkl")
    DEBERTA_PATH: str = os.path.join(MODELS_DIR, "deberta_dense.pth")
    DEBERTA_TOKENIZER_PATH: str = os.path.join(MODELS_DIR, "deberta_tokenizer")
    DISTILROBERTA_PATH: str = os.path.join(MODELS_DIR, "distilroberta.pth")
    DISTILROBERTA_TOKENIZER_PATH: str = os.path.join(MODELS_DIR, "distilroberta_tokenizer")
    CNN_TRANSFORMER_PATH: str = os.path.join(MODELS_DIR, "cnn_transformer.pth")  # legacy
    DISTILBERT_PATH: str = os.path.join(MODELS_DIR, "distilbert_dense.pth")      # legacy
    URL_MODEL_PATH: str = os.path.join(MODELS_DIR, "url_phishing_model.pkl")
    URL_TRANSFORMER_PATH: str = os.path.join(MODELS_DIR, "url_transformer.pth")
    URL_TRANSFORMER_TOKENIZER_PATH: str = os.path.join(MODELS_DIR, "url_transformer_tokenizer")
    URL_TRANSFORMER_MAX_LEN: int = 128
    META_LEARNER_PATH: str = os.path.join(MODELS_DIR, "meta_learner.pkl")
    META_LABEL_ENCODER_PATH: str = os.path.join(MODELS_DIR, "meta_label_encoder.pkl")
    TOKENIZER_PATH: str = os.path.join(MODELS_DIR, "distilbert_tokenizer")       # legacy
    FEEDBACK_DB: str = "feedback.db"
    AUDIT_LOG_PATH: str = "audit.log"
    EVAL_RESULTS_PATH: str = "eval_results.json"
    EVAL_MAX_SAMPLES: int = 500
    WHITELIST_FILE: str = os.path.join(MODELS_DIR, "domain_whitelist.json")
    MAX_LEN: int = 256
    BATCH_SIZE: int = 16
    DEVICE: str = "cuda" if torch.cuda.is_available() else "cpu"
    GROQ_API_KEY: Optional[str] = None
    OPENROUTER_API_KEY: Optional[str] = None
    GOOGLE_API_KEY: Optional[str] = None
    VT_API_KEY: Optional[str] = None           # VirusTotal v3
    OTX_API_KEY: Optional[str] = None          # AlienVault OTX
    PHISHTANK_APP_KEY: Optional[str] = None    # PhishTank (optional)
    VISION_MODEL_ID: str = "Qwen/Qwen2-VL-2B-Instruct"
    ADMIN_EMAIL: str = ""          # F-31: if set, only this email gets admin role on first OAuth login
    ADMIN_PASSWORD: str = "phishguard2025"
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    MICROSOFT_CLIENT_ID: str = ""
    MICROSOFT_CLIENT_SECRET: str = ""
    OAUTH_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth"
    SESSION_SECRET: str = "replace-me-with-a-random-secret"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

settings = Settings()