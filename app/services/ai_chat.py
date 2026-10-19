import logging
import torch
from openai import OpenAI
from app.core.config import settings

logger = logging.getLogger(__name__)

# Global variables - set by init_ai_client()
ai_client = None
AI_PROVIDER = None
AI_MODEL = None


def init_ai_client():
    global ai_client, AI_PROVIDER, AI_MODEL

    if settings.GROQ_API_KEY:
        ai_client = OpenAI(
            api_key=settings.GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1"
        )
        AI_PROVIDER = "groq"
        AI_MODEL = "llama-3.3-70b-versatile"
        print("[OK]  Groq AI chat ready (free Llama 3.3).")
        return

    if settings.OPENROUTER_API_KEY:
        ai_client = OpenAI(
            api_key=settings.OPENROUTER_API_KEY,
            base_url="https://openrouter.ai/api/v1"
        )
        AI_PROVIDER = "openrouter"
        AI_MODEL = "deepseek/deepseek-chat-v3-0324"
        print("[OK]  OpenRouter AI chat ready.")
        return

    if settings.GOOGLE_API_KEY:
        ai_client = OpenAI(
            api_key=settings.GOOGLE_API_KEY,
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
        )
        AI_PROVIDER = "google"
        AI_MODEL = "gemini-1.5-flash"
        print("[OK]  Google AI chat ready.")
        return

    print("[INFO]  AI chat not configured.")


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
    SYSTEM = (
        "You are a friendly cybersecurity assistant. "
        "Use the scan context when relevant, but answer naturally for general questions. "
        "Be concise and clear - aim for under 150 words."
    )
    user_msg = f"Context:\n{context}\n\nQuestion: {question}" if context.strip() else question

    # 1. Cloud API first - fast (< 2s on Groq)
    if ai_client and AI_MODEL:
        try:
            response = ai_client.chat.completions.create(
                model=AI_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": user_msg},
                ],
                max_tokens=250,
                temperature=0.3,
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.warning(f"Cloud LLM failed: {e}")

    # 2. Local vision model fallback - slower but free
    try:
        from app.services.vision_forensics import vision_model, vision_processor
        if vision_model is not None and vision_processor is not None:
            prompt = f"{SYSTEM}\n\n{user_msg}"
            messages = [{"role": "user", "content": prompt}]
            text = vision_processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            inputs = vision_processor(text=[text], images=None, return_tensors="pt").to(vision_model.device)
            with torch.no_grad():
                generated_ids = vision_model.generate(**inputs, max_new_tokens=200, temperature=0.3)
            trimmed = [out[len(inp):] for inp, out in zip(inputs.input_ids, generated_ids)]
            return vision_processor.batch_decode(trimmed, skip_special_tokens=True)[0].strip()
    except Exception as e:
        logger.warning(f"Local LLM failed: {e}")

    return "AI assistant not configured. Set GROQ_API_KEY, OPENROUTER_API_KEY, or GOOGLE_API_KEY in your .env file for fast responses."