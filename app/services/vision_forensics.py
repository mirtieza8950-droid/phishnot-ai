import torch
from transformers import Qwen2VLForConditionalGeneration, AutoProcessor, BitsAndBytesConfig
from app.core.config import settings

vision_model = None
vision_processor = None
_vision_attempted = False


def _ensure_vision_loaded():
    global vision_model, vision_processor, _vision_attempted
    if _vision_attempted:
        return
    _vision_attempted = True
    try:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4"
        )
        vision_model = Qwen2VLForConditionalGeneration.from_pretrained(
            settings.VISION_MODEL_ID,
            torch_dtype=torch.float16,
            device_map="auto",
            quantization_config=bnb_config
        )
        vision_processor = AutoProcessor.from_pretrained(settings.VISION_MODEL_ID)
        print("[OK]  Local vision model ready (Qwen2-VL-2B).")
    except Exception as e:
        print(f"[WARN] Local vision model not available: {e}")


def analyze_screenshot(image_base64: str) -> str:
    _ensure_vision_loaded()
    if vision_model is None or vision_processor is None:
        return "Local vision model not loaded."

    import io, base64
    from PIL import Image

    try:
        image_bytes = base64.b64decode(image_base64)
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception:
        return "Invalid image data."

    prompt = (
        "Analyze this screenshot for phishing indicators. Look for: "
        "1. Brand impersonation 2. Suspicious UI elements 3. Urgency/fear language "
        "4. Password/credential fields 5. Poor grammar/design. Be concise, 150 words max."
    )

    messages = [
        {"role": "user", "content": [
            {"type": "image", "image": image},
            {"type": "text", "text": prompt}
        ]}
    ]

    try:
        text = vision_processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = vision_processor(text=[text], images=[image], return_tensors="pt").to(vision_model.device)
        generated_ids = vision_model.generate(**inputs, max_new_tokens=200)
        generated_ids_trimmed = [
            out_ids[len(in_ids):] for in_ids, out_ids in zip(inputs.input_ids, generated_ids)
        ]
        answer = vision_processor.batch_decode(generated_ids_trimmed, skip_special_tokens=True)[0]
        return answer.strip()
    except Exception as e:
        return f"Could not analyze screenshot: {e}"
