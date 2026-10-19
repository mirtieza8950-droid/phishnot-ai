import torch
from transformers import Qwen2_5_VLForConditionalGeneration, AutoProcessor
from PIL import Image
import warnings
warnings.filterwarnings("ignore")

model_id = "Qwen/Qwen2.5-VL-3B-Instruct"

# Load model in 4‑bit to fit your GTX 1660 (6 GB)
model = Qwen2_5_VLForConditionalGeneration.from_pretrained(
    model_id,
    torch_dtype=torch.float16,
    device_map="auto",
    load_in_4bit=True
)
processor = AutoProcessor.from_pretrained(model_id)

def analyze_screenshot(image_path):
    """Return a short forensic description of the image."""
    image = Image.open(image_path).convert("RGB")
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "image", "image": image},
                {"type": "text", "text": "Is this page trying to impersonate a legitimate brand? Describe any suspicious elements."}
            ]
        }
    ]
    # Apply chat template
    text = processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = processor(text=[text], images=[image], return_tensors="pt").to(model.device)
    # Generate answer
    generated_ids = model.generate(**inputs, max_new_tokens=256)
    generated_ids_trimmed = [
        out_ids[len(in_ids):] for in_ids, out_ids in zip(inputs.input_ids, generated_ids)
    ]
    answer = processor.batch_decode(generated_ids_trimmed, skip_special_tokens=True)[0]
    return answer.strip()

if __name__ == "__main__":
    # Quick test - replace with your own screenshot path
    result = analyze_screenshot("test_screenshot.png")
    print("Visual analysis:", result)