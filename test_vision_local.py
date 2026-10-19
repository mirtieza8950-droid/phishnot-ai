import torch
from transformers import Qwen2_5_VLForConditionalGeneration, AutoProcessor
from PIL import Image

model_id = "Qwen/Qwen2.5-VL-3B-Instruct"

print("Loading local vision model (this may take 30 seconds on first run)...")
model = Qwen2_5_VLForConditionalGeneration.from_pretrained(
    model_id,
    torch_dtype=torch.float16,
    device_map="auto",
    load_in_4bit=True
)
processor = AutoProcessor.from_pretrained(model_id)

def analyze_screenshot(image_path):
    image = Image.open(image_path).convert("RGB")
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "image", "image": image},
                {"type": "text", "text": (
                    "Analyze this screenshot for phishing indicators. Look for: "
                    "1. Brand impersonation (fake logos, similar domain names) "
                    "2. Suspicious UI elements (fake URL bars, missing lock icons) "
                    "3. Urgency or fear-inducing language in the text "
                    "4. Password or credential request fields "
                    "5. Poor grammar or design quality "
                    "Be concise but specific. If the page looks legitimate, say so. "
                    "Limit your response to 150 words."
                )}
            ]
        }
    ]
    text = processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = processor(text=[text], images=[image], return_tensors="pt").to(model.device)
    generated_ids = model.generate(**inputs, max_new_tokens=256)
    generated_ids_trimmed = [
        out_ids[len(in_ids):] for in_ids, out_ids in zip(inputs.input_ids, generated_ids)
    ]
    answer = processor.batch_decode(generated_ids_trimmed, skip_special_tokens=True)[0]
    return answer.strip()

if __name__ == "__main__":
    # Test with any screenshot you have
    result = analyze_screenshot("test_screenshot.png")
    print("Visual Analysis:", result)