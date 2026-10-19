"""Phase 5 - QR code detection from screenshots."""
from PIL import Image
import io


def detect_qr_codes(image_bytes: bytes) -> dict:
    result = {"found": False, "codes": [], "warning": None}
    try:
        from pyzbar.pyzbar import decode as pyzbar_decode
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        decoded = pyzbar_decode(img)
        for obj in decoded:
            data = obj.data.decode("utf-8", errors="replace")
            result["codes"].append({"type": str(obj.type), "data": data})
        result["found"] = bool(result["codes"])
        if result["found"]:
            result["warning"] = f"Found {len(result['codes'])} QR code(s) - each embedded URL should be scanned separately."
    except ImportError:
        result["warning"] = "pyzbar not installed. Install with: pip install pyzbar"
    except Exception as e:
        result["warning"] = f"QR detection error: {e}"
    return result
