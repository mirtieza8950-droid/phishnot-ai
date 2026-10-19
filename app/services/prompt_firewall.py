"""
Prompt injection detection firewall.
Blocks known jailbreak patterns in AI chat and thinking endpoints.
"""
import re

INJECTION_PATTERNS = [
    r"ignore (all )?(previous|above|prior) (instructions?|prompts?|rules?)",
    r"disregard (all )?(previous|above|prior) (instructions?|prompts?|rules?)",
    r"forget (all )?(previous|above|prior) (instructions?|prompts?|rules?)",
    r"you are now (a |an )?(evil|malicious|unethical|rogue|unrestricted|unfiltered)",
    r"new (system )?instructions?:",
    r"system prompt:",
    r"reveal (your )?(system |hidden |initial )?prompt",
    r"show (your )?(system |hidden |initial )?instructions?",
    r"what (is|are) (your )?(system |hidden |initial )?prompt",
    r"pretend (you are|to be) (a |an )?(different|another)",
    r"you are not (an |a )?(AI|assistant|language model)",
    r"jailbreak",
    r"dan mode",
    r"developer mode",
    r"bypass (your )?(restrictions?|safety|guidelines?)",
]

def detect_injection(text: str) -> bool:
    """Return True if the text contains known injection patterns."""
    text_lower = text.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            return True
    return False

def sanitize(text: str, max_length: int = 2000) -> str:
    """Truncate and strip potentially dangerous characters."""
    return text[:max_length].strip()