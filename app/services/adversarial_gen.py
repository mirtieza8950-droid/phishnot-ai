"""
Adversarial training data generator.

Applies text-perturbation strategies to phishing/spam seed text to produce
variants that may evade the classifier. Each variant is scored by the live
ensemble so the caller can see which ones actually fool the model.

Produced variants can be exported as CSV to augment the training set.
"""

import random, re, unicodedata
from dataclasses import dataclass, field

# ── Homoglyph table (ASCII -> lookalike Unicode) ──────────────────────────────
# Uses Cyrillic / Greek confusables that render identically in most fonts.
_HOMOGLYPHS: dict[str, str] = {
    "a": "а",   # Cyrillic а (U+0430)
    "c": "с",   # Cyrillic с (U+0441)
    "e": "е",   # Cyrillic е (U+0435)
    "i": "і",   # Ukrainian і (U+0456)
    "j": "ϳ",   # Greek letter yot (U+03F3)
    "o": "о",   # Cyrillic о (U+043E)
    "p": "р",   # Cyrillic р (U+0440)
    "s": "ѕ",   # Cyrillic dze (U+0455)
    "x": "х",   # Cyrillic х (U+0445)
    "y": "у",   # Cyrillic у (U+0443)
}

# ── Leetspeak table ───────────────────────────────────────────────────────────
_LEET: dict[str, str] = {
    "a": "@", "e": "3", "i": "!", "l": "1",
    "o": "0", "s": "$", "t": "7", "g": "9",
}

# ── Phishing-keyword regex (targets the most suspicious words) ───────────────
_PHISH_WORDS = re.compile(
    r"\b(verify|account|password|login|secure|update|confirm|click|"
    r"suspend|urgent|immediately|bank|credential|access|unusual|"
    r"limited|review|validate|authenticate|invoice|payment|transfer)\b",
    re.IGNORECASE,
)

# ── Benign filler phrases inserted to dilute phishing signal ─────────────────
_FILLERS = [
    "as part of our standard process",
    "following industry best practices",
    "in accordance with our privacy policy",
    "as a valued customer",
    "for your convenience",
    "to enhance your experience",
    "per our terms of service",
    "in line with regulatory requirements",
]

STRATEGY_NAMES = [
    "homoglyph",
    "leetspeak",
    "punctuation_split",
    "zero_width",
    "case_flip",
    "benign_insertion",
    "url_encode",
    "whitespace_inject",
]


@dataclass
class AdversarialVariant:
    strategy:    str
    text:        str
    prediction:  str   = ""
    confidence:  float = 0.0
    fooled:      bool  = False  # True when prediction ≠ true_label


# ── Strategy implementations ──────────────────────────────────────────────────

def _apply_homoglyph(text: str, rate: float = 0.4) -> str:
    """Replace a fraction of eligible lowercase chars with Cyrillic lookalikes."""
    result = []
    for ch in text:
        if ch.lower() in _HOMOGLYPHS and random.random() < rate:
            replacement = _HOMOGLYPHS[ch.lower()]
            result.append(replacement.upper() if ch.isupper() else replacement)
        else:
            result.append(ch)
    return "".join(result)


def _apply_leetspeak(text: str, rate: float = 0.5) -> str:
    result = []
    for ch in text:
        if ch.lower() in _LEET and random.random() < rate:
            result.append(_LEET[ch.lower()])
        else:
            result.append(ch)
    return "".join(result)


def _apply_punctuation_split(text: str) -> str:
    """Insert dots between letters of suspicious keywords: verify -> v.e.r.i.f.y"""
    def dot_word(m):
        word = m.group(0)
        if random.random() < 0.6:
            sep = random.choice([".", "-", "_"])
            return sep.join(list(word))
        return word
    return _PHISH_WORDS.sub(dot_word, text)


def _apply_zero_width(text: str) -> str:
    """Insert zero-width space (U+200B) between letters of suspicious keywords."""
    def zwsp_word(m):
        return "​".join(list(m.group(0)))
    return _PHISH_WORDS.sub(zwsp_word, text)


def _apply_case_flip(text: str, rate: float = 0.3) -> str:
    """Randomly flip case of letters."""
    return "".join(
        ch.upper() if ch.islower() and random.random() < rate
        else ch.lower() if ch.isupper() and random.random() < rate
        else ch
        for ch in text
    )


def _apply_benign_insertion(text: str) -> str:
    """Splice benign filler phrases after suspicious keywords."""
    def insert_filler(m):
        return m.group(0) + " " + random.choice(_FILLERS)

    # Only inject after a subset of matches to avoid over-stuffing
    count = [0]
    def maybe_inject(m):
        if count[0] < 2 and random.random() < 0.5:
            count[0] += 1
            return m.group(0) + ", " + random.choice(_FILLERS) + ","
        return m.group(0)

    return _PHISH_WORDS.sub(maybe_inject, text)


def _apply_url_encode(text: str) -> str:
    """Hex-encode random characters inside URLs to obfuscate them."""
    url_pat = re.compile(r"https?://[^\s]+")
    def encode_url(m):
        url = m.group(0)
        encoded = []
        for ch in url:
            # Don't encode protocol or slashes; randomly encode other chars
            if ch not in ":/." and ch.isalpha() and random.random() < 0.35:
                encoded.append(f"%{ord(ch):02X}")
            else:
                encoded.append(ch)
        return "".join(encoded)
    return url_pat.sub(encode_url, text)


def _apply_whitespace_inject(text: str) -> str:
    """Insert extra spaces inside suspicious words to break tokenization."""
    def split_word(m):
        word = m.group(0)
        if len(word) <= 3:
            return word
        split_at = random.randint(1, len(word) - 1)
        return word[:split_at] + " " + word[split_at:]
    return _PHISH_WORDS.sub(split_word, text)


_STRATEGY_FNS = {
    "homoglyph":         _apply_homoglyph,
    "leetspeak":         _apply_leetspeak,
    "punctuation_split": _apply_punctuation_split,
    "zero_width":        _apply_zero_width,
    "case_flip":         _apply_case_flip,
    "benign_insertion":  _apply_benign_insertion,
    "url_encode":        _apply_url_encode,
    "whitespace_inject": _apply_whitespace_inject,
}


# ── Public API ────────────────────────────────────────────────────────────────

def generate_variants(
    text: str,
    true_label: str,
    strategies: list[str],
    n_per_strategy: int = 3,
    seed: int = 42,
) -> list[AdversarialVariant]:
    """
    Generate adversarial variants for a seed text, then score each one.

    Args:
        text:           seed phishing/spam text
        true_label:     ground-truth label ("phishing", "spam", "ham")
        strategies:     list of strategy names from STRATEGY_NAMES
        n_per_strategy: how many variants per strategy
        seed:           random seed for reproducibility

    Returns list of AdversarialVariant (sorted: fooled ones first).
    """
    import app.services.ensemble_engine as engine

    random.seed(seed)
    variants: list[AdversarialVariant] = []

    for strat in strategies:
        fn = _STRATEGY_FNS.get(strat)
        if fn is None:
            continue
        seen: set[str] = set()
        attempts = 0
        while len(seen) < n_per_strategy and attempts < n_per_strategy * 6:
            attempts += 1
            random.seed(seed + attempts)
            try:
                perturbed = fn(text)
            except Exception:
                continue
            if perturbed == text or perturbed in seen:
                continue
            seen.add(perturbed)
            variants.append(AdversarialVariant(strategy=strat, text=perturbed))

    # Score every variant through the live ensemble
    for v in variants:
        try:
            pred, conf, _, _ = engine.predict_email_ensemble(v.text)
            v.prediction = pred
            v.confidence = round(conf, 4)
            v.fooled = pred != true_label
        except Exception:
            v.prediction = "error"
            v.confidence = 0.0
            v.fooled = False

    # Fooled variants first, then sorted by confidence descending
    variants.sort(key=lambda v: (not v.fooled, -v.confidence))
    return variants


def export_to_csv(
    variants: list[AdversarialVariant],
    true_label: str,
    output_path: str,
) -> int:
    """Append accepted variants to a CSV file (clean_text, label columns).
    Returns the number of rows written."""
    import csv, os
    write_header = not os.path.exists(output_path)
    count = 0
    with open(output_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["clean_text", "label"])
        if write_header:
            writer.writeheader()
        for v in variants:
            # Strip zero-width chars for the training row so labels are clean
            clean = v.text.replace("​", "")
            writer.writerow({"clean_text": clean, "label": true_label})
            count += 1
    return count
