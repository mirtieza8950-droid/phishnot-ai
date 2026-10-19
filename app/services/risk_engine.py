import re

URGENCY_PATTERNS = re.compile(
    r'(urgent|immediate|alert|verify|confirm|suspend|limited|expire|'
    r'action required|click here|login|account|password|update|secure)',
    re.IGNORECASE
)
# Cyrillic/Greek lookalikes for Latin letters commonly used in brand impersonation.
# a->а(U+0430), e->е(U+0435), o->о(U+043E), p->р(U+0440), c->с(U+0441),
# x->х(U+0445), i->і(U+0456), y->у(U+0443), А/Е/О/Р/С/Х/І/У (uppercase)
HOMOGLYPH_PATTERNS = re.compile(
    r'[аеорсхіу'
    r'АЕОРСХІУ'
    r'αορεκΟΑ]'
)

ATTACK_TYPE_KEYWORDS = {
    "Credential Harvesting": r'(login|sign.?in|password|verify account|update.*account|credential)',
    "Invoice/Billing Scam": r'(invoice|payment|billing|receipt|order|transaction)',
    "Tech Support Scam": r'(support|tech|help.?desk|security alert|virus|threat)',
    "Job Offer Scam": r'(job|hiring|recruit|salary|position|interview)',
    "Prize/Giveaway Scam": r'(winner|prize|won|claim|reward|congratulation)',
}


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
        if url_features.get('url_entropy', 0) > 3.5:
            risk_boost += 10
    risk_score = min(base_score + risk_boost, 100)
    if prediction in ("ham", "legitimate"):
        risk_score = min(risk_score, 30)
        level = "Low"
    else:
        if risk_score >= 80:
            level = "Critical"
        elif risk_score >= 60:
            level = "High"
        elif risk_score >= 40:
            level = "Medium"
        else:
            level = "Low"
    return {"score": round(risk_score, 1), "level": level}


def classify_attack(text: str) -> str:
    for attack, pattern in ATTACK_TYPE_KEYWORDS.items():
        if re.search(pattern, text, re.IGNORECASE):
            return attack
    return "Generic Phishing"
