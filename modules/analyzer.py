import math
import re

COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678", "123456789",
    "qwerty", "qwerty123", "admin", "admin123", "letmein",
    "welcome", "iloveyou", "abc123", "monkey", "dragon"
}


def estimate_entropy(password: str) -> float:
    if not password:
        return 0.0
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"\d", password): pool += 10
    if re.search(r"[^A-Za-z0-9]", password): pool += 32
    if pool == 0:
        pool = max(len(set(password)), 1)
    return round(len(password) * math.log2(pool), 2)



def analyze_password(password: str) -> dict:
    length = len(password)
    lower = bool(re.search(r"[a-z]", password))
    upper = bool(re.search(r"[A-Z]", password))
    digit = bool(re.search(r"\d", password))
    special = bool(re.search(r"[^A-Za-z0-9]", password))
    normalized = password.lower()
    dictionary_match = normalized in COMMON_PASSWORDS
    sequence = any(x in normalized for x in ("1234", "abcd", "qwerty"))
    repeated = bool(re.search(r"(.)\1{2,}", password))
    entropy = estimate_entropy(password)

    score = min(length * 4, 40)
    score += 10 if lower else 0
    score += 10 if upper else 0
    score += 10 if digit else 0
    score += 15 if special else 0
    score += min(max(entropy - 20, 0) / 4, 15)
    if dictionary_match: score -= 35
    if sequence: score -= 15
    if repeated: score -= 10
    score = max(0, min(100, round(score)))

    if dictionary_match or score < 40:
        strength = "Weak"
    elif score < 70:
        strength = "Medium"
    else:
        strength = "Strong"

    risk_factors = []
    if length < 12: risk_factors.append("Password is shorter than the recommended 12-character baseline.")
    if dictionary_match: risk_factors.append("Matches a common-password pattern.")
    if sequence: risk_factors.append("Contains a predictable sequence.")
    if repeated: risk_factors.append("Contains repeated characters.")
    if not upper or not lower: risk_factors.append("Uses only one letter case.")
    if not digit: risk_factors.append("Contains no digits.")
    if not special: risk_factors.append("Contains no special characters.")

    if dictionary_match or score < 40:
        severity = "High"
    elif score < 70:
        severity = "Medium"
    else:
        severity = "Low"

    recommendations = []
    if length < 12: recommendations.append("Prefer a longer unique passphrase, ideally 12+ characters.")
    if not lower or not upper: recommendations.append("Use varied letter case when compatible with the policy.")
    if not digit: recommendations.append("Include digits when appropriate to the authentication policy.")
    if not special: recommendations.append("Include special characters when appropriate to the authentication policy.")
    if dictionary_match: recommendations.append("Avoid common or easily guessed passwords.")
    if sequence: recommendations.append("Avoid predictable sequences such as 1234, abcd, or qwerty.")
    if repeated: recommendations.append("Avoid long runs of repeated characters.")
    if not recommendations: recommendations.append("Good baseline. Use a unique password and enable MFA where available.")

    return {
        "length": length, "entropy": entropy, "score": score, "strength": strength,
        "severity": severity, "lowercase": lower, "uppercase": upper, "digits": digit,
        "special": special, "dictionary_match": dictionary_match,
        "sequence_detected": sequence, "repeated_pattern": repeated,
        "risk_factors": risk_factors, "recommendations": recommendations,
    }
