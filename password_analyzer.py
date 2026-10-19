"""
password_analyzer.py
=============================================================================
Password Strength Analysis Engine
Academic Project: B.Tech Computer Science (Cyber Security)
=============================================================================
Evaluates password complexity, entropy, and detects common vulnerability patterns.
Returns structured feedback including a strength score, criteria results, pattern
warnings, entropy calculation, estimated brute-force times, and suggestions.
"""

import re
import math
from typing import Dict, Any, List


# Top ~100 most commonly leaked passwords (NIST / HaveIBeenPwned datasets)
COMMON_PASSWORDS = frozenset([
    "123456", "password", "123456789", "12345678", "12345", "111111", "1234567",
    "sunshine", "qwerty", "iloveyou", "princess", "admin", "welcome", "123123",
    "football", "monkey", "charlie", "donald", "shadow", "master", "dragon",
    "superman", "trustno1", "password123", "baseball", "passphrase", "computer",
    "letmein", "starwars", "login", "secret", "guest", "ninja", "mustang",
    "michael", "jessica", "testing", "killer", "matrix", "freedom", "hunter2",
    "whatever", "cheese", "batman", "test1234", "password1", "123321", "liverpool",
    "arsenal", "barcelona", "chelsea", "yellow", "orange", "cookie", "chocolate",
    "access", "default", "root", "toor", "pass123", "qazwsx", "wsxedc", "zaq12wsx",
    "abc123", "abcdef", "123qwe", "000000", "666666", "777777", "888888", "999999",
    "hello", "test", "master1", "solo", "system", "super", "secret1", "jordan",
    "pokemon", "coffee", "robert", "thomas", "daniel", "william", "alexander",
    "anderson", "hacker", "crypto", "security", "pass", "p@ssword", "p@ssw0rd",
    "passw0rd", "qwerty123", "1q2w3e", "1q2w3e4r", "abc1234", "azerty",
])

# Known keyboard walk patterns
KEYBOARD_PATTERNS = [
    "qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "qwertz", "azerty", "1234567890", "0987654321", "qazwsx", "wsxedc",
]

# Sequential character run patterns
SEQUENTIAL_PATTERN = re.compile(
    r'(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|'
    r'rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789|890|'
    r'321|432|543|654|765|876|987|zyx|yxw|wvu|vut|uts|tsr|srq|rqp|qpo)',
    re.IGNORECASE
)

# Three or more consecutive identical characters
REPEAT_PATTERN = re.compile(r'(.)\1{2,}')


def _calculate_character_pool(password: str) -> int:
    """Calculate the theoretical character pool size R for entropy calculation."""
    pool = 0
    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'[0-9]', password):
        pool += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        pool += 33  # Standard printable ASCII special characters
    return pool


def _calculate_entropy(password: str) -> float:
    """
    Calculate Shannon information entropy in bits.
    Formula: E = L × log₂(R)
    where L = password length, R = character pool size.
    """
    if not password:
        return 0.0
    pool = _calculate_character_pool(password)
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def _format_crack_time(seconds: float) -> str:
    """Convert raw seconds into a human-readable crack time estimate."""
    if seconds <= 0.001:
        return "Instant (< 1 ms)"
    if seconds < 1:
        return "< 1 second"
    if seconds < 60:
        return f"{int(seconds)} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 365:
        return f"{int(days)} days"
    years = days / 365
    if years < 1000:
        return f"{int(years)} years"
    if years < 1_000_000:
        return f"{years/1000:.1f}k years"
    if years < 1_000_000_000:
        return f"{years/1_000_000:.1f} million years"
    return "Billions of years (astronomical)"


def _estimate_crack_times(password: str) -> Dict[str, str]:
    """
    Estimate brute-force crack times under four different adversarial threat models.
    Assumes worst-case (50% key-space exhaustion) for conservative estimates.
    """
    pool = _calculate_character_pool(password)
    length = len(password)

    if pool == 0 or length == 0:
        return {
            "online_throttled": "Instant",
            "online_fast": "Instant",
            "offline_gpu": "Instant",
            "offline_pbkdf2": "Instant",
        }

    # log10-space arithmetic to prevent float overflow for large key spaces
    log10_combinations = length * math.log10(pool) - math.log10(2)

    def crack_at_rate(guesses_per_sec: float) -> str:
        log10_rate = math.log10(guesses_per_sec)
        log10_seconds = log10_combinations - log10_rate
        if log10_seconds > 30:
            return "Billions of years (astronomical)"
        if log10_seconds < -6:
            return "Instant (< 1 ms)"
        seconds = 10 ** log10_seconds
        return _format_crack_time(seconds)

    return {
        "online_throttled": crack_at_rate(100),            # 100/sec: web API rate limiting
        "online_fast":      crack_at_rate(10_000),         # 10k/sec: unthrottled API
        "offline_gpu":      crack_at_rate(100_000_000_000),# 100B/sec: GPU MD5/SHA-256 rig
        "offline_pbkdf2":   crack_at_rate(10_000),         # 10k/sec: hardened PBKDF2 rig
    }


def _detect_patterns(password: str) -> List[Dict[str, str]]:
    """
    Detect known vulnerability patterns in the password.
    Returns a list of warnings with type ('danger' or 'warning') and description.
    """
    warnings = []
    lower = password.lower()

    if lower in COMMON_PASSWORDS:
        warnings.append({
            "type": "danger",
            "text": f'This password appears in top common password breach databases and will be cracked instantly.'
        })

    if SEQUENTIAL_PATTERN.search(password):
        warnings.append({
            "type": "warning",
            "text": "Sequential character run detected (e.g., '123', 'abc'). Predictable patterns reduce effective entropy."
        })

    if REPEAT_PATTERN.search(password):
        warnings.append({
            "type": "warning",
            "text": "Three or more consecutive identical characters detected (e.g., 'aaa', '111')."
        })

    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower:
            warnings.append({
                "type": "warning",
                "text": f"Keyboard walk pattern detected ('{pattern}'). High-priority target for cracking tools."
            })
            break  # Report only the first match

    if 0 < len(password) < 8:
        warnings.append({
            "type": "danger",
            "text": "Password is too short. Passwords under 8 characters can be brute-forced in seconds."
        })

    return warnings


def _generate_suggestions(password: str, entropy: float, criteria: Dict, patterns: List) -> List[str]:
    """Generate actionable improvement suggestions based on analysis results."""
    suggestions = []

    if not password:
        return ["Enter a password above to receive security recommendations."]

    if len(password) < 14:
        suggestions.append(
            "Increase length to at least 14–20 characters. "
            "Length contributes exponentially more entropy than character complexity alone."
        )
    if not criteria["has_upper"]:
        suggestions.append("Add uppercase letters (A–Z) to expand the character pool by 26.")
    if not criteria["has_lower"]:
        suggestions.append("Add lowercase letters (a–z).")
    if not criteria["has_digit"]:
        suggestions.append("Include digits (0–9) for additional character variety.")
    if not criteria["has_symbol"]:
        suggestions.append(
            "Add special symbols (!@#$%^&*...) to expand the pool to 95 printable ASCII characters."
        )
    if patterns:
        suggestions.append(
            "Remove predictable sequences, common words, and keyboard walks from your password."
        )
    if entropy < 50 and len(password) > 0:
        suggestions.append(
            "Consider a random 4-word passphrase (e.g., 'sapphire-orbit-falcon-glacier') "
            "for high entropy with human memorability."
        )
    if not suggestions and entropy >= 80:
        suggestions.append(
            "Excellent! This password offers robust theoretical resistance against modern GPU cracking clusters."
        )

    suggestions.append(
        "Use a password manager (e.g., Bitwarden, 1Password) to generate and store unique high-entropy passwords per service."
    )
    return suggestions


def analyze_password(password: str) -> Dict[str, Any]:
    """
    Main entry point: perform full password security analysis.

    Args:
        password (str): Input password string.

    Returns:
        dict: Comprehensive analysis result with score, criteria, entropy,
              crack times, patterns, strength label, and suggestions.
    """
    if not isinstance(password, str):
        password = ""

    length = len(password)
    lower = password.lower()

    # --- Criteria Checks ---
    criteria = {
        "has_min_length": length >= 12,
        "has_upper":      bool(re.search(r'[A-Z]', password)),
        "has_lower":      bool(re.search(r'[a-z]', password)),
        "has_digit":      bool(re.search(r'[0-9]', password)),
        "has_symbol":     bool(re.search(r'[^a-zA-Z0-9]', password)),
    }
    criteria_passed = sum(criteria.values())

    # --- Pattern Warnings ---
    patterns = _detect_patterns(password) if password else []
    has_critical = any(p["type"] == "danger" for p in patterns)

    # --- Entropy ---
    entropy = round(_calculate_entropy(password), 2)
    pool_size = _calculate_character_pool(password)

    # --- Strength Score (1-5) ---
    # Base score from entropy + penalties for patterns
    if length == 0:
        score = 0
    elif has_critical or entropy < 28:
        score = 1  # Very Weak
    elif entropy < 45:
        score = 2  # Weak
    elif entropy < 65:
        score = 3  # Moderate
    elif entropy < 85:
        score = 4  # Strong
    else:
        score = 5  # Very Strong

    # Single-character set passwords (e.g., all lowercase, all digits) under 16 chars
    # lack variety and are capped at Weak (score 2)
    charset_types = sum([
        criteria["has_upper"],
        criteria["has_lower"],
        criteria["has_digit"],
        criteria["has_symbol"],
    ])
    if charset_types <= 1 and length < 16 and score > 2:
        score = 2


    strength_labels = {
        0: "Empty",
        1: "Very Weak",
        2: "Weak",
        3: "Moderate",
        4: "Strong",
        5: "Very Strong"
    }
    strength_colors = {
        0: "secondary",
        1: "danger",
        2: "warning",
        3: "info",
        4: "primary",
        5: "success"
    }

    # --- Crack Time Estimates ---
    crack_times = _estimate_crack_times(password) if password else {
        "online_throttled": "Instant",
        "online_fast": "Instant",
        "offline_gpu": "Instant",
        "offline_pbkdf2": "Instant",
    }

    # --- Suggestions ---
    suggestions = _generate_suggestions(password, entropy, criteria, patterns)

    return {
        "password_length": length,
        "pool_size": pool_size,
        "entropy": entropy,
        "entropy_formula": f"E = {length} × log₂({pool_size}) = {entropy} bits",
        "criteria": criteria,
        "criteria_passed": criteria_passed,
        "total_criteria": len(criteria),
        "patterns": patterns,
        "score": score,
        "strength_label": strength_labels[score],
        "strength_color": strength_colors[score],
        "crack_times": crack_times,
        "suggestions": suggestions,
    }
