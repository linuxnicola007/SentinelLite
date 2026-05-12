"""
Module: risk_engine.py
Purpose: Calculate risk scores based on multiple indicators.
"""

import math
import logging

logger = logging.getLogger(__name__)

# Risk weights
WEIGHT_YARA_MATCH = 30          # Each YARA rule match
WEIGHT_HIGH_ENTROPY = 20        # Entropy > 6.8
WEIGHT_SUSPICIOUS_IMPORT = 25   # Suspicious API import
WEIGHT_KNOWN_MALICIOUS = 100    # Hash match in malware database

# Thresholds
ENTROPY_THRESHOLD = 6.8
VERDICT_SAFE_MAX = 20
VERDICT_SUSPICIOUS_MAX = 50

def compute_risk_score(
    known_hash_match: bool,
    yara_matches: list,
    has_suspicious_imports: bool,
    file_entropy: float
) -> dict:
    """
    Calculate risk score and verdict based on multiple indicators.
    
    Args:
        known_hash_match: True if file hash found in malware database
        yara_matches: List of matched YARA rule names
        has_suspicious_imports: True if PE file imports suspicious APIs
        file_entropy: Shannon entropy of the file (0-8)
    
    Returns:
        Dictionary with score, verdict, and contributing factors
    """
    score = 0
    reasons = []
    
    # 1. Known malicious hash (+100)
    if known_hash_match:
        score += WEIGHT_KNOWN_MALICIOUS
        reasons.append("File hash matches known malware database")
    
    # 2. YARA rule matches (each +30)
    if yara_matches:
        score += len(yara_matches) * WEIGHT_YARA_MATCH
        reasons.append(f"Matched {len(yara_matches)} YARA rule(s): {', '.join(yara_matches)}")
    
    # 3. Suspicious imports (+25)
    if has_suspicious_imports:
        score += WEIGHT_SUSPICIOUS_IMPORT
        reasons.append("Suspicious API imports detected (e.g., CreateRemoteThread, VirtualAlloc)")
    
    # 4. High entropy (+20)
    if file_entropy > ENTROPY_THRESHOLD:
        score += WEIGHT_HIGH_ENTROPY
        reasons.append(f"High entropy ({file_entropy:.2f}) - possible packing/encryption")
    
    # Determine verdict
    if score <= VERDICT_SAFE_MAX:
        verdict = "Safe"
    elif score <= VERDICT_SUSPICIOUS_MAX:
        verdict = "Suspicious"
    else:
        verdict = "Malicious"
    
    logger.info(f"Risk score: {score}, Verdict: {verdict}, Reasons: {reasons}")
    
    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }

def compute_file_entropy(file_path: str) -> float:
    """
    Calculate overall entropy of a file by reading its content.
    Used for non-PE files or as a universal indicator.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        
        if not data:
            return 0.0
        
        entropy = 0.0
        byte_counts = [0] * 256
        
        for byte in data:
            byte_counts[byte] += 1
        
        length = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return round(entropy, 2)
    except Exception as e:
        logger.error(f"Failed to compute file entropy for {file_path}: {e}")
        return 0.0