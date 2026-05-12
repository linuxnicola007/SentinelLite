"""
Module: yara_scan.py
Purpose: Scan files using YARA rules to detect malicious patterns.
"""

import yara
import os
import logging

logger = logging.getLogger(__name__)

# Path to YARA rules directory
RULES_DIR = "yara_rules"
RULES_FILE = os.path.join(RULES_DIR, "suspicious_rules.yar")

# Compile rules once at module load
try:
    if os.path.exists(RULES_FILE):
        RULES = yara.compile(filepath=RULES_FILE)
        logger.info(f"YARA rules compiled successfully from {RULES_FILE}")
    else:
        RULES = None
        logger.warning(f"YARA rules file not found: {RULES_FILE}")
except Exception as e:
    RULES = None
    logger.error(f"Failed to compile YARA rules: {e}")

def scan_with_yara(file_path: str) -> list:
    """
    Scan a file with compiled YARA rules.
    
    Args:
        file_path: Path to the file to scan
    
    Returns:
        List of matching rule names (empty if no matches or rules not available)
    """
    if RULES is None:
        logger.warning("YARA rules not available, skipping scan")
        return []
    
    try:
        matches = RULES.match(file_path)
        matched_rules = [match.rule for match in matches]
        if matched_rules:
            logger.info(f"YARA matches found: {matched_rules}")
        return matched_rules
    except Exception as e:
        logger.error(f"YARA scan error for {file_path}: {e}")
        return []