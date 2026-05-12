"""
Module: report_generator.py
Purpose: Generate structured JSON reports of scan results.
"""

import json
import os
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def generate_report(
    filename: str,
    sha256: str,
    yara_matches: list,
    pe_analysis: dict,
    risk_result: dict,
    file_entropy: float
) -> dict:
    """
    Create a comprehensive scan report.
    
    Args:
        filename: Original uploaded filename
        sha256: SHA256 hash of the file
        yara_matches: List of matched YARA rules
        pe_analysis: Results from PE analysis module
        risk_result: Risk score and verdict from risk engine
        file_entropy: Overall file entropy (calculated separately)
    
    Returns:
        Dictionary containing complete scan report
    """
    report = {
        "scan_id": None,  # Will be set by app.py
        "timestamp": datetime.now().isoformat(),
        "filename": filename,
        "sha256": sha256,
        "file_type": "PE (Windows executable)" if pe_analysis.get("is_pe") else "Unknown/Other",
        "yara_matches": yara_matches,
        "pe_analysis": {
            "is_pe": pe_analysis.get("is_pe", False),
            "compile_time": pe_analysis.get("compile_time"),
            "imported_dlls_and_apis": pe_analysis.get("imports", [])[:20],  # Show first 20 for brevity
            "suspicious_imports": pe_analysis.get("suspicious_imports", []),
            "sections": pe_analysis.get("sections", []),
            "section_entropy": pe_analysis.get("entropy", 0.0)
        },
        "entropy": file_entropy,
        "risk_score": risk_result["score"],
        "verdict": risk_result["verdict"],
        "detection_reasons": risk_result["reasons"]
    }
    
    return report

def save_report(report: dict, reports_dir: str = "reports") -> str:
    """
    Save report as JSON file and return the file path.
    """
    os.makedirs(reports_dir, exist_ok=True)
    report_id = report["scan_id"]
    filepath = os.path.join(reports_dir, f"{report_id}.json")
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    
    logger.info(f"Report saved: {filepath}")
    return filepath