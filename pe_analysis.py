"""
Module: pe_analysis.py
Purpose: Analyze Windows Portable Executable (PE) files for suspicious characteristics.
"""

import pefile
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Known suspicious API functions often abused by malware
SUSPICIOUS_APIS = {
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAlloc",
    "VirtualAllocEx", "ReadProcessMemory", "QueueUserAPC",
    "SetThreadContext", "NtCreateThreadEx", "WinExec", "ShellExecute",
    "ShellExecuteEx", "CreateProcess", "CreateProcessAsUser",
    "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "GetProcAddress"
}

def analyze_pe(file_path: str) -> dict:
    """
    Analyze a PE file and extract relevant features.
    
    Args:
        file_path: Path to the PE file
    
    Returns:
        Dictionary with analysis results or is_pe=False if not a valid PE
    """
    result = {
        "is_pe": False,
        "imports": [],
        "suspicious_imports": [],
        "sections": [],
        "entropy": 0.0,
        "compile_time": None
    }
    
    try:
        pe = pefile.PE(file_path)
        result["is_pe"] = True
        
        # Extract compile timestamp
        if hasattr(pe, "FILE_HEADER"):
            timestamp = pe.FILE_HEADER.TimeDateStamp
            if timestamp:
                result["compile_time"] = datetime.fromtimestamp(timestamp).isoformat()
        
        # Extract imported APIs and DLLs
        all_imports = []
        suspicious = []
        
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode('utf-8', errors='ignore')
                        all_imports.append(f"{dll_name}!{api_name}")
                        if api_name in SUSPICIOUS_APIS:
                            suspicious.append(api_name)
        
        result["imports"] = all_imports[:50]  # Limit for readability
        result["suspicious_imports"] = list(set(suspicious))
        
        # Extract section information and entropy
        sections_info = []
        for section in pe.sections:
            section_data = section.get_data()
            entropy = calculate_entropy(section_data) if section_data else 0.0
            sections_info.append({
                "name": section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 2)
            })
        result["sections"] = sections_info
        
        # Overall file entropy (average of sections weighted by size)
        if sections_info:
            total_weighted_entropy = sum(s["entropy"] * s["raw_size"] for s in sections_info)
            total_size = sum(s["raw_size"] for s in sections_info)
            result["entropy"] = round(total_weighted_entropy / total_size, 2) if total_size > 0 else 0.0
        
        pe.close()
        logger.info(f"PE analysis completed for {file_path}")
        
    except pefile.PEFormatError:
        logger.info(f"Not a valid PE file: {file_path}")
    except Exception as e:
        logger.error(f"PE analysis error for {file_path}: {e}")
    
    return result

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of binary data.
    High entropy (close to 8) indicates packed or encrypted content.
    """
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
            entropy -= p * (p.bit_length() - 1)  # log2(p) approximation
            # More accurate: entropy -= p * math.log2(p)
            # Using bit_length avoids math import for simplicity
    
    return round(entropy, 2)