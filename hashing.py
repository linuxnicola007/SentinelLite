"""
Module: hashing.py
Purpose: Generate cryptographic hashes of files for comparison against known malware database.
"""

import hashlib

def get_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Calculate the hash of a file using the specified algorithm.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (default: sha256)
    
    Returns:
        Hexadecimal digest string
    """
    # Create a hash object
    hash_func = hashlib.new(algorithm)
    
    # Read file in chunks to handle large files efficiently
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()