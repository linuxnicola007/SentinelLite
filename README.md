# SentinelLite - Educational Malware Detection Framework

SentinelLite is a lightweight, beginner-friendly malware scanner built with Python and FastAPI. It demonstrates core static analysis techniques used in real cybersecurity tools like EDR systems and sandboxes.

## ⚠️ Educational Purpose Only
This tool is designed for learning and research. Do not use it as a primary defense system.

## Features
- File upload dashboard
- SHA256 hash matching against known malware database
- YARA rule scanning (custom rules included)
- PE file analysis (imports, sections, entropy)
- Risk scoring engine (0-100+)
- JSON reports and scan history
- SQLite storage for persistence

## Installation

1. **Install Python 3.8+**
2. **Install YARA** (required for yara-python):
   - Windows: Download from [VirusTotal/yara](https://github.com/VirusTotal/yara/releases)
   - Linux: `sudo apt install yara`
   - macOS: `brew install yara`
3. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt