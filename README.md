# SentinelLite - Educational Malware Detection Framework

SentinelLite is a lightweight, beginner-friendly malware scanner built with Python and FastAPI. It demonstrates core static analysis techniques used in real cybersecurity tools like EDR systems and sandboxes.

## ⚠️ Educational Purpose Only
This tool is designed for learning and research. Do not use it as a primary defense system.

## Structure
SentinelLite/
│
├── app.py
├── requirements.txt
├── README.md
│
├── scanner/
│   ├── __init__.py
│   ├── hashing.py
│   ├── yara_scan.py
│   ├── pe_analysis.py
│   ├── risk_engine.py
│   └── report_generator.py
│
├── yara_rules/
│   └── suspicious_rules.yar
│
├── database/
│   └── (malware_hashes.db will be created automatically)
│
├── uploads/
├── reports/
│
├── templates/
│   └── index.html
│
├── static/
│   ├── style.css
│   └── app.js
│
└── logs/
    └── (scan.log will be created automatically)

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


## 🚀 Quick Start

```bash
git clone https://github.com/linuxnicola007/SentinelLite.git
cd SentinelLite
pip install -r requirements.txt
# Install YARA system dependency (see README for OS-specific instructions)
python app.py
# Open http://localhost:8000


🧪 Test with EICAR
Create a file with the EICAR test string – SentinelLite will detect it as Malicious (hash match).

📚 Educational Purpose Only
This framework is designed for learning and research. Do not use as a primary security solution.

🔮 Future Expansion Ideas
Add machine learning classifier (e.g., LightGBM on PE features)

Implement behavioral analysis (sandbox)

Real-time file system monitoring (EDR-like)

Integrate VirusTotal API

Add more YARA rules from community repos

🤝 Contributing
Pull requests, new YARA rules, and educational improvements are welcome!

📄 License
MIT – free to use, modify, and distribute for educational purposes.

text

---

## Optional: Badges (Markdown)

Add these at the top of your `README.md` for a professional look:

```markdown
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Static Analysis](https://img.shields.io/badge/Static%20Analysis-YARA%20%2B%20PE-orange)
