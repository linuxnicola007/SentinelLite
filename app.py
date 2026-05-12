"""
SentinelLite - Main Application
Entry point for FastAPI server, orchestrates all scanning modules.
"""

import os
import shutil
import sqlite3
import logging
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager

# Import scanner modules
from scanner import hashing, yara_scan, pe_analysis, risk_engine, report_generator

# ========================
# Configuration
# ========================
UPLOAD_DIR = "uploads"
REPORTS_DIR = "reports"
LOGS_DIR = "logs"
DATABASE_DIR = "database"
DB_PATH = os.path.join(DATABASE_DIR, "malware_hashes.db")

# Create necessary directories
for dir_path in [UPLOAD_DIR, REPORTS_DIR, LOGS_DIR, DATABASE_DIR]:
    Path(dir_path).mkdir(parents=True, exist_ok=True)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, "scan.log")),
        logging.StreamHandler()  # Also print to console
    ]
)
logger = logging.getLogger("SentinelLite")

# ========================
# Database Setup
# ========================
def init_database():
    """Initialize SQLite database with required tables and sample malware hashes."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Table for known malicious hashes
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS known_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT UNIQUE NOT NULL,
            description TEXT,
            added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Table for scan history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            risk_score INTEGER,
            verdict TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            report_json TEXT
        )
    """)
    
    # Insert sample known malware hashes (for demonstration purposes only)
    sample_hashes = [
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR Test String"),
        ("5b6f0d6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a", "Sample Malware (Dummy)")
    ]
    
    for hash_value, desc in sample_hashes:
        try:
            cursor.execute("INSERT INTO known_hashes (hash, description) VALUES (?, ?)", (hash_value, desc))
            logger.info(f"Inserted sample hash: {desc}")
        except sqlite3.IntegrityError:
            pass  # Already exists
    
    conn.commit()
    conn.close()
    logger.info("Database initialized")

def is_known_malicious(file_hash: str) -> bool:
    """Check if a hash exists in the known malware database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM known_hashes WHERE hash = ?", (file_hash,))
    result = cursor.fetchone() is not None
    conn.close()
    return result

def save_scan_history(scan_id: str, filename: str, sha256: str, risk_score: int, verdict: str, report_json: str):
    """Store scan result in database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_history (id, filename, sha256, risk_score, verdict, report_json) VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, filename, sha256, risk_score, verdict, report_json)
    )
    conn.commit()
    conn.close()
    logger.info(f"Scan history saved: {scan_id}")

def get_scan_history(limit: int = 50):
    """Retrieve recent scan history."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, filename, sha256, risk_score, verdict, timestamp FROM scan_history ORDER BY timestamp DESC LIMIT ?",
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_report_from_db(scan_id: str):
    """Retrieve full report JSON from database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT report_json FROM scan_history WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None

# ========================
# FastAPI App Setup
# ========================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_database()
    yield
    # Shutdown (cleanup if needed)

app = FastAPI(title="SentinelLite Malware Scanner", lifespan=lifespan)

# Serve static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ========================
# API Endpoints
# ========================
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve the main dashboard."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    """
    Main scanning endpoint.
    Receives file, runs through all analysis modules, returns report.
    """
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())
    
    # Save uploaded file securely
    safe_filename = f"{scan_id}_{file.filename.replace('/', '_')}"
    file_path = os.path.join(UPLOAD_DIR, safe_filename)
    
    try:
        # Save file to disk
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        logger.info(f"File uploaded: {file.filename} -> {file_path}")
        
        # 1. Hashing
        file_hash = hashing.get_file_hash(file_path)
        logger.info(f"SHA256: {file_hash}")
        
        # 2. Known hash comparison
        known_malicious = is_known_malicious(file_hash)
        
        # 3. YARA scanning
        yara_matches = yara_scan.scan_with_yara(file_path)
        
        # 4. PE Analysis (if applicable)
        pe_results = pe_analysis.analyze_pe(file_path)
        
        # 5. Calculate file entropy (universal indicator)
        file_entropy = risk_engine.compute_file_entropy(file_path)
        
        # 6. Risk scoring
        risk_result = risk_engine.compute_risk_score(
            known_hash_match=known_malicious,
            yara_matches=yara_matches,
            has_suspicious_imports=len(pe_results.get("suspicious_imports", [])) > 0,
            file_entropy=file_entropy
        )
        
        # 7. Generate report
        report = report_generator.generate_report(
            filename=file.filename,
            sha256=file_hash,
            yara_matches=yara_matches,
            pe_analysis=pe_results,
            risk_result=risk_result,
            file_entropy=file_entropy
        )
        report["scan_id"] = scan_id
        
        # 8. Save report to disk and database
        import json
        report_json_str = json.dumps(report, indent=2)
        report_generator.save_report(report, REPORTS_DIR)
        save_scan_history(scan_id, file.filename, file_hash, risk_result["score"], risk_result["verdict"], report_json_str)
        
        # Return report to frontend
        return JSONResponse(content=report)
        
    except Exception as e:
        logger.error(f"Scan failed for {file.filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")
    finally:
        # Clean up uploaded file (optional - uncomment if disk space is concern)
        # if os.path.exists(file_path):
        #     os.remove(file_path)
        pass

@app.get("/report/{scan_id}")
async def get_report(scan_id: str):
    """Retrieve a previously generated scan report by ID."""
    report_json = get_report_from_db(scan_id)
    if not report_json:
        raise HTTPException(status_code=404, detail="Report not found")
    import json
    return JSONResponse(content=json.loads(report_json))

@app.get("/history")
async def get_history(limit: int = 20):
    """Get recent scan history."""
    history = get_scan_history(limit)
    return JSONResponse(content=history)

# ========================
# Run Server
# ========================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)