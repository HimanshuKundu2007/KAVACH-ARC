"""
KAVACH-ARC Application Server
FastAPI Web Application serving the unified Stitch frontend and coordinating the Python security engine.
"""

import os
import json
from pathlib import Path
from uuid import uuid4
import re

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from backend.engine.static_scanner import StaticScanner
from backend.engine.dynamic_analyzer import DynamicAnalyzer
from backend.engine.ai_reasoner import AIReasoner
from backend.engine.verifier import Verifier
from backend.engine.reporter import SecurityReporter

app = FastAPI(
    title="KAVACH-ARC API",
    description="Autonomous Reasoning & Correction for C/C++ Security",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS_DIR = os.path.join(BASE_DIR, "backend", "targets")
FRONTEND_FILE = os.path.join(BASE_DIR, "frontend", "index.html")

# Global session cache
current_session_state = {}

class PipelineRequest(BaseModel):
    filename: str
    custom_code: Optional[str] = None

@app.post("/api/upload-target")
async def upload_target(file: UploadFile = File(...)):
    """
    Uploads a user-provided C/C++ source file into the controlled
    local target directory for analysis.
    """

    # Only allow C/C++ source files
    if not file.filename or not file.filename.lower().endswith((".c", ".cpp")):
        raise HTTPException(
            status_code=400,
            detail="Only .c and .cpp source files are supported."
        )

    # Keep only the filename, preventing directory traversal
    safe_filename = os.path.basename(file.filename)

    # Give uploaded files a unique name so they don't accidentally
    # overwrite an existing target
    file_stem = Path(safe_filename).stem
    file_ext = Path(safe_filename).suffix

    stored_filename = f"uploaded_{uuid4().hex[:8]}_{file_stem}{file_ext}"
    target_path = os.path.join(TARGETS_DIR, stored_filename)

    # Make sure target directory exists
    os.makedirs(TARGETS_DIR, exist_ok=True)

    # Read and save uploaded source
    content = await file.read()

    # Basic size protection
    if len(content) > 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="File is too large. Maximum supported size is 1 MB."
        )

    try:
        source_code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="The uploaded file must be valid UTF-8 source code."
        )

    with open(target_path, "w", encoding="utf-8") as f:
        f.write(source_code)

    return {
        "success": True,
        "filename": stored_filename,
        "original_filename": safe_filename,
        "size": len(content),
        "code": source_code
    }

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    """Serves the pixel-perfect Stitch single page application."""
    if not os.path.exists(FRONTEND_FILE):
        raise HTTPException(status_code=404, detail="Frontend file not found")
    with open(FRONTEND_FILE, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/api/targets")
async def list_targets():
    """Lists all controlled local demonstration C/C++ targets."""
    if not os.path.exists(TARGETS_DIR):
        return {"targets": []}
    files = [f for f in os.listdir(TARGETS_DIR) if f.endswith((".c", ".cpp"))]
    return {"targets": files}

@app.get("/api/target-code")
async def get_target_code(filename: str = Query(...)):
    """Fetches source code for a selected local target."""
    target_path = os.path.join(TARGETS_DIR, filename)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="Target file not found")
    with open(target_path, "r", encoding="utf-8") as f:
        return {"filename": filename, "code": f.read()}

@app.post("/api/run-pipeline")
async def run_pipeline(req: PipelineRequest):
    """
    Executes the full Autonomous Reasoning & Correction pipeline:
    1. Static Scanner (AST & Pattern matching)
    2. Dynamic Analyzer (Runtime execution & exploit trigger)
    3. AI Cyber Reasoner (Root cause deduction & patch synthesis)
    4. Independent Verifier (Rebuild + Security test + Regression suite)
    5. Reporter (Audit report formulation)
    """
    global current_session_state
    
    target_path = os.path.join(TARGETS_DIR, req.filename)
    if req.custom_code:
        source_code = req.custom_code
    elif os.path.exists(target_path):
        with open(target_path, "r", encoding="utf-8") as f:
            source_code = f.read()
    else:
        raise HTTPException(status_code=404, detail=f"Target {req.filename} not found")

    # 1. STATIC DISCOVERY
    static_findings = StaticScanner.scan_code(req.filename, source_code)

    # 2. DYNAMIC EXECUTION & EXPLOIT TRIGGER
    dynamic_evidence = DynamicAnalyzer.analyze_target(target_path, source_code)

    # 3. AI CYBER REASONING & PATCH GENERATION
    ai_correction = AIReasoner.reason_and_patch(
        source_filename=req.filename,
        source_code=source_code,
        static_findings=static_findings,
        dynamic_evidence=dynamic_evidence
    )

    # 4. INDEPENDENT VERIFICATION (REBUILD + MITIGATION TEST + REGRESSION SUITE)
    verification = Verifier.verify_patch(
        target_filename=req.filename,
        patched_code=ai_correction["patched_code"]
    )

    # 5. AUDIT REPORT AGGREGATION
    session_data = {
        "target_name": req.filename,
        "static_findings": static_findings,
        "dynamic_evidence": dynamic_evidence,
        "ai_correction": ai_correction,
        "verification": verification
    }
    audit_report = SecurityReporter.generate_report(session_data)
    session_data["audit_report"] = audit_report
    current_session_state = session_data

    return JSONResponse(content=session_data)

@app.get("/api/report/export")
async def export_report():
    """Downloads the full cryptographic audit report in JSON format."""
    global current_session_state
    if not current_session_state:
        raise HTTPException(status_code=400, detail="No active analysis session found")
    
    report_json = json.dumps(current_session_state.get("audit_report", {}), indent=2)
    return Response(
        content=report_json,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=kavach_audit_report_{current_session_state.get('target_name', 'target')}.json"}
    )
