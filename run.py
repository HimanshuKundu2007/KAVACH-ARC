"""
KAVACH-ARC Launcher Script
Starts the FastAPI server with Uvicorn and opens the web application.
"""

import sys
import os
import uvicorn

if __name__ == "__main__":
    print("=" * 70)
    print(" KAVACH-ARC: Autonomous Reasoning & Correction (PoC v1.0)")
    print(" Detect. Reason. Correct. Verify.")
    print("=" * 70)
    print(" Starting security engine & web interface at: http://127.0.0.1:8000")
    print(" Press Ctrl+C to terminate.")
    print("=" * 70)
    
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)
