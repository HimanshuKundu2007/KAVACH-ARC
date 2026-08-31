"""
Automated Pipeline Verification Test for KAVACH-ARC
Tests all demonstration targets through the full autonomous remediation pipeline.
"""

import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.engine.static_scanner import StaticScanner
from backend.engine.dynamic_analyzer import DynamicAnalyzer
from backend.engine.ai_reasoner import AIReasoner
from backend.engine.verifier import Verifier
from backend.engine.reporter import SecurityReporter

def test_target(filename: str):
    print(f"\n--- Testing Target: {filename} ---")
    target_path = os.path.join(BASE_DIR, "backend", "targets", filename)
    with open(target_path, "r", encoding="utf-8") as f:
        code = f.read()

    # 1. Static Discovery
    findings = StaticScanner.scan_code(filename, code)
    print(f"[1/5] Static Findings: {len(findings)} matches")
    assert len(findings) > 0, f"Expected static findings for {filename}"

    # 2. Dynamic Execution
    dyn = DynamicAnalyzer.analyze_target(target_path, code)
    print(f"[2/5] Dynamic Exploit Triggered: {dyn['security_triggered']} | Regression: {dyn['regression_passed']}")

    # 3. AI Reasoning & Patch
    ai_patch = AIReasoner.reason_and_patch(filename, code, findings, dyn)
    print(f"[3/5] AI Reasoner: {ai_patch['vulnerability']} ({ai_patch['cwe']})")
    assert "diff" in ai_patch and len(ai_patch["diff"]) > 0

    # 4. Independent Verification
    ver = Verifier.verify_patch(filename, ai_patch["patched_code"])
    print(f"[4/5] Independent Verification Verdict: {ver['verdict']}")
    assert ver["verdict"] == "VERIFIED_SECURE", f"Verification failed for {filename}"

    # 5. Security Report
    session = {
        "target_name": filename,
        "static_findings": findings,
        "dynamic_evidence": dyn,
        "ai_correction": ai_patch,
        "verification": ver
    }
    report = SecurityReporter.generate_report(session)
    print(f"[5/5] Report Generated: ID {report['report_id']} | Compliance: {report['executive_summary']['compliance_score']}")
    print(f"PASS: {filename} autonomously remediated and verified secure!")

if __name__ == "__main__":
    targets = ["demo_buffer_overflow.c", "demo_use_after_free.c", "demo_integer_overflow.c"]
    for t in targets:
        test_target(t)
    print("\n=======================================================")
    print(" ALL KAVACH-ARC TARGETS PASSED AUTONOMOUS VERIFICATION! ")
    print("=======================================================")
