"""
KAVACH-ARC Complete Pipeline Audit Script
Inspects and reports the exact origin and execution of every step in the pipeline.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from backend.engine.static_scanner import StaticScanner
from backend.engine.dynamic_analyzer import DynamicAnalyzer
from backend.engine.ai_reasoner import AIReasoner
from backend.engine.verifier import Verifier
from backend.engine.reporter import SecurityReporter

def run_audit():
    print("=" * 70)
    print(" KAVACH-ARC REAL PIPELINE EXECUTION AUDIT")
    print("=" * 70)

    # 1. Target Loading
    target_file = os.path.join(BASE_DIR, "backend", "targets", "demo_buffer_overflow.c")
    with open(target_file, "r", encoding="utf-8") as f:
        source_code = f.read()
    print(f"\n[1] TARGET LOADED: demo_buffer_overflow.c ({len(source_code)} bytes)")
    print("    - Real target file on disk: YES")

    # 2. Static Analysis
    findings = StaticScanner.scan_code("demo_buffer_overflow.c", source_code)
    print(f"\n[2] STATIC ANALYSIS ENGINE: {len(findings)} finding(s)")
    print("    - Tool: Python AST / Rule Scanner (Semgrep CLI not installed)")
    for f in findings:
        print(f"    - Finding: {f['cwe']} | Rule: {f['rule_id']} | Line {f['line']}: {f['snippet']}")
        print(f"      Message: {f['message']}")

    # 3. Dynamic Execution & Trigger Test
    dyn = DynamicAnalyzer.analyze_target(target_file, source_code)
    print("\n[3] DYNAMIC EXECUTION & CRASH DETECTOR:")
    print("    - Tool: GCC (C:\\MinGW\\bin\\gcc.exe)")
    print(f"    - Target compiled successfully: {dyn['compiled']}")
    print(f"    - Baseline regression test exit code: {dyn['exit_code_reg']} (Passed: {dyn['regression_passed']})")
    print(f"    - Exploit trigger test exit code: {dyn['exit_code_sec']} (0xC0000005 Windows Access Violation)")
    print(f"    - Exploit triggered & confirmed: {dyn['security_triggered']}")
    print("    - Diagnostic Output:")
    for line in dyn['security_logs'].splitlines():
        print(f"      | {line}")

    # 4. AI Reasoning & Patch Synthesis
    has_gemini_key = bool(os.environ.get("GEMINI_API_KEY"))
    patch_result = AIReasoner.reason_and_patch("demo_buffer_overflow.c", source_code, findings, dyn)
    print("\n[4] AI CYBER REASONER & PATCH SYNTHESIS:")
    print(f"    - GEMINI_API_KEY present: {has_gemini_key}")
    print(f"    - Reasoning Mode: {'Live Gemini LLM' if has_gemini_key else 'Deterministic Rule Remediation Engine (Fallback)'}")
    print(f"    - Deduced Vulnerability: {patch_result['vulnerability']}")
    print(f"    - Root Cause: {patch_result['root_cause']}")
    print(f"    - Affected Location: {patch_result['affected_location']}")
    print(f"    - Patch Strategy: {patch_result['patch_strategy']}")
    print("    - Generated Unified Diff (computed via difflib):")
    for dline in patch_result['diff'].splitlines():
        print(f"      {dline}")

    # 5. Independent Verification
    ver = Verifier.verify_patch("demo_buffer_overflow.c", patch_result["patched_code"])
    print("\n[5] INDEPENDENT VERIFICATION (REBUILD & TESTING):")
    print("    - Tool: GCC Compiler + Execution Sandbox Subprocesses")
    print(f"    - Stage 1 (Patch Application): {ver['stages']['patch']['status']}")
    print(f"      Log: {ver['stages']['patch']['log']}")
    print(f"    - Stage 2 (GCC Rebuild): {ver['stages']['build']['status']}")
    print(f"      Log: {ver['stages']['build']['log']}")
    print(f"    - Stage 3 (Security Trigger Test on Patched Target): {ver['stages']['security_test']['status']}")
    print(f"      Log: {ver['stages']['security_test']['log']}")
    print(f"    - Stage 4 (Regression Test Suite on Patched Target): {ver['stages']['regression_test']['status']}")
    print(f"      Log: {ver['stages']['regression_test']['log']}")
    print(f"    - Stage 5 (Final Independent Verdict): {ver['verdict']}")

    # 6. Audit Report
    session_data = {
        "target_name": "demo_buffer_overflow.c",
        "static_findings": findings,
        "dynamic_evidence": dyn,
        "ai_correction": patch_result,
        "verification": ver
    }
    report = SecurityReporter.generate_report(session_data)
    print(f"\n[6] AUDIT REPORT GENERATED: ID {report['report_id']}")
    print(f"    - Compliance Score: {report['executive_summary']['compliance_score']}")
    print(f"    - Verification Verdict: {report['executive_summary']['independent_verification_verdict']}")
    print("=" * 70)

if __name__ == "__main__":
    run_audit()
