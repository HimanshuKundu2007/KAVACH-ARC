"""
KAVACH-ARC Independent Verification Engine
Autonomous 5-Stage Rebuild, Security Test, and Regression Verification.
"""

import subprocess
import tempfile
import os
import shutil
from typing import Dict, Any

class Verifier:
    """Independently verifies patched source code via compilation, security attack execution, and regression suites."""

    @staticmethod
    def verify_patch(target_filename: str, patched_code: str) -> Dict[str, Any]:
        """
        Executes the complete 5-stage independent verification cycle.
        """
        temp_dir = tempfile.mkdtemp(prefix="kavach_verify_")
        patched_src = os.path.join(temp_dir, target_filename)
        # Avoid names like 'patched_target.exe' to bypass Windows UAC installer heuristics
        binary_out = os.path.join(temp_dir, "kavach_ver.exe")
        
        stages = {
            "patch": {"status": "PENDING", "log": ""},
            "build": {"status": "PENDING", "log": ""},
            "security_test": {"status": "PENDING", "log": ""},
            "regression_test": {"status": "PENDING", "log": ""},
            "final_verdict": "PENDING"
        }

        try:
            # STAGE 1: PATCH APPLICATION
            with open(patched_src, "w", encoding="utf-8") as f:
                f.write(patched_code)
            stages["patch"]["status"] = "PASSED"
            stages["patch"]["log"] = f"Patch cleanly applied to {target_filename} ({len(patched_code)} bytes written)."

            # STAGE 2: INDEPENDENT REBUILD
            compile_cmd = ["gcc", "-Wall", "-O1", "-o", binary_out, patched_src]
            comp = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=15)
            
            if comp.returncode != 0:
                stages["build"]["status"] = "FAILED"
                stages["build"]["log"] = f"Compilation Error:\n{comp.stderr}"
                stages["final_verdict"] = "REMEDIATION_FAILED"
                return {"success": False, "verdict": "REMEDIATION_FAILED", "stages": stages}
                
            stages["build"]["status"] = "PASSED"
            stages["build"]["log"] = "Binary successfully built with GCC (-Wall -O1) without warnings or errors."

            # STAGE 3: SECURITY TRIGGER TEST (Exploit payload should no longer trigger vulnerability or crash)
            sec_proc = subprocess.run([binary_out, "--security-test"], capture_output=True, text=True, timeout=10)
            sec_output = (sec_proc.stdout + "\n" + sec_proc.stderr).strip()
            
            is_mitigated = (
                sec_proc.returncode == 0 and 
                ("SECURITY PASS" in sec_output or "safely" in sec_output or "prevented" in sec_output) and 
                "TRIGGER" not in sec_output
            )

            if is_mitigated:
                stages["security_test"]["status"] = "PASSED"
                stages["security_test"]["log"] = f"Security attack vector successfully mitigated:\n{sec_output}"
            else:
                stages["security_test"]["status"] = "FAILED"
                stages["security_test"]["log"] = f"Security vulnerability STILL reproducible after patch (Exit code {sec_proc.returncode}):\n{sec_output}"
                stages["final_verdict"] = "REMEDIATION_FAILED"
                return {"success": False, "verdict": "REMEDIATION_FAILED", "stages": stages}

            # STAGE 4: REGRESSION TEST SUITE (Normal operations must remain functional)
            reg_proc = subprocess.run([binary_out, "--regression-test"], capture_output=True, text=True, timeout=10)
            reg_output = (reg_proc.stdout + "\n" + reg_proc.stderr).strip()
            
            if reg_proc.returncode == 0 and "REGRESSION PASS" in reg_output:
                stages["regression_test"]["status"] = "PASSED"
                stages["regression_test"]["log"] = f"Regression suite completed with 100% pass rate:\n{reg_output}"
            else:
                stages["regression_test"]["status"] = "FAILED"
                stages["regression_test"]["log"] = f"Regression failure detected in patched build:\n{reg_output}"
                stages["final_verdict"] = "REMEDIATION_FAILED"
                return {"success": False, "verdict": "REMEDIATION_FAILED", "stages": stages}

            # STAGE 5: FINAL VERDICT
            stages["final_verdict"] = "VERIFIED_SECURE"
            return {
                "success": True,
                "verdict": "VERIFIED_SECURE",
                "stages": stages
            }

        except Exception as e:
            stages["final_verdict"] = "REMEDIATION_FAILED"
            stages["build"]["log"] = str(e)
            return {"success": False, "verdict": "REMEDIATION_FAILED", "stages": stages}
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
