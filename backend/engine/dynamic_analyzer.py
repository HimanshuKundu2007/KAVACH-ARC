"""
KAVACH-ARC Dynamic Execution & Sanitizer Analysis Engine
Compiles local C/C++ target programs and monitors runtime execution telemetry and memory safety.
"""

import subprocess
import tempfile
import os
import shutil
from typing import Dict, Any

class DynamicAnalyzer:
    """Compiles C/C++ source code and runs security triggers and regression test suites."""

    @staticmethod
    def analyze_target(source_path: str, code_content: str = None) -> Dict[str, Any]:
        """
        Compiles the target with GCC and runs both the regression harness and the security trigger test.
        """
        temp_dir = tempfile.mkdtemp(prefix="kavach_dyn_")
        source_file = os.path.join(temp_dir, "target.c")
        # Use name without 'patch', 'setup', 'update' to avoid Windows UAC elevation heuristics
        binary_file = os.path.join(temp_dir, "kavach_dyn.exe")
        
        try:
            if code_content is not None:
                with open(source_file, "w", encoding="utf-8") as f:
                    f.write(code_content)
            else:
                shutil.copyfile(source_path, source_file)

            # Compile with GCC
            compile_cmd = ["gcc", "-Wall", "-g", "-O1", "-o", binary_file, source_file]
            comp_proc = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=15)
            
            if comp_proc.returncode != 0:
                return {
                    "success": False,
                    "compiled": False,
                    "compile_error": comp_proc.stderr,
                    "security_triggered": False,
                    "regression_passed": False,
                    "security_logs": "",
                    "regression_logs": ""
                }

            # 1. Run Regression Test
            reg_proc = subprocess.run([binary_file, "--regression-test"], capture_output=True, text=True, timeout=10)
            regression_output = (reg_proc.stdout + "\n" + reg_proc.stderr).strip()
            regression_passed = (reg_proc.returncode == 0)

            # 2. Run Security Trigger Test
            sec_proc = subprocess.run([binary_file, "--security-test"], capture_output=True, text=True, timeout=10)
            security_output = (sec_proc.stdout + "\n" + sec_proc.stderr).strip()
            
            # Vulnerability confirmed if:
            # - Exit code indicates crash/access violation (e.g. 3221225477 = 0xC0000005, or non-zero exit)
            # - Return code is 2 (security test explicitly caught violation)
            # - Trigger output contains memory corruption keywords
            security_triggered = (
                sec_proc.returncode != 0 or 
                "SECURITY TRIGGER" in security_output or 
                "corrupted" in security_output or
                "Dangling pointer" in security_output or
                "Underallocated" in security_output
            )

            if sec_proc.returncode == 3221225477:
                security_output = f"[CRASH DETECTED] Process terminated by OS Access Violation (0xC0000005 / Buffer Overflow Stack Smashing)\n{security_output}"

            return {
                "success": True,
                "compiled": True,
                "compile_error": "",
                "security_triggered": security_triggered,
                "regression_passed": regression_passed,
                "security_logs": security_output,
                "regression_logs": regression_output,
                "exit_code_sec": sec_proc.returncode,
                "exit_code_reg": reg_proc.returncode
            }

        except Exception as e:
            return {
                "success": False,
                "compiled": False,
                "compile_error": str(e),
                "security_triggered": False,
                "regression_passed": False,
                "security_logs": "",
                "regression_logs": ""
            }
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
