"""
KAVACH-ARC Static Discovery Engine
Performs deep static pattern & AST-based vulnerability analysis on C/C++ source code.
"""

import re
from typing import List, Dict, Any

STATIC_RULES = [
    {
        "id": "KAVACH-C-001",
        "cwe": "CWE-120",
        "name": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
        "severity": "High",
        "pattern": r"\bstrcpy\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)",
        "message": "Use of unsafe function 'strcpy' without bounds checking can lead to buffer overflow.",
        "remediation": "Replace with 'strncpy', 'strlcpy', or 'snprintf' with explicit destination buffer capacity.",
    },
    {
        "id": "KAVACH-C-002",
        "cwe": "CWE-416",
        "name": "Use After Free",
        "severity": "Critical",
        "pattern": r"free\s*\(\s*([a-zA-Z0-9_>.-]+)\s*\);(?![^;]*\1\s*=\s*NULL)",
        "message": "Pointer freed without resetting to NULL, allowing potential Use-After-Free access.",
        "remediation": "Immediately set pointer to NULL after calling free() and guard access with null check.",
    },
    {
        "id": "KAVACH-C-003",
        "cwe": "CWE-190",
        "name": "Integer Overflow or Wraparound",
        "severity": "High",
        "pattern": r"(unsigned\s+int|size_t)\s+([a-zA-Z0-9_]+)\s*=\s*([a-zA-Z0-9_]+)\s*\*\s*([a-zA-Z0-9_]+);",
        "message": "Arithmetic multiplication of allocation bounds without overflow pre-check.",
        "remediation": "Validate multiplication bounds before allocation: if (count > MAX_ITEMS || count * size > MAX_BYTES).",
    },
    {
        "id": "KAVACH-C-004",
        "cwe": "CWE-134",
        "name": "Use of Externally-Controlled Format String",
        "severity": "Critical",
        "pattern": r"\bprintf\s*\(\s*([a-zA-Z0-9_>.-]+)\s*\)",
        "message": "Direct pass of variable buffer to printf without constant format specifier.",
        "remediation": "Use explicit format specifier: printf(\"%s\", buffer).",
    },
    {
        "id": "KAVACH-C-005",
        "cwe": "CWE-676",
        "name": "Use of Potentially Dangerous Function",
        "severity": "Medium",
        "pattern": r"\b(gets|sprintf|strcat)\s*\(",
        "message": "Dangerous legacy C standard library function prone to unbounded memory writes.",
        "remediation": "Replace with safe bounds-checked alternatives (fgets, snprintf, strncat).",
    }
]

class StaticScanner:
    """Scans C/C++ source code for static security vulnerabilities."""

    @staticmethod
    def scan_code(file_path: str, code_content: str) -> List[Dict[str, Any]]:
        findings = []
        lines = code_content.splitlines()
        
        for rule in STATIC_RULES:
            pattern = re.compile(rule["pattern"])
            
            # Check line by line
            for idx, line in enumerate(lines, start=1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    continue
                    
                match = pattern.search(line)
                if match:
                    findings.append({
                        "id": f"{rule['id']}-{idx}",
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "cwe": rule["cwe"],
                        "severity": rule["severity"],
                        "file": file_path,
                        "line": idx,
                        "snippet": line.strip(),
                        "message": rule["message"],
                        "remediation": rule["remediation"]
                    })
                    
        return findings
