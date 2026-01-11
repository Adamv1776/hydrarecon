#!/usr/bin/env python3
"""
HydraRecon Security Self-Audit
═══════════════════════════════════════════════════════════════════════════════
Scans the codebase for common security issues and vulnerabilities.
Run before publishing to ensure code quality.
═══════════════════════════════════════════════════════════════════════════════
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class SecurityFinding:
    """Represents a security finding"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    file: str
    line: int
    message: str
    code_snippet: str = ""


class SecurityAuditor:
    """Security auditor for Python codebase"""
    
    # Patterns to detect potential security issues
    PATTERNS = {
        'CRITICAL': [
            (r'eval\s*\(', 'Dangerous eval() usage - potential code injection'),
            (r'exec\s*\(', 'Dangerous exec() usage - potential code injection'),
            (r'pickle\.load', 'Unsafe pickle deserialization - potential RCE'),
            (r'yaml\.load\s*\([^,]+\)', 'Unsafe YAML load - use yaml.safe_load()'),
            (r'subprocess\.call\s*\([^,]*shell\s*=\s*True', 'Shell=True with subprocess - command injection risk'),
            (r'os\.system\s*\(', 'os.system() usage - prefer subprocess'),
        ],
        'HIGH': [
            (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password detected'),
            (r'api_key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key detected'),
            (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret detected'),
            (r'token\s*=\s*["\'][a-zA-Z0-9]{20,}["\']', 'Hardcoded token detected'),
            (r'__import__\s*\(', 'Dynamic import - potential code injection'),
            (r'compile\s*\([^)]+exec', 'Dynamic code compilation'),
            (r'input\s*\([^)]*\)\s*$', 'Raw input() in Python - validate user input'),
        ],
        'MEDIUM': [
            (r'verify\s*=\s*False', 'SSL verification disabled'),
            (r'check_hostname\s*=\s*False', 'Hostname verification disabled'),
            (r'md5\s*\(', 'Weak MD5 hash - use SHA-256 or better'),
            (r'sha1\s*\(', 'Weak SHA1 hash - use SHA-256 or better'),
            (r'DES|Blowfish|RC4', 'Weak encryption algorithm'),
            (r'random\.random|random\.randint', 'Non-cryptographic random - use secrets module'),
            (r'tempfile\.mktemp', 'Insecure temp file - use mkstemp()'),
            (r'chmod\s*\(\s*[^,]+,\s*0o?777', 'World-writable permissions'),
        ],
        'LOW': [
            (r'# TODO|# FIXME|# XXX|# HACK', 'TODO/FIXME comment found'),
            (r'print\s*\([^)]*password', 'Potential password logging'),
            (r'logging\.debug.*password', 'Potential password in debug logs'),
            (r'assert\s+', 'Assert statements (disabled with -O flag)'),
            (r'except\s*:', 'Bare except clause - catches everything'),
            (r'pass\s*$', 'Empty except/finally block'),
        ],
        'INFO': [
            (r'# type:\s*ignore', 'Type checking ignored'),
            (r'noqa', 'Linting suppressed'),
            (r'pylint:\s*disable', 'Pylint disabled'),
        ]
    }
    
    # Files/directories to skip
    SKIP_PATTERNS = [
        '__pycache__',
        '.git',
        'venv',
        '.env',
        'node_modules',
        '.pytest_cache',
        '*.pyc',
        '*.egg-info',
    ]
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.findings: List[SecurityFinding] = []
        self.stats = defaultdict(int)
    
    def should_skip(self, path: Path) -> bool:
        """Check if path should be skipped"""
        path_str = str(path)
        for pattern in self.SKIP_PATTERNS:
            if pattern in path_str:
                return True
        return False
    
    def scan_file(self, file_path: Path) -> List[SecurityFinding]:
        """Scan a single file for security issues"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            return findings
        
        for line_num, line in enumerate(lines, 1):
            for severity, patterns in self.PATTERNS.items():
                for pattern, message in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Skip false positives
                        if self._is_false_positive(pattern, line, file_path):
                            continue
                        
                        findings.append(SecurityFinding(
                            severity=severity,
                            category=self._get_category(pattern),
                            file=str(file_path.relative_to(self.project_root)),
                            line=line_num,
                            message=message,
                            code_snippet=line.strip()[:100]
                        ))
                        self.stats[severity] += 1
        
        return findings
    
    def _is_false_positive(self, pattern: str, line: str, file_path: Path) -> bool:
        """Check for common false positives"""
        # Skip comments (except for TODO/FIXME patterns)
        if line.strip().startswith('#') and 'TODO' not in pattern:
            return True
        
        # Skip docstrings and string literals that mention these terms
        if '"""' in line or "'''" in line:
            return True
        
        # Skip test files for some patterns
        if 'test' in str(file_path).lower():
            if 'password' in pattern or 'secret' in pattern:
                return True
        
        # Skip audit file itself
        if 'security_audit' in str(file_path):
            return True
        
        # Qt app.exec() is NOT Python's exec - it's the event loop
        if 'exec' in pattern and ('app.exec()' in line or 'dialog.exec()' in line):
            return True
        
        # PyTorch model.eval() is NOT Python's eval
        if 'eval' in pattern and ('.eval()' in line and 'model' in line.lower()):
            return True
        
        # asyncio.create_subprocess_exec is safe subprocess usage
        if 'exec' in pattern and 'subprocess_exec' in line:
            return True
        
        # Skip documentation strings mentioning dangerous functions
        if ('description' in line.lower() or 'docstring' in line.lower() or 
            line.strip().startswith('"') or line.strip().startswith("'")):
            if 'exec' in pattern or 'eval' in pattern or 'pickle' in pattern:
                return True
        
        # Skip string references in exploit framework (they're examples, not usage)
        if 'exploit' in str(file_path).lower():
            if any(x in line for x in ['Runtime.getRuntime()', 'Process p =']):
                return True
        
        # random.random used for non-security purposes is fine
        if 'random' in pattern:
            # Skip if it's clearly not for security
            if any(x in line.lower() for x in ['color', 'position', 'delay', 'animation', 'ui', 'visual']):
                return True
        
        return False
    
    def _get_category(self, pattern: str) -> str:
        """Categorize the finding"""
        if 'eval' in pattern or 'exec' in pattern or 'import' in pattern:
            return 'Code Injection'
        if 'password' in pattern or 'secret' in pattern or 'key' in pattern:
            return 'Hardcoded Credentials'
        if 'ssl' in pattern.lower() or 'verify' in pattern:
            return 'SSL/TLS Issues'
        if 'md5' in pattern or 'sha1' in pattern or 'random' in pattern:
            return 'Weak Cryptography'
        if 'subprocess' in pattern or 'system' in pattern:
            return 'Command Injection'
        return 'Other'
    
    def scan_project(self) -> List[SecurityFinding]:
        """Scan entire project"""
        print("="*60)
        print("HydraRecon Security Self-Audit")
        print("="*60)
        print(f"Scanning: {self.project_root}")
        print()
        
        python_files = []
        for root, dirs, files in os.walk(self.project_root):
            # Filter out directories to skip
            dirs[:] = [d for d in dirs if not self.should_skip(Path(root) / d)]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = Path(root) / file
                    if not self.should_skip(file_path):
                        python_files.append(file_path)
        
        print(f"Found {len(python_files)} Python files to scan")
        print()
        
        for file_path in python_files:
            file_findings = self.scan_file(file_path)
            self.findings.extend(file_findings)
        
        return self.findings
    
    def generate_report(self) -> str:
        """Generate security audit report"""
        report = []
        report.append("="*60)
        report.append("SECURITY AUDIT REPORT")
        report.append("="*60)
        report.append("")
        
        # Summary
        report.append("SUMMARY")
        report.append("-"*40)
        total = sum(self.stats.values())
        report.append(f"Total Findings: {total}")
        report.append(f"  🔴 CRITICAL: {self.stats['CRITICAL']}")
        report.append(f"  🟠 HIGH:     {self.stats['HIGH']}")
        report.append(f"  🟡 MEDIUM:   {self.stats['MEDIUM']}")
        report.append(f"  🔵 LOW:      {self.stats['LOW']}")
        report.append(f"  ⚪ INFO:     {self.stats['INFO']}")
        report.append("")
        
        # Risk assessment
        if self.stats['CRITICAL'] > 0:
            report.append("⚠️  RISK: HIGH - Critical issues must be addressed before publishing")
        elif self.stats['HIGH'] > 0:
            report.append("⚠️  RISK: MEDIUM - High severity issues should be reviewed")
        else:
            report.append("✅ RISK: LOW - No critical issues found")
        report.append("")
        
        # Detailed findings by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            severity_findings = [f for f in self.findings if f.severity == severity]
            if severity_findings:
                report.append("")
                report.append(f"{severity} FINDINGS ({len(severity_findings)})")
                report.append("-"*40)
                
                for finding in severity_findings[:20]:  # Limit to first 20 per severity
                    report.append(f"  [{finding.category}] {finding.file}:{finding.line}")
                    report.append(f"    {finding.message}")
                    if finding.code_snippet:
                        report.append(f"    Code: {finding.code_snippet[:60]}...")
                    report.append("")
                
                if len(severity_findings) > 20:
                    report.append(f"  ... and {len(severity_findings) - 20} more {severity} findings")
                    report.append("")
        
        # Recommendations
        report.append("")
        report.append("RECOMMENDATIONS")
        report.append("-"*40)
        
        if self.stats['CRITICAL'] > 0:
            report.append("1. Address all CRITICAL findings immediately")
            report.append("   - Remove eval()/exec() usage or sandbox properly")
            report.append("   - Use yaml.safe_load() instead of yaml.load()")
            report.append("   - Avoid subprocess with shell=True")
        
        if self.stats['HIGH'] > 0:
            report.append("2. Review HIGH severity findings")
            report.append("   - Remove hardcoded credentials")
            report.append("   - Use environment variables or secure vaults")
        
        if self.stats['MEDIUM'] > 0:
            report.append("3. Consider MEDIUM severity improvements")
            report.append("   - Enable SSL verification")
            report.append("   - Use stronger hash algorithms (SHA-256+)")
            report.append("   - Use secrets module for cryptographic randomness")
        
        report.append("")
        report.append("="*60)
        report.append("Report generated by HydraRecon Security Auditor")
        report.append("="*60)
        
        return "\n".join(report)


def main():
    """Run security audit"""
    # Get project root
    if len(sys.argv) > 1:
        project_root = sys.argv[1]
    else:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    auditor = SecurityAuditor(project_root)
    findings = auditor.scan_project()
    
    report = auditor.generate_report()
    print(report)
    
    # Write report to file
    report_path = os.path.join(project_root, 'SECURITY_AUDIT_REPORT.txt')
    with open(report_path, 'w') as f:
        f.write(report)
    
    print(f"\nReport saved to: {report_path}")
    
    # Exit with code based on findings
    if auditor.stats['CRITICAL'] > 0:
        return 2
    elif auditor.stats['HIGH'] > 0:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
