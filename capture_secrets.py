#!/usr/bin/env python3
"""
SecureFlow Secret Capture Script
Scans the codebase for hardcoded secrets and generates a comprehensive report.
"""
import os
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime

class SecretCapture:
    """Capture and inventory all secrets in the codebase."""
    
    # Secret patterns (regex)
    PATTERNS = {
        'api_key': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        'secret_key': r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        'password': r'["\']?password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        'db_password': r'DB_PASSWORD\s*[:=]\s*["\']?([^"\']+)["\']?',
        'postgres_password': r'POSTGRES_PASSWORD\s*[:=]\s*["\']?([^"\']+)["\']?',
        'jwt_secret': r'JWT_SECRET\s*[:=]\s*["\']?([^"\']+)["\']?',
        'session_secret': r'SESSION_SECRET\s*[:=]\s*["\']?([^"\']+)["\']?',
        'token': r'["\']?token["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
        'bearer_token': r'Bearer\s+([a-zA-Z0-9._-]+)',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN (RSA|OPENSSH|DSA|EC|PGP).*?-----END',
    }
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.secrets = {}
        self.files_scanned = 0
        
    def scan(self) -> Dict:
        """Scan the entire repository for secrets."""
        print(f"🔍 Scanning repository: {self.repo_path}")
        print("-" * 80)
        
        # Scan specific high-risk files
        self._scan_file(".env")
        self._scan_file("docker-compose.yml")
        self._scan_file(".env.example")
        self._scan_file("infra/terraform/main.tf")
        self._scan_glob("services/**/app.py")
        self._scan_glob("services/**/requirements.txt")
        self._scan_glob("infra/kubernetes/**/*.yaml")
        
        return self.secrets
    
    def _scan_file(self, filepath: str) -> None:
        """Scan a single file for secrets."""
        full_path = self.repo_path / filepath
        if not full_path.exists():
            return
        
        self.files_scanned += 1
        print(f"📄 Scanning: {filepath}")
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                self._extract_secrets(filepath, content)
        except Exception as e:
            print(f"  ⚠️  Error reading file: {e}")
    
    def _scan_glob(self, pattern: str) -> None:
        """Scan files matching a glob pattern."""
        for filepath in self.repo_path.glob(pattern):
            if filepath.is_file():
                self._scan_file(str(filepath.relative_to(self.repo_path)))
    
    def _extract_secrets(self, filepath: str, content: str) -> None:
        """Extract secrets from file content using regex patterns."""
        if filepath not in self.secrets:
            self.secrets[filepath] = []
        
        for pattern_name, pattern in self.PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            for match in matches:
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Extract the secret value
                secret_value = match.group(1) if match.groups() else match.group(0)
                
                # Skip common false positives
                if self._is_false_positive(secret_value):
                    continue
                
                secret_entry = {
                    'pattern': pattern_name,
                    'line': line_num,
                    'value': secret_value[:50] + '...' if len(secret_value) > 50 else secret_value,
                    'full_value': secret_value,
                    'risk': self._assess_risk(pattern_name, secret_value),
                }
                
                self.secrets[filepath].append(secret_entry)
                print(f"  🔐 {pattern_name.upper()} found at line {line_num}: {secret_value[:30]}...")
    
    def _is_false_positive(self, value: str) -> bool:
        """Check if the secret is a known false positive."""
        false_positives = [
            'placeholder', 'example', 'your_', 'xxx', 'yyy', 'zzz',
            'changeme', 'password123', 'admin', 'test', 'demo',
            'http://', 'https://', 'file://', 'true', 'false',
        ]
        return any(fp in value.lower() for fp in false_positives)
    
    def _assess_risk(self, pattern_name: str, value: str) -> str:
        """Assess the risk level of the secret."""
        critical_patterns = ['aws_key', 'private_key', 'jwt_secret', 'db_password']
        high_patterns = ['token', 'api_key', 'secret_key']
        
        if pattern_name in critical_patterns:
            return 'CRITICAL'
        elif pattern_name in high_patterns:
            return 'HIGH'
        elif len(value) < 8:
            return 'LOW'
        else:
            return 'MEDIUM'
    
    def generate_report(self) -> str:
        """Generate a formatted report of all captured secrets."""
        report = []
        report.append("=" * 80)
        report.append("SECUREFLOW SECRET CAPTURE REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.now().isoformat()}")
        report.append(f"Scan Location: {self.repo_path}")
        report.append(f"Files Scanned: {self.files_scanned}")
        report.append("")
        
        # Summary by risk level
        risk_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        total_secrets = 0
        
        for filepath, secrets in self.secrets.items():
            for secret in secrets:
                total_secrets += 1
                risk_summary[secret['risk']] += 1
        
        report.append("📊 RISK SUMMARY")
        report.append("-" * 80)
        report.append(f"Total Secrets Found: {total_secrets}")
        report.append(f"  🔴 CRITICAL: {risk_summary['CRITICAL']}")
        report.append(f"  🟠 HIGH:     {risk_summary['HIGH']}")
        report.append(f"  🟡 MEDIUM:   {risk_summary['MEDIUM']}")
        report.append(f"  🟢 LOW:      {risk_summary['LOW']}")
        report.append("")
        
        # Detailed findings by file
        report.append("📄 DETAILED FINDINGS BY FILE")
        report.append("=" * 80)
        
        for filepath, secrets in sorted(self.secrets.items()):
            if secrets:
                report.append(f"\n{filepath}")
                report.append("-" * 80)
                
                for i, secret in enumerate(secrets, 1):
                    report.append(f"  [{i}] Line {secret['line']}: {secret['pattern'].upper()}")
                    report.append(f"      Risk Level: {secret['risk']}")
                    report.append(f"      Value: {secret['value']}")
                    report.append("")
        
        # Recommendations
        report.append("=" * 80)
        report.append("🛡️  REMEDIATION RECOMMENDATIONS")
        report.append("=" * 80)
        report.append("""
1. IMMEDIATE ACTIONS:
   - Rotate all exposed credentials immediately
   - Revoke any exposed API keys and tokens
   - Reset database passwords

2. SOURCE CONTROL:
   - Use git filter-branch or git filter-repo to remove secrets from history
   - Never commit secrets to version control
   - Add .env and other secret files to .gitignore

3. SECRETS MANAGEMENT:
   - Move all secrets to environment variables
   - Use HashiCorp Vault or AWS Secrets Manager for production
   - Implement secret rotation policies

4. DETECTION:
   - Integrate Gitleaks into CI/CD pipeline
   - Enable pre-commit hooks to block secret commits
   - Run regular secret scans

5. DOCUMENTATION:
   - Create secure credential distribution process
   - Document secret management procedures
   - Train team on secret handling best practices
""")
        
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def save_json_report(self, output_path: str) -> None:
        """Save findings as JSON."""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'repo_path': str(self.repo_path),
            'files_scanned': self.files_scanned,
            'secrets': {}
        }
        
        for filepath, secrets in self.secrets.items():
            report_data['secrets'][filepath] = secrets
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\n✅ JSON report saved to: {output_path}")


def main():
    """Main entry point."""
    repo_path = Path(__file__).parent
    
    # Run secret capture
    capture = SecretCapture(str(repo_path))
    secrets = capture.scan()
    
    # Generate and print report
    report = capture.generate_report()
    print("\n")
    print(report)
    
    # Save reports
    report_path = repo_path / "secret_capture_report.txt"
    json_path = repo_path / "secret_capture_report.json"
    
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"✅ Text report saved to: {report_path}")
    
    capture.save_json_report(str(json_path))


if __name__ == "__main__":
    main()
