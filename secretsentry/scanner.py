"""
SecretSentry Scanner Module

This module contains the core scanning functionality for detecting sensitive
data in source code files, with special support for Jupyter notebooks and
intelligent false positive filtering.
"""

import os
import re
import random
import string
import json
import csv
import sys
from typing import Dict, List, Tuple, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path

# Import optional dependencies with fallbacks
try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    HAS_PLOTTING = True
    plt.style.use('default')
    sns.set_palette("husl")
except ImportError:
    HAS_PLOTTING = False

try:
    from IPython.display import display, HTML, clear_output
    import ipywidgets as widgets
    from ipywidgets import interact, interactive
    from tqdm.notebook import tqdm as notebook_tqdm
    HAS_JUPYTER = True
except ImportError:
    HAS_JUPYTER = False

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


@dataclass
class Finding:
    """Represents a sensitive data finding"""
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    pattern_type: str
    matched_text: str
    context: str

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)


class SensitiveDataScanner:
    """
    Universal Sensitive Data Scanner
    
    Supports CLI, Jupyter notebook, and Python script execution.
    Detects API keys, PII, credit cards, and other sensitive information.
    """
    
    def __init__(self, custom_patterns: Optional[Dict[str, str]] = None, 
                 execution_mode: str = 'auto'):
        """
        Initialize the scanner
        
        Args:
            custom_patterns: Custom regex patterns {name: pattern}
            execution_mode: 'cli', 'jupyter', 'script', or 'auto'
        """
        self.findings: List[Finding] = []
        self.patterns = self._load_default_patterns()
        self.exclusion_patterns = self._load_exclusion_patterns()
        
        if custom_patterns:
            self.patterns.update(custom_patterns)
        
        # Detect execution mode if auto
        if execution_mode == 'auto':
            execution_mode = self._detect_execution_mode()
        
        self.execution_mode = execution_mode
        self.scan_stats = {
            'files_scanned': 0,
            'total_findings': 0,
            'patterns_matched': set(),
            'false_positives_filtered': 0
        }
    
    def _detect_execution_mode(self) -> str:
        """Auto-detect execution environment"""
        try:
            # Check if running in Jupyter
            if 'ipykernel' in sys.modules or 'IPython' in sys.modules:
                return 'jupyter'
            # Check if called from command line
            elif len(sys.argv) > 1:
                return 'cli'
            else:
                return 'script'
        except:
            return 'script'
    
    def _load_default_patterns(self) -> Dict[str, str]:
        """Load comprehensive regex patterns for sensitive data detection"""
        return {
            # API Keys and Secrets - More context-aware patterns
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'(?<![\w/])[A-Za-z0-9/+=]{40}(?![\w/+=])',
            'github_token': r'ghp_[A-Za-z0-9]{36}',
            'github_classic_token': r'gh[pousr]_[A-Za-z0-9]{36}',
            'slack_token': r'xox[baprs]-[A-Za-z0-9-]{10,72}',
            'slack_webhook': r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+',
            'google_api_key': r'AIza[0-9A-Za-z_-]{35}',
            'google_oauth': r'ya29\.[0-9A-Za-z_-]+',
            'stripe_live_key': r'sk_live_[0-9a-zA-Z]{24}',
            'stripe_test_key': r'sk_test_[0-9a-zA-Z]{24}',
            'twilio_key': r'SK[a-z0-9]{32}',
            'sendgrid_key': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
            'mailgun_key': r'key-[a-z0-9]{32}',
            'generic_api_key': r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)["\'\s]*[:=]["\'\s]*[A-Za-z0-9+/=_-]{16,}',
            
            # Cloud Provider Keys
            'azure_storage_key': r'[A-Za-z0-9+/]{88}==',
            'gcp_service_account': r'"private_key":\s*"-----BEGIN PRIVATE KEY-----[^"]+-----END PRIVATE KEY-----"',
            'heroku_api_key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            
            # Credit Card Numbers
            'credit_card_visa': r'4[0-9]{12}(?:[0-9]{3})?',
            'credit_card_mastercard': r'5[1-5][0-9]{14}',
            'credit_card_amex': r'3[47][0-9]{13}',
            'credit_card_discover': r'6(?:011|5[0-9]{2})[0-9]{12}',
            'credit_card_diners': r'3[0689][0-9]{11}',
            'credit_card_jcb': r'(?:2131|1800|35\d{3})\d{11}',
            'credit_card_generic': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            
            # Personal Identifiers
            'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
            'phone_us': r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
            'phone_international': r'\+[1-9]\d{1,14}',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'passport_us': r'\b[A-Z]{1,2}[0-9]{6,9}\b',
            'drivers_license': r'\b[A-Z]{1,2}[0-9]{6,8}\b',
            
            # Financial Information
            'salary_pattern': r'(?i)\b(salary|wage|income|compensation|pay|annual[_-]?salary)\s*[:=]\s*\$?[\d,]+(?:\.\d{2})?\b',
            'bank_account': r'\b\d{8,17}\b',
            'routing_number': r'\b[0-9]{9}\b',
            'iban': r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b',
            'swift_code': r'\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b',
            
            # Geographic Information
            'coordinates': r'[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)',
            'zip_code_us': r'\b\d{5}(?:-\d{4})?\b',
            'postal_code_ca': r'\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z][ -]?\d[ABCEGHJ-NPRSTV-Z]\d\b',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'ipv6_address': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            'mac_address': r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b',
            
            # Sensitive Personal Data
            'ethnic_terms': r'(?i)\b(race|ethnicity|ethnic[_-]?group|racial[_-]?category)\s*[:=]\s*["\']?[A-Za-z\s]+["\']?',
            'religion': r'(?i)\b(religion|religious[_-]?affiliation)\s*[:=]\s*["\']?[A-Za-z\s]+["\']?',
            'medical_record': r'(?i)\b(medical[_-]?record|patient[_-]?id|mrn)\s*[:=]\s*["\']?[A-Za-z0-9]+["\']?',
            'disability_status': r'(?i)\b(disability|disabled|handicap)\s*[:=]\s*["\']?[A-Za-z\s]+["\']?',
            
            # Database and System
            'db_connection': r'(?i)(connection[_-]?string|database[_-]?url|db[_-]?url)\s*[:=]\s*["\'][^"\']+["\']',
            'mongodb_uri': r'mongodb://[^"\s]+',
            'redis_url': r'redis://[^"\s]+',
            'password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{6,}["\']',
            'username': r'(?i)(username|user)\s*[:=]\s*["\'][^"\']+["\']',
            
            # Private Keys and Certificates
            'private_key': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
            'public_key': r'-----BEGIN\s+PUBLIC\s+KEY-----',
            'certificate': r'-----BEGIN\s+CERTIFICATE-----',
            'ssh_key': r'ssh-rsa\s+[A-Za-z0-9+/=]+',
            'ssh_ed25519': r'ssh-ed25519\s+[A-Za-z0-9+/=]+',
            
            # Tokens and JWTs
            'jwt_token': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'bearer_token': r'(?i)bearer\s+[A-Za-z0-9+/=_-]+',
            'oauth_token': r'(?i)oauth[_-]?token["\'\s]*[:=]["\'\s]*[A-Za-z0-9+/=_-]{20,}',
            
            # URLs with credentials
            'url_with_password': r'https?://[^:\s]+:[^@\s]+@[^\s]+',
            'ftp_with_credentials': r'ftp://[^:\s]+:[^@\s]+@[^\s]+',
        }
    
    def _load_exclusion_patterns(self) -> List[str]:
        """Load patterns that should be excluded as false positives"""
        return [
            # Base64 encoded images (common in Jupyter notebooks)
            r'iVBORw0KGgo',  # PNG header in base64
            r'/9j/',  # JPEG header in base64
            r'data:image/',  # Data URL images
            r'R0lGODlh',  # GIF header in base64
            
            # Jupyter notebook cell IDs and execution metadata
            r'"cell_type"',
            r'"execution_count"',
            r'"metadata"',
            r'"outputs"',
            r'"source"',
            
            # Common HTML/CSS/JS patterns that look like secrets but aren't
            r'#[0-9a-fA-F]{6}',  # Hex colors
            r'rgb\(',  # RGB colors
            r'rgba\(',  # RGBA colors
            r'url\(',  # CSS URLs
            
            # Font and asset hashes
            r'woff2',
            r'ttf',
            r'eot',
            r'font-',
            
            # Common library/framework identifiers
            r'jQuery',
            r'bootstrap',
            r'fontawesome',
            r'googleapis',
            
            # Lorem ipsum and placeholder text
            r'lorem',
            r'ipsum',
            r'placeholder',
        ]
    
    def _is_likely_false_positive(self, matched_text: str, context: str, file_path: str) -> bool:
        """Check if a match is likely a false positive"""
        # Check against exclusion patterns
        for exclusion_pattern in self.exclusion_patterns:
            if re.search(exclusion_pattern, context, re.IGNORECASE):
                return True
        
        # Special handling for Jupyter notebooks
        if file_path.endswith('.ipynb'):
            return self._is_jupyter_false_positive(matched_text, context)
        
        # Special handling for HTML files
        if file_path.endswith(('.html', '.htm')):
            return self._is_html_false_positive(matched_text, context)
        
        return False
    
    def _is_jupyter_false_positive(self, matched_text: str, context: str) -> bool:
        """Check for Jupyter notebook specific false positives"""
        # Base64 image data
        if 'data:image/' in context or '"image/png"' in context or '"image/jpeg"' in context:
            return True
        
        # Cell metadata and outputs
        if any(keyword in context for keyword in [
            '"cell_type"', '"execution_count"', '"metadata"', '"outputs"',
            '"display_data"', '"execute_result"', '"stream"'
        ]):
            return True
        
        # Notebook execution IDs and cell IDs that look like secrets
        if len(matched_text) > 20 and (
            context.count('"') > 2 or  # Likely JSON
            'execution_count' in context or
            'cell_id' in context.lower()
        ):
            return True
        
        return False
    
    def _is_html_false_positive(self, matched_text: str, context: str) -> bool:
        """Check for HTML specific false positives"""
        # Base64 encoded assets
        if 'data:' in context and ('base64,' in context):
            return True
        
        # CSS/HTML attributes that might look like secrets
        if any(attr in context.lower() for attr in [
            'src=', 'href=', 'style=', 'class=', 'id=', 'alt=', 'title='
        ]):
            return True
        
        # JavaScript/CSS content
        if any(keyword in context for keyword in [
            'function(', 'var ', 'const ', 'let ', '.css', '.js'
        ]):
            return True
        
        return False
    
    def add_custom_patterns(self, patterns: Dict[str, str]) -> None:
        """Add custom regex patterns"""
        self.patterns.update(patterns)
    
    def set_findings(self, findings: List[Finding]) -> None:
        """Set findings manually (useful for testing)"""
        self.findings = findings
    
    def scan_file(self, file_path: str, show_progress: bool = False) -> List[Finding]:
        """Scan a single file for sensitive data"""
        file_findings = []
        
        try:
            # Special handling for Jupyter notebooks
            if file_path.endswith('.ipynb'):
                return self._scan_jupyter_notebook(file_path, show_progress)
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
            
            pattern_items = list(self.patterns.items())
            
            if show_progress and HAS_JUPYTER:
                pattern_items = notebook_tqdm(pattern_items, desc=f"Scanning {os.path.basename(file_path)}")
            elif show_progress and HAS_TQDM:
                pattern_items = tqdm(pattern_items, desc=f"Scanning {os.path.basename(file_path)}")
                
            for pattern_name, pattern in pattern_items:
                for line_num, line in enumerate(lines, 1):
                    try:
                        for match in re.finditer(pattern, line):
                            matched_text = match.group()
                            
                            # Check for false positives
                            if self._is_likely_false_positive(matched_text, line, file_path):
                                self.scan_stats['false_positives_filtered'] += 1
                                continue
                            
                            finding = Finding(
                                file_path=file_path,
                                line_number=line_num,
                                column_start=match.start(),
                                column_end=match.end(),
                                pattern_type=pattern_name,
                                matched_text=matched_text,
                                context=line.strip()
                            )
                            file_findings.append(finding)
                            self.scan_stats['patterns_matched'].add(pattern_name)
                    except re.error:
                        # Skip invalid regex patterns
                        continue
                        
        except Exception as e:
            print(f"❌ Error scanning file {file_path}: {e}")
            
        return file_findings
    
    def _scan_jupyter_notebook(self, file_path: str, show_progress: bool = False) -> List[Finding]:
        """Special scanning logic for Jupyter notebook files"""
        file_findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                notebook_content = file.read()
            
            # Parse as JSON to access notebook structure
            try:
                import json
                notebook_data = json.loads(notebook_content)
                
                # Only scan source code cells, not outputs or metadata
                lines_to_scan = []
                line_mapping = {}  # Map processed line numbers to original positions
                current_line = 1
                
                for cell in notebook_data.get('cells', []):
                    if cell.get('cell_type') == 'code':
                        source_lines = cell.get('source', [])
                        for source_line in source_lines:
                            if isinstance(source_line, str):
                                lines_to_scan.append(source_line)
                                line_mapping[len(lines_to_scan)] = current_line
                                current_line += 1
                
            except (json.JSONDecodeError, KeyError):
                # Fallback: treat as regular text file but with stricter filtering
                lines_to_scan = notebook_content.split('\n')
                line_mapping = {i+1: i+1 for i in range(len(lines_to_scan))}
            
            # Scan the extracted lines
            pattern_items = list(self.patterns.items())
            
            if show_progress and HAS_JUPYTER:
                pattern_items = notebook_tqdm(pattern_items, desc=f"Scanning {os.path.basename(file_path)}")
            elif show_progress and HAS_TQDM:
                pattern_items = tqdm(pattern_items, desc=f"Scanning {os.path.basename(file_path)}")
            
            for pattern_name, pattern in pattern_items:
                for line_idx, line in enumerate(lines_to_scan, 1):
                    try:
                        for match in re.finditer(pattern, line):
                            matched_text = match.group()
                            
                            # Extra strict filtering for notebooks
                            if (self._is_likely_false_positive(matched_text, line, file_path) or
                                self._is_notebook_metadata(line) or
                                len(matched_text) > 100):  # Very long matches in notebooks are usually data
                                self.scan_stats['false_positives_filtered'] += 1
                                continue
                            
                            # Map back to original line number
                            original_line = line_mapping.get(line_idx, line_idx)
                            
                            finding = Finding(
                                file_path=file_path,
                                line_number=original_line,
                                column_start=match.start(),
                                column_end=match.end(),
                                pattern_type=pattern_name,
                                matched_text=matched_text,
                                context=line.strip()
                            )
                            file_findings.append(finding)
                            self.scan_stats['patterns_matched'].add(pattern_name)
                    except re.error:
                        continue
                        
        except Exception as e:
            print(f"❌ Error scanning Jupyter notebook {file_path}: {e}")
            
        return file_findings
    
    def _is_notebook_metadata(self, line: str) -> bool:
        """Check if line contains notebook metadata that should be ignored"""
        metadata_indicators = [
            '"cell_type":', '"execution_count":', '"metadata":', '"outputs":',
            '"display_data"', '"execute_result"', '"stream"', '"text/plain"',
            '"image/png"', '"image/jpeg"', '"text/html"', '"application/json"'
        ]
        return any(indicator in line for indicator in metadata_indicators)
    
    def scan_directory(self, directory_path: str, 
                      file_extensions: Optional[List[str]] = None,
                      exclude_dirs: Optional[List[str]] = None,
                      show_progress: bool = True) -> List[Finding]:
        """Recursively scan directory for sensitive data"""
        if file_extensions is None:
            file_extensions = [
                '.py', '.js', '.java', '.cpp', '.c', '.h', '.cs', '.php', 
                '.rb', '.go', '.rs', '.swift', '.kt', '.ts', '.jsx', '.tsx',
                '.sql', '.xml', '.json', '.yaml', '.yml', '.config', '.env',
                '.ini', '.conf', '.properties', '.toml', '.dockerfile',
                '.html', '.htm', '.ipynb', '.md', '.txt'
            ]
        
        if exclude_dirs is None:
            exclude_dirs = {
                '.git', '.svn', '__pycache__', 'node_modules', 'venv', 'env',
                '.venv', 'dist', 'build', 'target', '.idea', '.vscode'
            }
        
        # Collect all files
        files_to_scan = []
        for root, dirs, files in os.walk(directory_path):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = Path(file).suffix.lower()
                
                if (file_ext in file_extensions or 
                    any(ext in file.lower() for ext in file_extensions)):
                    files_to_scan.append(file_path)
        
        all_findings = []
        
        # Scan files with appropriate progress tracking
        if show_progress and self._should_show_progress():
            if self.execution_mode == 'jupyter' and HAS_JUPYTER:
                files_iter = notebook_tqdm(files_to_scan, desc="Scanning files")
            elif HAS_TQDM:
                files_iter = tqdm(files_to_scan, desc="Scanning files")
            else:
                files_iter = files_to_scan
                print(f"Scanning {len(files_to_scan)} files...")
        else:
            files_iter = files_to_scan
            
        for file_path in files_iter:
            findings = self.scan_file(file_path, show_progress=False)
            all_findings.extend(findings)
            self.scan_stats['files_scanned'] += 1
        
        self.findings = all_findings
        self.scan_stats['total_findings'] = len(all_findings)
        return all_findings
    
    def _should_show_progress(self) -> bool:
        """Determine if progress bars should be shown"""
        return self.execution_mode in ['cli', 'jupyter', 'script']
    
    def display_findings(self, max_display: int = 50, group_by_type: bool = True, 
                        show_context: bool = True) -> None:
        """Display findings with environment-appropriate formatting"""
        if not self.findings:
            if self.execution_mode == 'jupyter' and HAS_JUPYTER:
                display(HTML("<h3>🎉 No sensitive data found!</h3>"))
            else:
                print("🎉 No sensitive data found!")
            return
        
        if self.execution_mode == 'jupyter' and HAS_JUPYTER:
            self._display_findings_jupyter(max_display)
        else:
            self._display_findings_console(max_display, group_by_type, show_context)
    
    def _display_findings_console(self, max_display: int, group_by_type: bool, 
                                 show_context: bool) -> None:
        """Display findings in console format"""
        print(f"\n🔍 Found {len(self.findings)} potential sensitive data instances")
        print(f"📊 Files scanned: {self.scan_stats['files_scanned']}")
        print(f"📋 Pattern types found: {len(self.scan_stats['patterns_matched'])}")
        print(f"🛡️  False positives filtered: {self.scan_stats['false_positives_filtered']}\n")
        
        findings_to_show = self.findings[:max_display]
        
        if group_by_type:
            # Group by pattern type
            grouped = {}
            for finding in findings_to_show:
                if finding.pattern_type not in grouped:
                    grouped[finding.pattern_type] = []
                grouped[finding.pattern_type].append(finding)
            
            for pattern_type, findings in grouped.items():
                print(f"📋 {pattern_type.upper()} ({len(findings)} instances):")
                print("-" * 60)
                
                for finding in findings:
                    print(f"  📁 File: {finding.file_path}")
                    print(f"  📍 Line {finding.line_number}, Col {finding.column_start}-{finding.column_end}")
                    print(f"  🎯 Match: {finding.matched_text}")
                    if show_context:
                        print(f"  📝 Context: {finding.context[:100]}...")
                    print()
        else:
            for i, finding in enumerate(findings_to_show, 1):
                print(f"{i}. {finding.pattern_type.upper()}")
                print(f"   📁 File: {finding.file_path}")
                print(f"   📍 Line {finding.line_number}")
                print(f"   🎯 Match: {finding.matched_text}")
                if show_context:
                    print(f"   📝 Context: {finding.context[:100]}...")
                print()
        
        if len(self.findings) > max_display:
            print(f"... and {len(self.findings) - max_display} more findings")
    
    def _display_findings_jupyter(self, max_display: int) -> None:
        """Display findings in Jupyter format with HTML styling"""
        # Create summary
        display(HTML(f"""
        <div style="background-color: #f0f8ff; padding: 15px; border-radius: 8px; margin: 10px 0;">
            <h3>🔍 Scan Results Summary</h3>
            <strong>Total Findings:</strong> {len(self.findings)}<br>
            <strong>Files Scanned:</strong> {self.scan_stats['files_scanned']}<br>
            <strong>Pattern Types Found:</strong> {len(self.scan_stats['patterns_matched'])}<br>
            <strong>False Positives Filtered:</strong> {self.scan_stats['false_positives_filtered']}
        </div>
        """))
        
        # Create findings table
        findings_to_show = self.findings[:max_display]
        
        html_table = """
        <table style="width:100%; border-collapse: collapse; margin: 20px 0;">
        <tr style="background-color: #4CAF50; color: white;">
            <th style="border: 1px solid #ddd; padding: 8px;">Pattern Type</th>
            <th style="border: 1px solid #ddd; padding: 8px;">File</th>
            <th style="border: 1px solid #ddd; padding: 8px;">Line</th>
            <th style="border: 1px solid #ddd; padding: 8px;">Match</th>
            <th style="border: 1px solid #ddd; padding: 8px;">Context</th>
        </tr>
        """
        
        for i, finding in enumerate(findings_to_show):
            row_color = "#f2f2f2" if i % 2 == 0 else "white"
            match_display = finding.matched_text[:30] + "..." if len(finding.matched_text) > 30 else finding.matched_text
            context_display = finding.context[:50] + "..." if len(finding.context) > 50 else finding.context
            
            html_table += f"""
            <tr style="background-color: {row_color};">
                <td style="border: 1px solid #ddd; padding: 8px;"><strong>{finding.pattern_type}</strong></td>
                <td style="border: 1px solid #ddd; padding: 8px;">{os.path.basename(finding.file_path)}</td>
                <td style="border: 1px solid #ddd; padding: 8px;">{finding.line_number}</td>
                <td style="border: 1px solid #ddd; padding: 8px; font-family: monospace;">{match_display}</td>
                <td style="border: 1px solid #ddd; padding: 8px; font-family: monospace;">{context_display}</td>
            </tr>
            """
        
        html_table += "</table>"
        
        if len(self.findings) > max_display:
            html_table += f"<p><em>Showing {max_display} of {len(self.findings)} findings.</em></p>"
        
        display(HTML(html_table))
    
    def generate_gibberish(self, length: int, pattern_type: str) -> str:
        """Generate appropriate replacement text based on pattern type"""
        if 'credit_card' in pattern_type:
            return ''.join(random.choices('0123456789', k=length))
        elif 'email' in pattern_type:
            username = ''.join(random.choices(string.ascii_lowercase, k=8))
            domain = ''.join(random.choices(string.ascii_lowercase, k=6))
            return f"{username}@{domain}.com"
        elif 'phone' in pattern_type:
            return f"({random.randint(200,999)}) {random.randint(200,999)}-{random.randint(1000,9999)}"
        elif 'ssn' in pattern_type:
            return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"
        elif any(key in pattern_type for key in ['key', 'token', 'secret']):
            chars = string.ascii_letters + string.digits
            return ''.join(random.choices(chars, k=length))
        elif 'coordinates' in pattern_type:
            lat = round(random.uniform(-90, 90), 6)
            lon = round(random.uniform(-180, 180), 6)
            return f"{lat}, {lon}"
        elif 'ip_address' in pattern_type:
            return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        elif 'url' in pattern_type:
            return "https://sanitized-url.example.com"
        else:
            chars = string.ascii_letters + string.digits
            return ''.join(random.choices(chars, k=min(length, 20)))
    
    def sanitize_files(self, backup: bool = True, dry_run: bool = False) -> Dict[str, int]:
        """Sanitize files by replacing sensitive data with gibberish"""
        if not self.findings:
            if dry_run:
                print("No findings to sanitize!")
            return {'files_processed': 0, 'instances_sanitized': 0}
        
        # Group findings by file
        files_to_sanitize = {}
        for finding in self.findings:
            if finding.file_path not in files_to_sanitize:
                files_to_sanitize[finding.file_path] = []
            files_to_sanitize[finding.file_path].append(finding)
        
        stats = {'files_processed': 0, 'instances_sanitized': 0}
        
        # Progress tracking for sanitization
        if self._should_show_progress():
            if self.execution_mode == 'jupyter' and HAS_JUPYTER:
                file_iter = notebook_tqdm(files_to_sanitize.items(), desc="Sanitizing files")
            elif HAS_TQDM:
                file_iter = tqdm(files_to_sanitize.items(), desc="Sanitizing files")
            else:
                file_iter = files_to_sanitize.items()
                print(f"Processing {len(files_to_sanitize)} files...")
        else:
            file_iter = files_to_sanitize.items()
        
        for file_path, findings in file_iter:
            try:
                # Read original file with better error handling
                try:
                    with open(file_path, 'r', encoding='utf-8') as file:
                        content = file.read()
                except UnicodeDecodeError:
                    # Skip binary files or files with encoding issues
                    print(f"⚠️  Skipping file with encoding issues: {os.path.basename(file_path)}")
                    continue
                
                # Create backup
                if backup and not dry_run:
                    backup_path = f"{file_path}.backup"
                    with open(backup_path, 'w', encoding='utf-8') as backup_file:
                        backup_file.write(content)
                    if self.execution_mode != 'cli':
                        print(f"📋 Created backup: {backup_path}")
                
                # Sort findings by position (reverse order)
                findings.sort(key=lambda x: (x.line_number, x.column_start), reverse=True)
                
                lines = content.split('\n')
                
                for finding in findings:
                    if finding.line_number <= len(lines):
                        line = lines[finding.line_number - 1]
                        
                        # Generate replacement
                        original_text = finding.matched_text
                        gibberish = self.generate_gibberish(len(original_text), finding.pattern_type)
                        
                        # Debug info for CLI mode
                        if dry_run and self.execution_mode != 'cli':
                            print(f"🔄 Would replace '{original_text}' with '{gibberish}' in {os.path.basename(file_path)}:{finding.line_number}")
                        
                        # More robust replacement - ensure we're replacing the right text
                        if original_text in line:
                            # Replace by text matching (more reliable)
                            new_line = line.replace(original_text, gibberish, 1)  # Replace only first occurrence
                        else:
                            # Fallback to position-based replacement
                            new_line = (line[:finding.column_start] + 
                                      gibberish + 
                                      line[finding.column_end:])
                        
                        lines[finding.line_number - 1] = new_line
                        stats['instances_sanitized'] += 1
                
                # Write sanitized content
                if not dry_run:
                    with open(file_path, 'w', encoding='utf-8') as file:
                        file.write('\n'.join(lines))
                
                stats['files_processed'] += 1
                
            except Exception as e:
                print(f"❌ Error sanitizing file {file_path}: {e}")
        
        return stats
    
    def export_findings(self, output_file: str, format: str = 'auto') -> None:
        """Export findings to file"""
        if format == 'auto':
            format = 'json' if output_file.endswith('.json') else 'csv'
        
        if format == 'json':
            findings_dict = [finding.to_dict() for finding in self.findings]
            with open(output_file, 'w') as f:
                json.dump(findings_dict, f, indent=2)
        
        elif format == 'csv':
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['File Path', 'Line Number', 'Column Start', 'Column End', 
                               'Pattern Type', 'Matched Text', 'Context'])
                
                for finding in self.findings:
                    writer.writerow([finding.file_path, finding.line_number, finding.column_start,
                                   finding.column_end, finding.pattern_type, finding.matched_text,
                                   finding.context])
        
        print(f"📊 Exported {len(self.findings)} findings to {output_file}")
    
    # Pandas integration (if available)
    def to_dataframe(self):
        """Convert findings to pandas DataFrame"""
        if not HAS_PANDAS:
            print("⚠️  pandas not available - install with: pip install pandas")
            return None
        
        if not self.findings:
            return pd.DataFrame()
        
        data = []
        for finding in self.findings:
            data.append({
                'pattern_type': finding.pattern_type,
                'file_path': finding.file_path,
                'filename': os.path.basename(finding.file_path),
                'line_number': finding.line_number,
                'column_start': finding.column_start,
                'column_end': finding.column_end,
                'matched_text': finding.matched_text,
                'match_length': len(finding.matched_text),
                'context': finding.context,
                'file_extension': Path(finding.file_path).suffix.lower()
            })
        
        return pd.DataFrame(data)
    
    # Jupyter-specific methods
    def create_interactive_viewer(self):
        """Create interactive Jupyter widget for exploring findings"""
        if not HAS_JUPYTER:
            print("⚠️  Interactive viewer requires Jupyter widgets")
            print("Install with: pip install ipywidgets")
            return
        
        if not self.findings:
            print("No findings to explore!")
            return
        
        df = self.to_dataframe()
        if df is None:
            return
        
        # Create widgets
        pattern_options = ['All'] + sorted(df['pattern_type'].unique().tolist())
        file_options = ['All'] + sorted(df['filename'].unique().tolist())
        
        pattern_dropdown = widgets.Dropdown(
            options=pattern_options,
            value='All',
            description='Pattern:'
        )
        
        file_dropdown = widgets.Dropdown(
            options=file_options,
            value='All',
            description='File:'
        )
        
        max_slider = widgets.IntSlider(
            value=20,
            min=5,
            max=100,
            step=5,
            description='Max Results:'
        )
        
        def filter_and_display(pattern_type, filename, max_results):
            filtered_df = df.copy()
            
            if pattern_type != 'All':
                filtered_df = filtered_df[filtered_df['pattern_type'] == pattern_type]
            
            if filename != 'All':
                filtered_df = filtered_df[filtered_df['filename'] == filename]
            
            if len(filtered_df) == 0:
                display(HTML("<p>No findings match the selected filters.</p>"))
                return
            
            result_df = filtered_df[['pattern_type', 'filename', 'line_number', 'matched_text', 'context']].head(max_results)
            display(HTML(f"<h4>Showing {len(result_df)} of {len(filtered_df)} findings</h4>"))
            display(result_df)
        
        interactive_plot = interactive(filter_and_display, 
                                     pattern_type=pattern_dropdown,
                                     filename=file_dropdown,
                                     max_results=max_slider)
        display(interactive_plot)
    
    def plot_findings_distribution(self, figsize: Tuple[int, int] = (12, 8)):
        """Create visualization plots of findings"""
        if not HAS_PLOTTING:
            print("⚠️  Plotting requires matplotlib and seaborn")
            print("Install with: pip install matplotlib seaborn")
            return
        
        if not self.findings:
            print("No findings to visualize!")
            return
        
        df = self.to_dataframe()
        if df is None or df.empty:
            return
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=figsize)
        
        # Pattern type distribution
        pattern_counts = df['pattern_type'].value_counts().head(10)
        ax1.barh(pattern_counts.index, pattern_counts.values)
        ax1.set_title('Top 10 Pattern Types')
        ax1.set_xlabel('Count')
        
        # Files with most findings
        file_counts = df['filename'].value_counts().head(10)
        ax2.barh(file_counts.index, file_counts.values)
        ax2.set_title('Top 10 Files by Findings')
        ax2.set_xlabel('Count')
        
        # Pattern type pie chart
        top_patterns = pattern_counts.head(7)
        if len(pattern_counts) > 7:
            others = pattern_counts.iloc[7:].sum()
            plot_data = pd.concat([top_patterns, pd.Series([others], index=['Others'])])
        else:
            plot_data = top_patterns
        
        ax3.pie(plot_data.values, labels=plot_data.index, autopct='%1.1f%%')
        ax3.set_title('Pattern Distribution')
        
        # File extension analysis
        ext_counts = df['file_extension'].value_counts().head(8)
        ax4.bar(ext_counts.index, ext_counts.values)
        ax4.set_title('Findings by File Extension')
        ax4.set_xlabel('Extension')
        ax4.set_ylabel('Count')
        ax4.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.show()


# Convenience functions for script usage
def quick_scan(directory_path: str, 
               file_extensions: Optional[List[str]] = None,
               custom_patterns: Optional[Dict[str, str]] = None,
               show_plots: bool = False) -> SensitiveDataScanner:
    """Quick scan function for script usage"""
    scanner = SensitiveDataScanner(custom_patterns=custom_patterns, execution_mode='script')
    
    print(f"🚀 Scanning: {directory_path}")
    findings = scanner.scan_directory(directory_path, file_extensions=file_extensions)
    
    print(f"✅ Found {len(findings)} potential issues in {scanner.scan_stats['files_scanned']} files")
    
    scanner.display_findings()
    
    if show_plots and HAS_PLOTTING and findings:
        scanner.plot_findings_distribution()
    
    return scanner


def create_sample_files(base_dir: str = "./test_sensitive_data") -> None:
    """Create sample files with various types of sensitive data for testing"""
    os.makedirs(base_dir, exist_ok=True)
    
    # Sample Python file
    python_content = '''#!/usr/bin/env python3
import os
import requests

# NOTICE: ALL DATA BELOW IS FAKE AND FOR TESTING SECRETSENTRY ONLY
# These patterns are designed to be detected by the scanner but are obviously fake

# API Keys - OBVIOUSLY FAKE PATTERNS FOR TESTING
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS example key from documentation
github_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # GitHub placeholder format
stripe_live_key = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx"  # Stripe placeholder format  
google_api_key = "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"  # Google placeholder format

# Database connections - FAKE TEST CREDENTIALS
DATABASE_URL = "postgresql://testuser:testpass123@localhost:5432/testdb"
REDIS_URL = "redis://testuser:testpass123@localhost:6379/0"

# Personal information - FAKE TEST DATA
employee_data = {
    "salary": 85000,
    "ssn": "000-00-0000",  # Invalid SSN format for testing
    "phone": "(000) 000-0000",  # Invalid phone for testing  
    "email": "test@example.com",
    "credit_card": "0000-0000-0000-0000"  # Invalid card for testing
}

# Geographic information
office_coordinates = "00.0000, 00.0000"  # Fake coordinates
employee_zip = "00000"
server_ip = "127.0.0.1"  # Localhost IP

# Sensitive personal data - TEST DATA ONLY
def process_employee_data():
    employee_race = "TestRace"
    employee_religion = "TestReligion"  
    medical_record_id = "MRN-TEST001"
    return employee_race, employee_religion

# Private key - FAKE TEST KEY
private_key = """-----BEGIN RSA PRIVATE KEY-----
FAKE-TEST-KEY-NOT-REAL-DO-NOT-USE
THIS-IS-FOR-SECRETSENTRY-TESTING-ONLY
-----END RSA PRIVATE KEY-----"""

# JWT token - FAKE TEST TOKEN
auth_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJURVNUIiwibmFtZSI6IlRlc3QgVXNlciJ9.FAKE-TEST-SIGNATURE"

if __name__ == "__main__":
    print("Processing FAKE test data for SecretSentry testing...")
'''
    
    # Sample environment file  
    env_content = '''# NOTICE: ALL CREDENTIALS BELOW ARE FAKE FOR TESTING SECRETSENTRY
# Database Configuration - TEST CREDENTIALS ONLY
DATABASE_URL=postgresql://testuser:testpass123@localhost:5432/testdb
REDIS_URL=redis://testuser:testpass123@localhost:6379/0

# API Keys - FAKE PLACEHOLDER PATTERNS FOR TESTING
STRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxxx
GOOGLE_MAPS_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
SLACK_BOT_TOKEN=xoxb-000000000000-000000000000-xxxxxxxxxxxxxxxxxxxxxxxx
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Email Service - FAKE PLACEHOLDER PATTERNS
SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxx
MAILGUN_API_KEY=key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Employee Information - TEST DATA
HR_DIRECTOR_SALARY=95000
CFO_COMPENSATION=175000

# System Configuration - TEST DATA
ADMIN_EMAIL=test@example.com
SUPPORT_PHONE=+1-000-000-0000
SERVER_IP=127.0.0.1
'''
    
    # Sample HTML file
    html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecretSentry Test File - FAKE DATA</title>
    <style>
        body { background-color: #f0f0f0; }
        .warning { color: #ff0000; font-weight: bold; }
    </style>
</head>
<body>
    <h1>SecretSentry Test Application</h1>
    <div class="warning">⚠️ ALL DATA IN THIS FILE IS FAKE FOR TESTING PURPOSES</div>
    
    <!-- Fake sensitive data for testing detection -->
    <script>
        // FAKE API KEYS FOR SECRETSENTRY TESTING
        const config = {
            apiKey: "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
            stripeKey: "pk_live_xxxxxxxxxxxxxxxxxxxxxxxx", 
            databaseUrl: "mongodb://testuser:testpass@localhost:27017/testapp"
        };
        
        // FAKE employee data for testing detection
        const employeeInfo = {
            ssn: "000-00-0000",
            salary: "$95000", 
            email: "test@example.com"
        };
        
        // Base64 image data (should be filtered out as false positive)
        const logoImage = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
        
        // CSS hex colors (should be filtered out)
        const colors = {
            primary: "#3498db",
            secondary: "#2ecc71", 
            danger: "#e74c3c"
        };
    </script>
    
    <p>Contact: test@example.com or (000) 000-0000</p>
    <p><strong>⚠️ This is a test file for SecretSentry with fake data only!</strong></p>
</body>
</html>'''
    
    # Jupyter notebook with fake data
    notebook_content = '''{
 "cells": [
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# SecretSentry Test Notebook\\n",
    "⚠️ This notebook contains FAKE data for testing SecretSentry detection"
   ]
  },
  {
   "cell_type": "code", 
   "execution_count": 1,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream", 
     "text": [
      "Loading FAKE test configuration...\\n"
     ]
    }
   ],
   "source": [
    "# FAKE Configuration for SecretSentry testing\\n",
    "API_KEY = \\"AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\\"\\n",
    "DATABASE_PASSWORD = \\"fake_test_password_123\\"\\n",
    "\\n",
    "# FAKE employee data\\n", 
    "employee_ssn = \\"000-00-0000\\"\\n",
    "employee_salary = 75000\\n",
    "\\n",
    "print(\\"Loading FAKE test configuration...\\")\\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 2,
   "metadata": {},
   "outputs": [],
   "source": [
    "# More FAKE sensitive data for testing\\n",
    "credit_card = \\"0000-0000-0000-0000\\"\\n",
    "phone_number = \\"(000) 000-0000\\"\\n", 
    "email_address = \\"test@example.com\\""
   ]
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python", 
   "name": "python3"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 4
}'''
    
    # Create files
    files_to_create = [
        ("sensitive_app.py", python_content),
        (".env", env_content), 
        ("sample_webpage.html", html_content),
        ("data_analysis.ipynb", notebook_content)
    ]
    
    for filename, content in files_to_create:
        file_path = os.path.join(base_dir, filename)
        with open(file_path, 'w') as f:
            f.write(content)
    
    print(f"📁 Created {len(files_to_create)} sample files in {base_dir}")
    print("🔍 Files contain FAKE patterns for testing SecretSentry detection")
    print("⚠️  All data is obviously fake and safe for public repositories")
    print("🛡️  Using placeholder formats (xxx) to avoid GitHub secret scanning")