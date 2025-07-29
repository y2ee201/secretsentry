#!/usr/bin/env python3
"""Debug what's missing from the scanner"""

from secretsentry import SecretSentry
import tempfile
import os

def debug_scanner_state():
    scanner = SecretSentry()
    
    # Check if set_findings method exists
    if hasattr(scanner, 'set_findings'):
        print("✅ set_findings method exists")
    else:
        print("❌ set_findings method is MISSING!")
        
    # Test with a simple file
    test_content = 'API_KEY = "sk_live_1234567890abcdef"'
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_content)
        temp_file = f.name
    
    try:
        # Test scan_file
        findings = scanner.scan_file(temp_file)
        print(f"📊 scan_file returned: {len(findings)} findings")
        
        # Check internal state
        print(f"📊 scanner.findings has: {len(scanner.findings)} findings")
        
        if findings:
            print(f"   First finding: {findings[0].pattern_type} = '{findings[0].matched_text}'")
            
            # Try to set findings if method exists
            if hasattr(scanner, 'set_findings'):
                scanner.set_findings(findings)
                print(f"📊 After set_findings: scanner.findings has {len(scanner.findings)} findings")
            
            # Test sanitization
            stats = scanner.sanitize_files(dry_run=True)
            print(f"📊 Dry run stats: {stats}")
            
    finally:
        os.unlink(temp_file)

if __name__ == '__main__':
    debug_scanner_state()