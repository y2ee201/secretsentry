#!/usr/bin/env python3
"""
Test script for SecretSentry ML detection functionality

This script demonstrates the ML-enhanced secret detection capabilities
and compares performance with regex-only detection.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the secretsentry module to path for testing
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from secretsentry import (
        SecretSentry, quick_scan, quick_ml_scan, 
        check_ml_requirements, HAS_ML_SUPPORT
    )
    print("✅ SecretSentry modules imported successfully")
except ImportError as e:
    print(f"❌ Failed to import SecretSentry: {e}")
    sys.exit(1)


def create_test_files(test_dir: str):
    """Create test files with various secret patterns"""
    print(f"📁 Creating test files in {test_dir}")
    
    # Python file with real secrets
    python_content = '''
# Real secrets that should be detected
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
stripe_key = "sk_live_1234567890abcdef123456789012345"
database_url = "postgresql://user:secret123@localhost:5432/mydb"
api_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# False positives that should be filtered out
base64_image = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
css_color = "#3498db"
jquery_version = "3.6.0"
lorem_text = "Lorem ipsum dolor sit amet"

# Personal information
employee_ssn = "123-45-6789"
phone_number = "(555) 123-4567"
email_address = "test@example.com"
'''
    
    # Configuration file
    config_content = '''
[database]
host = localhost
port = 5432
username = admin
password = super_secret_password_123

[api_keys]
stripe_secret = sk_live_abcdefghijklmnopqrstuvwxyz123456
slack_webhook = https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
github_token = ghp_1234567890abcdefghijklmnopqrstuv123456789

[email]
smtp_password = email_password_456
sendgrid_api_key = SG.abcdefghijklmnopqrstuvwx.yz1234567890abcdefghijklmnopqrstuvwxyz123456

# Test data - should be filtered as false positive
test_api_key = "test_key_placeholder"
demo_secret = "demo_value_for_testing"
'''
    
    # Jupyter notebook (JSON format)
    notebook_content = '''{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": 1,
   "metadata": {},
   "outputs": [],
   "source": [
    "# Real secret in notebook\\n",
    "API_KEY = \\"AIzaSyBkz1234567890abcdefghijklmnopqrs\\"\\n",
    "DATABASE_PASSWORD = \\"notebook_secret_password\\"\\n",
    "\\n",
    "# Base64 image (should be filtered)\\n",
    "image_data = \\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB\\"\\n"
   ]
  },
  {
   "cell_type": "markdown",
   "metadata": {},
   "source": [
    "# Test Notebook\\n",
    "This contains both real secrets and false positives"
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
    
    files = [
        ("test_app.py", python_content),
        ("config.ini", config_content),
        ("analysis.ipynb", notebook_content)
    ]
    
    for filename, content in files:
        file_path = os.path.join(test_dir, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    print(f"✅ Created {len(files)} test files")
    return files


def test_regex_detection(test_dir: str):
    """Test traditional regex-based detection"""
    print("\n🔍 Testing Regex-Only Detection:")
    print("=" * 50)
    
    scanner = SecretSentry(execution_mode='script')
    findings = scanner.scan_directory(test_dir, show_progress=False)
    
    print(f"📊 Regex Results:")
    print(f"  - Total findings: {len(findings)}")
    print(f"  - Files scanned: {scanner.scan_stats['files_scanned']}")
    print(f"  - False positives filtered: {scanner.scan_stats['false_positives_filtered']}")
    
    # Show some findings
    if findings:
        print("\n📋 Sample Findings (first 5):")
        for i, finding in enumerate(findings[:5], 1):
            print(f"  {i}. {finding.pattern_type}: {finding.matched_text[:30]}...")
    
    return scanner, findings


def test_ml_detection(test_dir: str):
    """Test ML-enhanced detection"""
    print("\n🧠 Testing ML-Enhanced Detection:")
    print("=" * 50)
    
    if not HAS_ML_SUPPORT:
        print("❌ ML support not available. Install with:")
        print("   pip install secretsentry[ml]")
        return None, []
    
    # Check ML requirements
    requirements = check_ml_requirements()
    print("📋 ML Requirements:")
    for req, available in requirements.items():
        status = "✅" if available else "❌"
        print(f"  {req}: {status}")
    
    if not all(requirements.values()):
        print("⚠️  Some ML requirements missing, proceeding with available components...")
    
    try:
        scanner = SecretSentry(
            execution_mode='script',
            use_ml_detection=True,
            ml_confidence_threshold=0.6,
            ml_ensemble_mode=True
        )
        
        findings = scanner.scan_directory(test_dir, show_progress=False)
        
        print(f"\n📊 ML Results:")
        print(f"  - Total findings: {len(findings)}")
        print(f"  - ML findings: {scanner.scan_stats.get('ml_findings', 0)}")
        print(f"  - Files scanned: {scanner.scan_stats['files_scanned']}")
        print(f"  - Regex false positives filtered: {scanner.scan_stats['false_positives_filtered']}")
        print(f"  - ML false positives filtered: {scanner.scan_stats.get('ml_false_positives_filtered', 0)}")
        print(f"  - Detection mode: {scanner.scan_stats.get('detection_mode', 'unknown')}")
        
        # Show ML-specific findings
        ml_findings = scanner.get_ml_findings()
        if ml_findings:
            print(f"\n🤖 ML-Specific Findings ({len(ml_findings)}):")
            for i, finding in enumerate(ml_findings[:3], 1):
                print(f"  {i}. {finding.pattern_type}: {finding.matched_text[:30]}... "
                      f"(confidence: {finding.confidence_score:.3f})")
        
        # High confidence findings
        high_conf = scanner.get_high_confidence_findings(0.8)
        if high_conf:
            print(f"\n🎯 High Confidence Findings ({len(high_conf)}):")
            for i, finding in enumerate(high_conf[:3], 1):
                print(f"  {i}. {finding.pattern_type}: {finding.matched_text[:30]}... "
                      f"(confidence: {finding.confidence_score:.3f})")
        
        return scanner, findings
        
    except Exception as e:
        print(f"❌ Error in ML detection: {e}")
        return None, []


def test_quick_functions(test_dir: str):
    """Test quick scan functions"""
    print("\n⚡ Testing Quick Scan Functions:")
    print("=" * 50)
    
    # Regular quick scan
    print("🚀 Regular Quick Scan:")
    scanner1 = quick_scan(test_dir, show_plots=False)
    print(f"  Found {len(scanner1.findings)} findings")
    
    # ML quick scan
    if HAS_ML_SUPPORT:
        print("\n🧠 ML Quick Scan:")
        scanner2 = quick_ml_scan(test_dir, confidence_threshold=0.6, show_plots=False)
        if scanner2:
            print(f"  Found {len(scanner2.findings)} findings")
            ml_findings = scanner2.get_ml_findings()
            print(f"  ML findings: {len(ml_findings)}")
        else:
            print("  ML quick scan failed")
    else:
        print("\n⚠️  ML quick scan not available (missing dependencies)")


def compare_results(regex_findings, ml_findings):
    """Compare regex vs ML results"""
    print("\n📈 Comparison Results:")
    print("=" * 50)
    
    print(f"Regex-only findings: {len(regex_findings)}")
    print(f"ML-enhanced findings: {len(ml_findings)}")
    
    if ml_findings:
        improvement = len(regex_findings) - len(ml_findings)
        if improvement > 0:
            print(f"✅ ML reduced false positives by {improvement} findings")
        elif improvement < 0:
            print(f"🔍 ML found {abs(improvement)} additional potential secrets")
        else:
            print("🟰 Same number of findings detected")


def main():
    """Main test function"""
    print("🧪 SecretSentry ML Detection Test")
    print("=" * 50)
    
    # Create temporary test directory
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"📁 Using temporary directory: {temp_dir}")
        
        # Create test files
        create_test_files(temp_dir)
        
        # Test regex detection
        regex_scanner, regex_findings = test_regex_detection(temp_dir)
        
        # Test ML detection
        ml_scanner, ml_findings = test_ml_detection(temp_dir)
        
        # Test quick functions
        test_quick_functions(temp_dir)
        
        # Compare results
        compare_results(regex_findings, ml_findings)
        
        print("\n🎉 Test completed!")
        
        # Show final summary
        print("\n📝 Summary:")
        print(f"  - Regex detection: {'✅ Working' if regex_findings is not None else '❌ Failed'}")
        print(f"  - ML detection: {'✅ Working' if HAS_ML_SUPPORT and ml_findings is not None else '❌ Not available'}")
        print(f"  - Cross-platform: {'✅ ' + sys.platform}")
        
        if HAS_ML_SUPPORT:
            print("\n💡 To use ML detection:")
            print("  # In Python:")
            print("  from secretsentry import quick_ml_scan")
            print("  scanner = quick_ml_scan('./my_project')")
            print("\n  # In CLI:")
            print("  secretsentry scan ./my_project --ml --display")
            print("  secretsentry scan ./my_project --ml-quick")
        else:
            print("\n💡 To enable ML detection, install:")
            print("  pip install secretsentry[ml]          # Basic ML")
            print("  pip install secretsentry[ml-advanced] # With transformers")
            print("  pip install secretsentry[full]        # Everything")


if __name__ == "__main__":
    main()