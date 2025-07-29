# SecretSentry 🛡️

> **The first sensitive data scanner built for modern data science and web development workflows**

[![PyPI version](https://badge.fury.io/py/secretsentry.svg)](https://badge.fury.io/py/secretsentry)
[![Python Support](https://img.shields.io/pypi/pyversions/secretsentry.svg)](https://pypi.org/project/secretsentry/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

SecretSentry is an advanced sensitive data scanner that goes beyond traditional secret detection. Built specifically for **Jupyter notebooks**, **web development**, and **data science workflows**, it intelligently filters false positives while detecting API keys, PII, credentials, and other sensitive information.

## 🎯 **Why SecretSentry?**

### **Built for Modern Workflows**
- 🔬 **Jupyter Notebook Specialist**: First scanner designed for `.ipynb` files
- 🧠 **Smart False Positive Filtering**: Ignores base64 images, cell IDs, and CSS colors
- 🌐 **Multi-Environment**: CLI, Jupyter notebooks, and Python scripts
- 🎛️ **Interactive Analysis**: Built-in widgets for exploring findings

### **Comprehensive Detection**
- 🔑 **50+ Built-in Patterns**: API keys, tokens, secrets, credentials
- 👤 **PII Detection**: SSNs, credit cards, phone numbers, emails
- 💰 **Financial Data**: Salary information, bank accounts, routing numbers
- 🌍 **Geographic Data**: Coordinates, IP addresses, postal codes
- 🏥 **Sensitive Categories**: Ethnic data, religious information, medical records

### **Advanced Features**
- 🛡️ **Smart Sanitization**: Context-aware gibberish replacement
- 📊 **Rich Visualizations**: Charts and statistics (with matplotlib/seaborn)
- 📈 **Pandas Integration**: Export to DataFrames for analysis
- 🔄 **CI/CD Ready**: Perfect for automation and pipelines

## 🚀 **Quick Start**

### **Installation**

```bash
# Basic installation
pip install secretsentry

# Full installation with all features
pip install secretsentry[full]

# For Jupyter notebooks only
pip install secretsentry[jupyter]
```

### **Basic Usage**

```python
from secretsentry import SecretSentry, quick_scan

# Quick scan with automatic results
scanner = quick_scan("./my_project")

# Manual scanning with custom options
scanner = SecretSentry()
findings = scanner.scan_directory("./my_project")
scanner.display_findings()

# Sanitize files (creates backups automatically)
stats = scanner.sanitize_files(dry_run=True)  # Preview changes
stats = scanner.sanitize_files()  # Actually sanitize
```

### **Command Line**

```bash
# Scan and display results
secretsentry scan ./my_project --display

# Scan specific file types
secretsentry scan ./my_project --extensions .py .js .ipynb --display

# Export findings
secretsentry scan ./my_project --export findings.json

# Sanitize files (with backup)
secretsentry scan ./my_project --sanitize --dry-run
secretsentry scan ./my_project --sanitize

# List all detection patterns
secretsentry list-patterns
```

## 🎓 **Jupyter Notebook Integration**

SecretSentry shines in Jupyter environments with **zero false positives** from notebook metadata:

```python
# In Jupyter notebook
from secretsentry import SecretSentry, create_sample_files

# Create test data
create_sample_files("./test_data")

# Quick scan with visualizations
scanner = quick_scan("./test_data", show_plots=True)

# Interactive exploration
scanner.create_interactive_viewer()

# Data analysis with pandas
df = scanner.to_dataframe()
summary = df.groupby('pattern_type').size()
```

## 📊 **What Makes It Special**

### **Intelligent False Positive Filtering**

**Traditional scanners** flag this as secrets:
```
❌ aws_secret_key: iVBORw0KGgoAAAANSUhEUgAABKYAAAMW...  # Just a PNG image!
❌ api_key: "cell_type": "code"  # Notebook metadata!
❌ secret: #3498db  # CSS color!
```

**SecretSentry** ignores these and only reports **real issues**:
```
✅ aws_secret_key: AKIAIOSFODNN7EXAMPLE
✅ stripe_key: sk_live_1234567890abcdef123456789
✅ database_url: postgresql://user:password@localhost/db
```

### **Smart Sanitization**

SecretSentry doesn't just find secrets—it **fixes them safely**:

```python
# Before sanitization
API_KEY = "sk_live_1234567890abcdef"
employee_ssn = "123-45-6789"
coordinates = "40.7128, -74.0060"

# After sanitization (context-aware gibberish)
API_KEY = "sk_live_xK8mP9nQ4vL7wR2Z"
employee_ssn = "456-78-9123"  
coordinates = "38.8951, -77.0364"
```

## 🔧 **Advanced Usage**

### **Custom Patterns**

```python
# Add organization-specific patterns
custom_patterns = {
    'employee_id': r'EMP-\d{6}',
    'project_code': r'PROJ-[A-Z]{3}-\d{4}',
    'internal_api': r'internal_key_[a-zA-Z0-9]{32}'
}

scanner = SecretSentry(custom_patterns=custom_patterns)
```

### **CI/CD Integration**

```python
#!/usr/bin/env python3
# security_check.py
import sys
from secretsentry import SecretSentry

def security_gate():
    scanner = SecretSentry()
    findings = scanner.scan_directory(".", show_progress=False)
    
    if findings:
        print(f"❌ SECURITY CHECK FAILED: {len(findings)} secrets found")
        scanner.display_findings(max_display=10)
        return 1
    else:
        print("✅ SECURITY CHECK PASSED: No secrets detected")
        return 0

if __name__ == "__main__":
    sys.exit(security_gate())
```

### **Batch Processing**

```python
# Scan multiple projects
from secretsentry import SecretSentry
import os

projects = ["./frontend", "./backend", "./data-science"]
all_results = {}

for project in projects:
    if os.path.exists(project):
        scanner = SecretSentry()
        findings = scanner.scan_directory(project)
        all_results[project] = len(findings)
        
        # Export individual reports
        scanner.export_findings(f"{project.replace('./', '')}_security_report.json")

print("Security Summary:", all_results)
```

## 📈 **Detection Categories**

<details>
<summary><b>🔑 API Keys & Secrets (20+ patterns)</b></summary>

- AWS Access/Secret Keys
- GitHub Tokens (classic & fine-grained)  
- Google API Keys
- Stripe Keys (live & test)
- Slack Tokens & Webhooks
- SendGrid API Keys
- Twilio Keys
- Mailgun Keys
- Azure Storage Keys
- Heroku API Keys
- Generic API patterns

</details>

<details>
<summary><b>💳 Financial Data (8+ patterns)</b></summary>

- Credit Cards (Visa, MasterCard, AmEx, Discover, JCB, Diners)
- Bank Account Numbers
- Routing Numbers  
- IBAN & SWIFT Codes
- Salary Information

</details>

<details>
<summary><b>👤 Personal Information (10+ patterns)</b></summary>

- Social Security Numbers
- Phone Numbers (US & International)
- Email Addresses
- Passport Numbers
- Driver's License Numbers
- Medical Record Numbers

</details>

<details>
<summary><b>🌍 Geographic Data (5+ patterns)</b></summary>

- GPS Coordinates
- IP Addresses (IPv4 & IPv6)
- MAC Addresses  
- ZIP/Postal Codes

</details>

<details>
<summary><b>🏥 Sensitive Personal Data (5+ patterns)</b></summary>

- Ethnic/Racial Categories
- Religious Affiliations  
- Medical Information
- Disability Status

</details>

<details>
<summary><b>🔐 Cryptographic Material (5+ patterns)</b></summary>

- Private Keys (RSA, SSH)
- Public Keys & Certificates
- JWT Tokens
- OAuth Tokens  

</details>

## 🎛️ **Configuration**

### **Environment Variables**
```bash
# Disable progress bars
export SECRETSENTRY_NO_PROGRESS=1

# Custom config file
export SECRETSENTRY_CONFIG=/path/to/config.json
```

### **Configuration File**
```json
{
    "excluded_patterns": ["test_", "example_", "demo_"],
    "excluded_files": ["*.test.js", "test_*.py"],
    "excluded_dirs": ["tests", "examples", "docs"],
    "custom_patterns": {
        "company_id": "COMP-\\d{8}"
    },
    "sanitization": {
        "create_backups": true,
        "backup_suffix": ".backup"
    }
}
```

## 🤝 **Contributing**

We welcome contributions! Here's how to get started:

```bash
# Clone the repository
git clone https://github.com/yourusername/secretsentry.git
cd secretsentry

# Install development dependencies
pip install -e ".[full]"
pip install pytest black flake8

# Run tests
pytest tests/

# Format code
black secretsentry/
flake8 secretsentry/
```

## 📝 **License**

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- Inspired by [detect-secrets](https://github.com/Yelp/detect-secrets) and [truffleHog](https://github.com/dxa4481/truffleHog)
- Built for the data science and security communities
- Special thanks to all contributors and the open source community

## 📞 **Support**

- 📖 **Documentation**: [Full docs](https://github.com/yourusername/secretsentry#readme)
- 🐛 **Issues**: [Report bugs](https://github.com/yourusername/secretsentry/issues)
- 💬 **Discussions**: [Community forum](https://github.com/yourusername/secretsentry/discussions)
- 📧 **Contact**: your.email@example.com

---

**SecretSentry** - *Standing guard over your sensitive data* 🛡️
