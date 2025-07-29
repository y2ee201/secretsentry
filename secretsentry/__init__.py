"""
SecretSentry - Advanced sensitive data scanner with Jupyter notebook support

SecretSentry is the first sensitive data scanner built specifically for modern
data science and web development workflows. It intelligently detects API keys,
PII, credentials, and other sensitive information while filtering out false
positives from Jupyter notebooks, HTML files, and other common sources.

Key Features:
- Jupyter notebook specialization with smart false positive filtering
- 50+ built-in detection patterns for various types of sensitive data
- Interactive analysis tools with pandas integration
- Context-aware sanitization with intelligent gibberish replacement
- Multi-environment support: CLI, Jupyter, and Python scripts
- Rich visualizations and reporting capabilities

Example usage:
    >>> from secretsentry import SecretSentry, quick_scan
    >>> scanner = quick_scan("./my_project")
    >>> findings = scanner.findings
    >>> scanner.display_findings()
"""

__version__ = "1.0.0"
__author__ = "SecretSentry Team"
__license__ = "MIT"
__copyright__ = "Copyright 2024 SecretSentry"

# Import main classes and functions for easy access
from .scanner import (
    SensitiveDataScanner as SecretSentry,
    Finding,
    quick_scan,
)

# Define what gets imported with "from secretsentry import *"
__all__ = [
    "SecretSentry",
    "SensitiveDataScanner", 
    "Finding",
    "quick_scan", 
    "__version__"
]

# Alias for backward compatibility and cleaner imports
SensitiveDataScanner = SecretSentry

# Package metadata
__package_name__ = "secretsentry"
__description__ = "Advanced sensitive data scanner with Jupyter notebook support and intelligent false positive filtering"
__url__ = "https://github.com/yourusername/secretsentry"
__maintainer__ = "SecretSentry Team"
__maintainer_email__ = "your.email@example.com"