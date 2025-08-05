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

__version__ = "2.0.0"
__author__ = "SecretSentry Team"
__license__ = "MIT"
__copyright__ = "Copyright 2024 SecretSentry"

# Import main classes and functions for easy access
from .scanner import (
    SensitiveDataScanner as SecretSentry,
    Finding,
    quick_scan,
    quick_ml_scan,
)

# Import ML components with fallback
try:
    from .ml_detector import (
        MLSecretDetector,
        MLFinding,
        check_ml_requirements,
        get_system_info
    )
    HAS_ML_SUPPORT = True
except ImportError:
    MLSecretDetector = None
    MLFinding = None
    check_ml_requirements = None
    get_system_info = None
    HAS_ML_SUPPORT = False

# Define what gets imported with "from secretsentry import *"
__all__ = [
    "SecretSentry",
    "SensitiveDataScanner", 
    "Finding",
    "quick_scan",
    "quick_ml_scan",
    "__version__",
    "HAS_ML_SUPPORT"
]

# Add ML components to __all__ if available
if HAS_ML_SUPPORT:
    __all__.extend([
        "MLSecretDetector",
        "MLFinding", 
        "check_ml_requirements",
        "get_system_info"
    ])

# Alias for backward compatibility and cleaner imports
SensitiveDataScanner = SecretSentry

# Package metadata
__package_name__ = "secretsentry"
__description__ = "Advanced sensitive data scanner with Jupyter notebook support and intelligent false positive filtering"
__url__ = "https://github.com/yourusername/secretsentry"
__maintainer__ = "SecretSentry Team"
__maintainer_email__ = "your.email@example.com"