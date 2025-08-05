# Changelog

All notable changes to SecretSentry will be documented in this file.

## [2.0.0] - 2024-12-XX

### 🚀 Major Features Added

#### **🤖 AI-Powered Detection**
- **Machine Learning Models**: Added scikit-learn and transformer-based secret detection
- **Context-Aware Analysis**: ML models understand code context, not just pattern matching
- **Confidence Scoring**: Every ML detection includes 0.0-1.0 confidence scores
- **Ensemble Detection**: Combines regex + ML for maximum accuracy
- **Feature Extraction**: Advanced text analysis (entropy, keywords, patterns)

#### **🔧 New CLI Options**
- `--ml`: Enable ML-enhanced detection
- `--ml-only`: Use pure ML detection (no regex)
- `--ml-quick`: Quick ML scan with optimal settings
- `--ml-confidence X.X`: Set custom confidence threshold
- `--check-ml`: Check ML requirements and dependencies

#### **📦 New Installation Options**
- `pip install secretsentry[ml]`: Basic ML capabilities (scikit-learn)
- `pip install secretsentry[ml-advanced]`: Advanced ML (transformers)
- `pip install secretsentry[full]`: Everything included

#### **🐍 New Python API**
- `quick_ml_scan()`: Quick ML-enhanced scanning
- `SecretSentry(use_ml_detection=True)`: ML-enabled scanner
- `scanner.get_ml_findings()`: Access ML-specific results
- `scanner.get_high_confidence_findings()`: Filter by confidence
- `check_ml_requirements()`: Verify ML dependencies

### ✨ Enhancements

#### **📊 Enhanced Data Analysis**
- **ML Metadata**: DataFrames include detection method and confidence scores
- **Advanced Filtering**: Filter findings by confidence threshold
- **Performance Stats**: Detailed ML performance metrics

#### **🎛️ Configuration Options**
- Environment variables for ML settings
- Configuration file support for ML parameters
- Model caching for faster subsequent runs

#### **🖥️ Cross-Platform Support**
- Full compatibility with macOS, Windows, and Linux
- Platform-specific model caching
- Graceful fallbacks when ML unavailable

### 🛠️ Technical Improvements

#### **🧠 ML Architecture**
- **Multiple Models**: Logistic Regression, Isolation Forest, optional Transformers
- **Local Processing**: All ML inference happens on user's machine
- **Model Persistence**: Trained models cached for performance
- **Synthetic Training**: Automatic model training on first run

#### **📈 Performance**
- **Smart Caching**: ML models cached after first training
- **Lazy Loading**: ML components loaded only when needed
- **Memory Efficient**: Optimized for different system configurations

### 🔧 Breaking Changes

- **Version Bump**: Major version increment (1.x → 2.x) for ML features
- **Python Requirement**: Recommended Python 3.8+ for ML features (3.7+ still supported for regex-only)

### 📋 Dependencies

#### **New Optional Dependencies**
- `scikit-learn>=1.0.0`: Core ML functionality
- `transformers>=4.20.0`: Advanced transformer models
- `torch>=1.11.0`: Deep learning backend
- `joblib>=1.1.0`: Model persistence

#### **Updated Core Dependencies**
- `numpy>=1.19.0`: Now required for ML features

### 🐛 Bug Fixes

- Fixed feature dimensionality issues in ML training
- Improved error handling for missing ML dependencies
- Enhanced cross-platform compatibility

### 📚 Documentation

- **Comprehensive README**: Updated with ML examples and performance guides
- **Installation Guide**: Clear ML installation options
- **Performance Documentation**: System requirements and benchmarks
- **Configuration Guide**: ML-specific settings and environment variables

### 🔄 Backward Compatibility

- **100% Compatible**: All existing regex-only functionality unchanged
- **Incremental Adoption**: Users can enable ML features gradually
- **Graceful Degradation**: Falls back to regex when ML unavailable

---

## [1.0.0] - 2024-XX-XX

### Initial Release
- Regex-based secret detection
- Jupyter notebook specialization  
- Smart false positive filtering
- CLI and Python API
- Sanitization capabilities
- Cross-platform support