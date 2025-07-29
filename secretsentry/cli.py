#!/usr/bin/env python3
"""
Command-line interface for SecretSentry

This module provides the CLI interface for SecretSentry, allowing users to
scan directories and files for sensitive data from the command line.
"""

import argparse
import sys
import os
import json
from typing import Optional, List



def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        prog="secretsentry",
        description='SecretSentry - Advanced sensitive data scanner with Jupyter notebook support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan ./my_project --display
  %(prog)s scan ./my_project --sanitize --dry-run
  %(prog)s scan ./my_project --export findings.json
  %(prog)s scan ./my_project --extensions .py .js .ipynb --exclude-dirs build dist
  %(prog)s create-samples ./test_data
  %(prog)s list-patterns
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan files for sensitive data')
    scan_parser.add_argument('path', help='File or directory path to scan')
    scan_parser.add_argument('--display', action='store_true', help='Display findings')
    scan_parser.add_argument('--sanitize', action='store_true', help='Sanitize sensitive data')
    scan_parser.add_argument('--dry-run', action='store_true', help='Show what would be changed')
    scan_parser.add_argument('--no-backup', action='store_true', help='Skip backup creation')
    scan_parser.add_argument('--export', help='Export findings to file')
    scan_parser.add_argument('--format', choices=['json', 'csv'], help='Export format')
    scan_parser.add_argument('--extensions', nargs='+', help='File extensions to scan')
    scan_parser.add_argument('--exclude-dirs', nargs='+', help='Directories to exclude')
    scan_parser.add_argument('--max-display', type=int, default=50, help='Maximum findings to display')
    scan_parser.add_argument('--custom-patterns', help='JSON file with custom patterns')
    scan_parser.add_argument('--quiet', action='store_true', help='Minimal output')
    scan_parser.add_argument('--quick', action='store_true', help='Use quick_scan function')
    
    # List patterns command  
    list_parser = subparsers.add_parser('list-patterns', help='List available detection patterns')
    list_parser.add_argument('--category', help='Filter patterns by category')
    list_parser.add_argument('--search', help='Search patterns by name')
    list_parser.add_argument('--quiet', action='store_true', help='Show only pattern names')
    
    # Create samples command
    samples_parser = subparsers.add_parser('create-samples', help='Create sample files for testing')
    samples_parser.add_argument('directory', nargs='?', default='./test_sensitive_data',
                               help='Directory to create sample files in')
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version information')
    
    args = parser.parse_args()
    
    if args.command == 'version':
        from . import __version__, __description__
        print(f"SecretSentry {__version__}")
        print(__description__)
        return 0
    
    if args.command == 'create-samples':
        return 0
    
    if args.command == 'list-patterns':
        scanner = SensitiveDataScanner(execution_mode='cli')
        patterns = scanner.patterns
        
        if args.search:
            patterns = {k: v for k, v in patterns.items() if args.search.lower() in k.lower()}
        
        if args.category:
            # Simple category filtering based on pattern names
            category_keywords = {
                'api': ['api', 'key', 'token', 'secret'],
                'credit': ['credit', 'card'],
                'personal': ['ssn', 'phone', 'email'],
                'financial': ['salary', 'bank', 'routing'],
                'geo': ['coordinates', 'ip', 'zip'],
                'crypto': ['private', 'ssh', 'jwt', 'oauth']
            }
            
            if args.category.lower() in category_keywords:
                keywords = category_keywords[args.category.lower()]
                patterns = {k: v for k, v in patterns.items() 
                          if any(keyword in k.lower() for keyword in keywords)}
        
        print(f"Available detection patterns ({len(patterns)} total):")
        print("=" * 50)
        
        for i, (pattern_name, pattern) in enumerate(sorted(patterns.items()), 1):
            print(f"{i:2d}. {pattern_name}")
            if not getattr(args, 'quiet', False):
                # Show truncated regex for reference
                regex_preview = pattern[:80] + "..." if len(pattern) > 80 else pattern
                print(f"    Regex: {regex_preview}")
                print()
        
        return 0
    
    if args.command != 'scan':
        parser.print_help()
        return 1
    
    # Load custom patterns if provided
    custom_patterns = {}
    if args.custom_patterns and os.path.exists(args.custom_patterns):
        try:
            with open(args.custom_patterns, 'r') as f:
                custom_patterns = json.load(f)
        except Exception as e:
            print(f"Error loading custom patterns: {e}")
            return 1
    
    # Initialize scanner
    if args.quick:
        # Use quick_scan function
        scanner = quick_scan(
            args.path,
            file_extensions=args.extensions,
            custom_patterns=custom_patterns if custom_patterns else None,
            show_plots=False  # CLI doesn't support plots
        )
        findings = scanner.findings
    else:
        # Manual scanning
        scanner = SensitiveDataScanner(custom_patterns=custom_patterns, execution_mode='cli')
        
        # Scan files
        try:
            if os.path.isfile(args.path):
                findings = scanner.scan_file(args.path, show_progress=not args.quiet)
            else:
                findings = scanner.scan_directory(
                    args.path, 
                    file_extensions=args.extensions,
                    exclude_dirs=args.exclude_dirs,
                    show_progress=not args.quiet
                )
        except KeyboardInterrupt:
            print("\n🛑 Scan interrupted by user")
            return 1
        except Exception as e:
            print(f"❌ Error during scan: {e}")
            return 1
    
    if not args.quiet:
        print(f"\n🔍 Scan complete! Found {len(findings)} potential issues.")
        if hasattr(scanner, 'scan_stats') and 'false_positives_filtered' in scanner.scan_stats:
            print(f"🛡️  Filtered out {scanner.scan_stats['false_positives_filtered']} false positives.")
    
    # Display findings
    if args.display or not (args.sanitize or args.export):
        scanner.display_findings(max_display=args.max_display)
    
    # Export findings
    if args.export:
        export_format = args.format or 'auto'
        scanner.export_findings(args.export, export_format)
    
    # Sanitize files
    if args.sanitize:
        stats = scanner.sanitize_files(
            backup=not args.no_backup,
            dry_run=args.dry_run
        )
        if not args.quiet:
            action = "Would process" if args.dry_run else "Processed"
            print(f"📊 {action} {stats.get('files_processed', 0)} files, "
                  f"{'would sanitize' if args.dry_run else 'sanitized'} {stats.get('instances_sanitized', 0)} instances")
    
    # Return appropriate exit code
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())