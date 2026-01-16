#!/usr/bin/env python3

import argparse
import json
import sys
import time
import logging
from datetime import datetime
from pathlib import Path
from scanner import Scanner
from utils import format_file_size

def main():
    # ... header print ...
    print("""
    +======================================================+
    |          SecretScanner - Git Leak Detector       |
    |                     by 0x127                     |
    |              Enhanced Version                    |
    +======================================================+
    """)
    
    start_time = time.time()

    parser = argparse.ArgumentParser(
    # ... args ...
        description='Enhanced Secret Scanner - Find hardcoded secrets in code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan /path/to/project --history --output report.json
  %(prog)s url https://github.com/user/repo.git --verbose
  %(prog)s scan . --severity high,critical --exclude test/
        """
    )
    
    parser.add_argument('mode', choices=['scan', 'url'], help='Scan local directory or clone repository')
    parser.add_argument('path', help='Directory path or repository URL')
    
    # Output options
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'sarif'], default='json', 
                       help='Output format (default: json)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    # Scanning options
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed progress')
    parser.add_argument('--history', action='store_true', help='Include git commit history')
    parser.add_argument('--depth', type=int, default=1000, help='Git history depth limit (default: 1000)')
    parser.add_argument('--threads', type=int, default=4, help='Number of scan threads (default: 4)')
    
    # Filtering options
    parser.add_argument('--severity', help='Filter by severity (comma-separated: critical,high,medium,low)')
    parser.add_argument('--exclude', help='Exclude paths (comma-separated)')
    parser.add_argument('--include', help='Include only these file types (comma-separated)')
    parser.add_argument('--max-file-size', type=int, default=5, help='Max file size in MB (default: 5)')
    
    # Advanced options
    parser.add_argument('--entropy-threshold', type=float, default=3.5, 
                       help='Minimum entropy for generic secrets (default: 3.5)')
    parser.add_argument('--context-lines', type=int, default=3, help='Context lines to show (default: 3)')
    parser.add_argument('--timeout', type=int, default=300, help='Scan timeout in seconds (default: 300)')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be scanned without executing')
    
    # Configuration
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--update-patterns', action='store_true', help='Update secret patterns from remote')

    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Validate arguments
    if args.severity:
        valid_severities = {'critical', 'high', 'medium', 'low'}
        user_severities = set(s.strip().lower() for s in args.severity.split(','))
        if not user_severities.issubset(valid_severities):
            print(f"Error: Invalid severity levels. Valid: {', '.join(valid_severities)}")
            sys.exit(1)
    
    # Load configuration if specified
    config = {}
    if args.config and Path(args.config).exists():
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            sys.exit(1)
    
    # Initialize scanner with enhanced options
    scan_tool = Scanner(
        show_progress=args.verbose,
        max_threads=args.threads,
        entropy_threshold=args.entropy_threshold,
        max_file_size=args.max_file_size * 1024 * 1024,
        context_lines=args.context_lines,
        exclude_paths=args.exclude.split(',') if args.exclude else [],
        include_extensions=args.include.split(',') if args.include else [],
        severity_filter=args.severity.split(',') if args.severity else None,
        no_color=args.no_color,
        timeout=args.timeout
    )
    
    try:
        if args.mode == 'scan':
            if args.dry_run:
                print(f"\n[DRY RUN] Would scan directory: {args.path}")
                return
            scan_tool.check_directory(args.path, check_history=args.history, history_depth=args.depth)
        elif args.mode == 'url':
            if args.dry_run:
                print(f"\n[DRY RUN] Would clone and scan repository: {args.path}")
                return
            scan_tool.clone_and_check(args.path, check_history=args.history, history_depth=args.depth)
    
        scan_tool.display_results()
    
        if args.output:
            if args.format == 'json':
                scan_tool.save_to_json(args.output)
            elif args.format == 'csv':
                scan_tool.save_to_csv(args.output)
            elif args.format == 'sarif':
                scan_tool.save_to_sarif(args.output)
    
        # Performance summary
        elapsed_time = time.time() - start_time
        print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
