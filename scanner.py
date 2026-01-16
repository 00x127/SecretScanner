import os
import re
import subprocess
import json
import threading
import signal
import platform
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from patterns import SECRET_PATTERNS, SKIP_EXTENSIONS, SKIP_DIRECTORIES
from utils import calc_entropy, check_if_binary, looks_like_test_data, extract_match_value, format_file_size

class Scanner:
    def __init__(self, show_progress=False, max_threads=4, entropy_threshold=3.5, 
                 max_file_size=5*1024*1024, context_lines=3, exclude_paths=None, 
                 include_extensions=None, severity_filter=None, no_color=False, timeout=300):
        self.results = []
        self.files_checked = 0
        self.files_ignored = 0
        self.show_progress = show_progress
        self.max_threads = max_threads
        self.entropy_threshold = entropy_threshold
        self.max_file_size = max_file_size
        self.context_lines = context_lines
        self.exclude_paths = exclude_paths or []
        self.include_extensions = include_extensions
        self.severity_filter = severity_filter
        self.no_color = no_color
        self.timeout = timeout
        self.scan_start_time = None
        self.lock = threading.Lock()
        self.is_windows = platform.system() == "Windows"
        self.logger = logging.getLogger("SecretScanner")
        
        # Setup timeout handler only on Unix-like systems
        if not self.is_windows:
            signal.signal(signal.SIGALRM, self._timeout_handler)

    def _timeout_handler(self, signum, frame):
        raise TimeoutError("Scan timeout exceeded")
    
    def _colorize(self, text, color):
        if self.no_color or self.is_windows:
            return text
        colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'reset': '\033[0m'
        }
        return f"{colors.get(color, '')}{text}{colors['reset']}"
    
    def should_check_file(self, file_path):
        try:
            if not os.path.isfile(file_path):
                return False

            path_components = Path(file_path).parts
            for skip_dir in list(SKIP_DIRECTORIES) + self.exclude_paths:
                if skip_dir in path_components:
                    with self.lock:
                        self.files_ignored += 1
                    return False

            file_ext = Path(file_path).suffix.lower()
            if self.include_extensions and file_ext not in self.include_extensions:
                with self.lock:
                    self.files_ignored += 1
                return False
            
            size = os.path.getsize(file_path)
            if size > self.max_file_size:
                with self.lock:
                    self.files_ignored += 1
                return False

            if size == 0:
                with self.lock:
                    self.files_ignored += 1
                return False

            if check_if_binary(file_path):
                with self.lock:
                    self.files_ignored += 1
                return False

            return True

        except Exception as err:
            if self.show_progress:
                self.logger.error(f"[ERROR] Checking {file_path}: {err}")
            with self.lock:
                self.files_ignored += 1
            return False

    def _scan_line(self, line_text, line_number, file_path, display_path):
        if not line_text.strip():
            return

        for pattern_name, (regex, risk_level) in SECRET_PATTERNS.items():
            try:
                for regex_match in re.finditer(regex, line_text, re.IGNORECASE):
                    matched_text = extract_match_value(regex_match)

                    if len(matched_text) < 8 or len(matched_text) > 500:
                        continue

                    if looks_like_test_data(matched_text, line_text):
                        continue

                    surrounding_text = line_text.strip()[:150]

                    result_id = f"{display_path}:{line_number}:{pattern_name}:{matched_text}"
                    
                    with self.lock:
                        if not any(r.get('_id') == result_id for r in self.results):
                            result_entry = {
                                'type': pattern_name,
                                'severity': risk_level,
                                'file': display_path,
                                'line': line_number,
                                'secret': matched_text,
                                'entropy': round(calc_entropy(matched_text), 2),
                                'context': surrounding_text,
                                '_id': result_id
                            }
                            self.results.append(result_entry)

                            if self.show_progress:
                                self.logger.info(f"[FOUND] {risk_level.upper()} - {pattern_name} in {display_path}:{line_number}")

            except Exception as err:
                if self.show_progress:
                    self.logger.error(f"[ERROR] Pattern {pattern_name}: {err}")
                continue

    def check_text_content(self, text_content, file_path, display_path):
        text_lines = text_content.split('\n')

        for line_number, line_text in enumerate(text_lines, 1):
            self._scan_line(line_text, line_number, file_path, display_path)

    def check_single_file(self, file_path, base_path=''):
        if not self.should_check_file(file_path):
            return

        rel_path = os.path.relpath(file_path, base_path) if base_path else file_path
        with self.lock:
            self.files_checked += 1

        if self.show_progress and self.files_checked % 25 == 0:
            self.logger.info(f"[*] Checked {self.files_checked} files...")

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_number, line_text in enumerate(f, 1):
                    self._scan_line(line_text, line_number, file_path, rel_path)
        except Exception as err:
            if self.show_progress:
                self.logger.error(f"[ERROR] Reading {file_path}: {err}")
            return
    
    def _check_files_parallel(self, file_list, base_path=''):
        """Check multiple files in parallel using ThreadPoolExecutor"""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.check_single_file, file_path, base_path): file_path 
                      for file_path in file_list}
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    if self.show_progress:
                        self.logger.error(f"[ERROR] in thread: {e}")

    def check_commit_history(self, repo_dir, commit_limit=1000):
        if not os.path.exists(os.path.join(repo_dir, '.git')):
            return

        self.logger.info(f"\n[*] Checking git history...")

        try:
            git_log = subprocess.run(
                ['git', 'log', '--all', '--pretty=format:%H', '--max-count=' + str(commit_limit)],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=60
            )

            commit_hashes = git_log.stdout.strip().split('\n')
            self.logger.info(f"[*] Found {len(commit_hashes)} commits")

            for idx, commit_id in enumerate(commit_hashes):
                if idx % 100 == 0 and idx > 0:
                    self.logger.info(f"[*] Progress: {idx}/{len(commit_hashes)} commits")

                commit_diff = subprocess.run(
                    ['git', 'show', '--pretty=', '--unified=0', commit_id],
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                active_file = None
                for diff_line in commit_diff.stdout.split('\n'):
                    if diff_line.startswith('+++'):
                        active_file = diff_line[6:].strip()
                        if active_file.startswith('b/'):
                            active_file = active_file[2:]
                    elif diff_line.startswith('+') and not diff_line.startswith('+++'):
                        added_content = diff_line[1:]
                        if active_file:
                            self.check_text_content(added_content, active_file, f"{active_file} (commit {commit_id[:8]})")

            self.logger.info(f"[+] Checked {len(commit_hashes)} commits")

        except subprocess.TimeoutExpired:
            self.logger.warning("[!] Git history check timed out")
        except Exception as err:
            if self.show_progress:
                self.logger.error(f"[!] Git history error: {err}")

    def check_directory(self, dir_path, include_subdirs=True, check_history=False, history_depth=1000):
        self.scan_start_time = datetime.now()
        self.logger.info(f"\n[*] Starting scan: {dir_path}")
        
        # Set timeout only on Unix-like systems
        if not self.is_windows:
            signal.alarm(self.timeout)

        if not os.path.exists(dir_path):
            self.logger.warning(f"[!] Directory not found")
            return

        # Collect all files to scan
        files_to_scan = []
        if include_subdirs:
            for root_dir, subdirs, file_list in os.walk(dir_path):
                subdirs[:] = [d for d in subdirs if d not in SKIP_DIRECTORIES]
                for file_name in file_list:
                    full_path = os.path.join(root_dir, file_name)
                    if self.should_check_file(full_path):
                        files_to_scan.append(full_path)
        else:
            for item_name in os.listdir(dir_path):
                full_path = os.path.join(dir_path, item_name)
                if os.path.isfile(full_path) and self.should_check_file(full_path):
                    files_to_scan.append(full_path)

        self.logger.info(f"[*] Found {len(files_to_scan)} files to scan")
        
        # Scan files in parallel
        if files_to_scan:
            self._check_files_parallel(files_to_scan, dir_path)

        # Disable timeout only on Unix-like systems
        if not self.is_windows:
            signal.alarm(0)

        self.logger.info(f"\n[+] Scan complete")
        self.logger.info(f"[+] Files checked: {self.files_checked}")
        self.logger.info(f"[+] Files skipped: {self.files_ignored}")

        if check_history:
            self.check_commit_history(dir_path, history_depth)

    def clone_and_check(self, repo_link, temp_location='/tmp', check_history=False, history_depth=1000):
        self.logger.info(f"\n[*] Cloning: {repo_link}")

        repo_id = urlparse(repo_link).path.split('/')[-1].replace('.git', '')
        target_dir = os.path.join(temp_location, f"secretscan_{repo_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

        try:
            clone_depth = [] if check_history else ['--depth=1']
            clone_result = subprocess.run(
                ['git', 'clone', '--quiet'] + clone_depth + [repo_link, target_dir],
                capture_output=True,
                text=True,
                timeout=180
            )

            if clone_result.returncode != 0:
                self.logger.error(f"[!] Clone failed: {clone_result.stderr}")
                return None

            self.logger.info(f"[+] Cloned to: {target_dir}")

        except subprocess.TimeoutExpired:
            self.logger.error("[!] Clone timeout")
            return None
        except Exception as err:
            self.logger.error(f"[!] Clone error: {err}")
            return None

        self.check_directory(target_dir, check_history=check_history, history_depth=history_depth)
        return target_dir

    def display_results(self):
        try:
            print("\n")
            print("=" * 80)
            print("SCAN RESULTS".center(80))
            print("=" * 80)

            # Filter results by severity if specified
            filtered_results = self.results
            if self.severity_filter:
                filtered_results = [r for r in self.results if r['severity'] in self.severity_filter]

            if not filtered_results:
                print(f"\nNo secrets detected.\n")
                return

            grouped_by_severity = defaultdict(list)
            for finding in filtered_results:
                grouped_by_severity[finding['severity']].append(finding)

            severity_levels = ['critical', 'high', 'medium', 'low']

            for level in severity_levels:
                if level not in grouped_by_severity:
                    continue

                level_results = grouped_by_severity[level]
                print(f"\n{level.upper()} ({len(level_results)} finding{'s' if len(level_results) != 1 else ''})")
                print("-" * 80)

                grouped_by_type = defaultdict(list)
                for finding in level_results:
                    grouped_by_type[finding['type']].append(finding)

                for secret_kind in sorted(grouped_by_type.keys()):
                    type_results = grouped_by_type[secret_kind]
                    print(f"\n  {secret_kind}")
                    print(f"  " + "─" * 76)

                    for position, finding in enumerate(type_results[:5], 1):
                        try:
                            print(f"  [{position}] File: {finding['file']}")
                            print(f"      Line: {finding['line']}")
                            # Truncate secret if too long to avoid encoding issues
                            secret = finding['secret'][:50] + "..." if len(finding['secret']) > 50 else finding['secret']
                            print(f"      Secret: {secret}")
                            print(f"      Entropy: {finding['entropy']}")
                            if len(finding['context']) > 100:
                                print(f"      Context: {finding['context'][:100]}...")
                            else:
                                print(f"      Context: {finding['context']}")
                            if position < len(type_results[:5]):
                                print()
                        except Exception as e:
                            print(f"      [Error displaying finding: {e}]")

                    if len(type_results) > 5:
                        print(f"\n  ... and {len(type_results) - 5} more occurrence(s)")

            print("\n" + "=" * 80)
            crit_count = len(grouped_by_severity.get('critical', []))
            high_count = len(grouped_by_severity.get('high', []))
            med_count = len(grouped_by_severity.get('medium', []))
            low_count = len(grouped_by_severity.get('low', []))

            print(f"SUMMARY: {len(filtered_results)} total secrets found".center(80))
            print(f"Critical: {crit_count}  |  High: {high_count}  |  Medium: {med_count}  |  Low: {low_count}".center(80))
            print(f"Scanned: {self.files_checked} files  |  Skipped: {self.files_ignored} files".center(80))
            
            if self.scan_start_time:
                elapsed = (datetime.now() - self.scan_start_time).total_seconds()
                print(f"Scan time: {elapsed:.2f} seconds".center(80))
            
            print("=" * 80)
            print()
        except Exception as e:
            print(f"[!] Error displaying results: {e}")
            print(f"[!] Found {len(self.results)} total secrets (check output file for details)")

    def save_to_json(self, output_path):
        filtered_results = self.results
        if self.severity_filter:
            filtered_results = [r for r in self.results if r['severity'] in self.severity_filter]
            
        report_data = {
            'scan_time': datetime.now().isoformat(),
            'files_scanned': self.files_checked,
            'files_skipped': self.files_ignored,
            'total_findings': len(filtered_results),
            'severity_filter': self.severity_filter,
            'scan_duration_seconds': (datetime.now() - self.scan_start_time).total_seconds() if self.scan_start_time else None,
            'findings': [
                {k: v for k, v in finding.items() if k != '_id'}
                for finding in filtered_results
            ]
        }

        with open(output_path, 'w') as output_file:
            json.dump(report_data, output_file, indent=2)
        print(f"\n[+] JSON report saved: {output_path}")
    
    def save_to_csv(self, output_path):
        import csv
        
        filtered_results = self.results
        if self.severity_filter:
            filtered_results = [r for r in self.results if r['severity'] in self.severity_filter]
        
        if not filtered_results:
            print(f"\n[!] No findings to export")
            return
        
        fieldnames = ['type', 'severity', 'file', 'line', 'secret', 'entropy', 'context']
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for finding in filtered_results:
                row = {field: finding.get(field, '') for field in fieldnames}
                writer.writerow(row)
        
        print(f"\n[+] CSV report saved: {output_path}")
    
    def save_to_sarif(self, output_path):
        """Save results in SARIF format for GitHub security integration"""
        filtered_results = self.results
        if self.severity_filter:
            filtered_results = [r for r in self.results if r['severity'] in self.severity_filter]
        
        if not filtered_results:
            print(f"\n[!] No findings to export")
            return
        
        sarif_report = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SecretScanner Enhanced",
                        "version": "2.0",
                        "informationUri": "https://github.com/00x127/SecretScanner"
                    }
                },
                "results": []
            }]
        }
        
        severity_levels = {
            'critical': 'error',
            'high': 'error', 
            'medium': 'warning',
            'low': 'note'
        }
        
        for finding in filtered_results:
            result = {
                "ruleId": finding['type'],
                "level": severity_levels.get(finding['severity'], 'warning'),
                "message": {
                    "text": f"Potential {finding['type']} detected with {finding['severity']} severity"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding['file']
                        },
                        "region": {
                            "startLine": finding['line'],
                            "snippet": {
                                "text": finding['context']
                            }
                        }
                    }
                }]
            }
            sarif_report["runs"][0]["results"].append(result)
        
        with open(output_path, 'w') as output_file:
            json.dump(sarif_report, output_file, indent=2)
        
        print(f"\n[+] SARIF report saved: {output_path}")
