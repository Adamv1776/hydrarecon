#!/usr/bin/env python3
"""
word_scrubber_cli.py - ULTRA ADVANCED Word Scrubber CLI

Enterprise-grade CLI for the WordScrubber module with:
- Interactive mode with real-time preview
- Batch processing from file lists
- Config file support (YAML/JSON)
- Progress bars and color output
- Scheduled/watch mode
- REST API server mode
- Email/webhook notifications
- Cloud storage integration
- Multiple export formats
- Undo/rollback capabilities
"""

import argparse
import json
import sys
import os
import time
import signal
import threading
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

# Try to import optional dependencies
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.prompt import Prompt, Confirm
    from rich.live import Live
    from rich.tree import Tree
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

try:
    import schedule
    SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False

try:
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    EMAIL_AVAILABLE = True
except ImportError:
    EMAIL_AVAILABLE = False

try:
    import requests as http_requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from core.word_scrubber import (
    WordScrubber, ScrubMode, PIIType, ContentType, BypassMode,
    scrub_url, scrub_text, scrub_file, detect_pii
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rich console for fancy output
console = Console() if RICH_AVAILABLE else None


class ColorOutput:
    """Fallback color output when Rich is not available"""
    COLORS = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
        'reset': '\033[0m',
        'bold': '\033[1m',
    }
    
    @classmethod
    def print(cls, text: str, color: str = 'white', bold: bool = False):
        prefix = cls.COLORS.get('bold', '') if bold else ''
        prefix += cls.COLORS.get(color, '')
        suffix = cls.COLORS['reset']
        print(f"{prefix}{text}{suffix}")
    
    @classmethod
    def success(cls, text: str):
        cls.print(f"✓ {text}", 'green', True)
    
    @classmethod
    def error(cls, text: str):
        cls.print(f"✗ {text}", 'red', True)
    
    @classmethod
    def warning(cls, text: str):
        cls.print(f"⚠ {text}", 'yellow')
    
    @classmethod
    def info(cls, text: str):
        cls.print(f"ℹ {text}", 'blue')


def output_success(text: str):
    if RICH_AVAILABLE:
        console.print(f"[bold green]✓[/bold green] {text}")
    else:
        ColorOutput.success(text)


def output_error(text: str):
    if RICH_AVAILABLE:
        console.print(f"[bold red]✗[/bold red] {text}")
    else:
        ColorOutput.error(text)


def output_warning(text: str):
    if RICH_AVAILABLE:
        console.print(f"[bold yellow]⚠[/bold yellow] {text}")
    else:
        ColorOutput.warning(text)


def output_info(text: str):
    if RICH_AVAILABLE:
        console.print(f"[bold blue]ℹ[/bold blue] {text}")
    else:
        ColorOutput.info(text)


def load_config(config_path: str) -> Dict:
    """Load configuration from YAML or JSON file"""
    with open(config_path, 'r') as f:
        if config_path.endswith(('.yml', '.yaml')):
            if YAML_AVAILABLE:
                return yaml.safe_load(f)
            else:
                output_error("YAML support not available. Install PyYAML: pip install pyyaml")
                sys.exit(1)
        else:
            return json.load(f)


def load_targets_from_file(filepath: str) -> List[str]:
    """Load target words/patterns from file"""
    targets = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                # Check if it's a JSON pattern definition
                if line.startswith('{'):
                    try:
                        targets.append(json.loads(line))
                    except json.JSONDecodeError:
                        targets.append(line)
                else:
                    targets.append(line)
    return targets


def load_urls_from_file(filepath: str) -> List[str]:
    """Load URLs from file"""
    urls = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                urls.append(line)
    return urls


def display_results_table(results: Dict, stats: Dict):
    """Display results in a formatted table"""
    if RICH_AVAILABLE:
        table = Table(title="Scrubbing Results", show_header=True, header_style="bold magenta")
        table.add_column("URL", style="cyan", no_wrap=True, max_width=50)
        table.add_column("Matches", justify="right", style="green")
        table.add_column("Content Type", style="yellow")
        table.add_column("Time (s)", justify="right", style="blue")
        
        for url, result in results.items():
            table.add_row(
                url[:50] + "..." if len(url) > 50 else url,
                str(len(result.matches)),
                str(result.content_type.name),
                f"{result.processing_time:.2f}"
            )
        
        console.print(table)
        
        # Stats panel
        stats_text = f"""
[bold]Total URLs:[/bold] {stats.get('total_urls', 0)}
[bold]Processed:[/bold] {stats.get('processed_urls', 0)}
[bold]Failed:[/bold] {stats.get('failed_urls', 0)}
[bold]Total Matches:[/bold] {stats.get('total_matches', 0)}
[bold]Processing Time:[/bold] {stats.get('processing_time_seconds', 0):.2f}s
[bold]URLs/Second:[/bold] {stats.get('urls_per_second', 0):.2f}
        """
        console.print(Panel(stats_text, title="Statistics", border_style="green"))
    else:
        print("\n" + "="*60)
        print("SCRUBBING RESULTS")
        print("="*60)
        for url, result in results.items():
            print(f"\nURL: {url}")
            print(f"  Matches: {len(result.matches)}")
            print(f"  Content Type: {result.content_type.name}")
            print(f"  Time: {result.processing_time:.2f}s")
        
        print("\n" + "-"*60)
        print("STATISTICS")
        print("-"*60)
        print(f"Total URLs: {stats.get('total_urls', 0)}")
        print(f"Processed: {stats.get('processed_urls', 0)}")
        print(f"Failed: {stats.get('failed_urls', 0)}")
        print(f"Total Matches: {stats.get('total_matches', 0)}")
        print(f"Processing Time: {stats.get('processing_time_seconds', 0):.2f}s")


def display_matches_detail(matches: List, limit: int = 20):
    """Display detailed match information"""
    if not matches:
        output_info("No matches found")
        return
    
    if RICH_AVAILABLE:
        table = Table(title=f"Match Details (showing {min(limit, len(matches))} of {len(matches)})", 
                     show_header=True, header_style="bold magenta")
        table.add_column("URL", style="cyan", max_width=30)
        table.add_column("Pattern", style="yellow", max_width=20)
        table.add_column("Matched", style="red", max_width=20)
        table.add_column("Replacement", style="green", max_width=20)
        table.add_column("PII Type", style="blue")
        table.add_column("Confidence", justify="right")
        
        for match in matches[:limit]:
            pii_type = match.pii_type.name if match.pii_type else "-"
            table.add_row(
                match.url[:30] + "..." if len(match.url) > 30 else match.url,
                match.pattern[:20] + "..." if len(match.pattern) > 20 else match.pattern,
                match.matched_text[:20] + "..." if len(match.matched_text) > 20 else match.matched_text,
                match.replacement[:20] + "..." if len(match.replacement) > 20 else match.replacement,
                pii_type,
                f"{match.confidence:.2f}"
            )
        
        console.print(table)
    else:
        print(f"\nMATCH DETAILS (showing {min(limit, len(matches))} of {len(matches)})")
        print("-"*80)
        for match in matches[:limit]:
            print(f"URL: {match.url}")
            print(f"  Pattern: {match.pattern}")
            print(f"  Matched: {match.matched_text}")
            print(f"  Replacement: {match.replacement}")
            if match.pii_type:
                print(f"  PII Type: {match.pii_type.name}")
            print(f"  Confidence: {match.confidence:.2f}")
            print()


def interactive_mode(args):
    """Run interactive scrubbing session"""
    if RICH_AVAILABLE:
        console.print(Panel.fit(
            "[bold cyan]Word Scrubber Interactive Mode[/bold cyan]\n"
            "Enter commands or type 'help' for available commands",
            border_style="cyan"
        ))
    else:
        print("\n" + "="*50)
        print("Word Scrubber Interactive Mode")
        print("Enter commands or type 'help' for available commands")
        print("="*50 + "\n")
    
    scrubber = None
    results = {}
    
    commands = {
        'help': 'Show available commands',
        'init <url>': 'Initialize scrubber with base URL',
        'add <word>': 'Add target word/pattern',
        'targets': 'List current targets',
        'pii <on/off>': 'Toggle PII detection',
        'mode <mode>': 'Set scrub mode (redact/hash/mask/tokenize/remove)',
        'scrub': 'Start scrubbing',
        'preview <text>': 'Preview scrubbing on text',
        'stats': 'Show statistics',
        'matches [n]': 'Show match details',
        'save <dir>': 'Save results to directory',
        'export <format>': 'Export report (json/csv/xml)',
        'undo': 'Undo last scrub (if tokenized)',
        'quit': 'Exit interactive mode'
    }
    
    targets = []
    base_url = args.url if hasattr(args, 'url') and args.url else None
    detect_pii_enabled = True
    scrub_mode = ScrubMode.REDACT
    
    while True:
        try:
            if RICH_AVAILABLE:
                cmd = Prompt.ask("[bold green]scrubber[/bold green]")
            else:
                cmd = input("scrubber> ").strip()
            
            if not cmd:
                continue
            
            parts = cmd.split(maxsplit=1)
            command = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else None
            
            if command == 'help':
                if RICH_AVAILABLE:
                    help_table = Table(title="Available Commands", show_header=True)
                    help_table.add_column("Command", style="cyan")
                    help_table.add_column("Description", style="white")
                    for cmd_name, desc in commands.items():
                        help_table.add_row(cmd_name, desc)
                    console.print(help_table)
                else:
                    print("\nAvailable Commands:")
                    for cmd_name, desc in commands.items():
                        print(f"  {cmd_name:20} - {desc}")
            
            elif command == 'init':
                if arg:
                    base_url = arg
                    output_success(f"Initialized with URL: {base_url}")
                else:
                    output_error("Please provide a URL")
            
            elif command == 'add':
                if arg:
                    targets.append(arg)
                    output_success(f"Added target: {arg}")
                else:
                    output_error("Please provide a target word/pattern")
            
            elif command == 'targets':
                if targets:
                    output_info(f"Current targets: {targets}")
                else:
                    output_warning("No targets defined")
            
            elif command == 'pii':
                if arg and arg.lower() in ['on', 'off', 'true', 'false']:
                    detect_pii_enabled = arg.lower() in ['on', 'true']
                    output_success(f"PII detection: {'enabled' if detect_pii_enabled else 'disabled'}")
                else:
                    output_info(f"PII detection is currently: {'enabled' if detect_pii_enabled else 'disabled'}")
            
            elif command == 'mode':
                if arg:
                    try:
                        scrub_mode = ScrubMode[arg.upper()]
                        output_success(f"Scrub mode set to: {scrub_mode.name}")
                    except KeyError:
                        output_error(f"Invalid mode. Available: {[m.name for m in ScrubMode]}")
                else:
                    output_info(f"Current mode: {scrub_mode.name}")
            
            elif command == 'preview':
                if arg:
                    if not targets:
                        output_warning("No targets defined. Use 'add <word>' first.")
                        continue
                    
                    temp_scrubber = WordScrubber(
                        base_url="",
                        targets=targets,
                        detect_pii=detect_pii_enabled,
                        scrub_mode=scrub_mode
                    )
                    scrubbed, matches = temp_scrubber.scrub_text(arg)
                    
                    if RICH_AVAILABLE:
                        console.print(Panel(f"[red]{arg}[/red]\n↓\n[green]{scrubbed}[/green]",
                                          title="Preview", border_style="yellow"))
                        if matches:
                            console.print(f"[yellow]Found {len(matches)} matches[/yellow]")
                    else:
                        print(f"\nOriginal: {arg}")
                        print(f"Scrubbed: {scrubbed}")
                        print(f"Matches: {len(matches)}")
                    
                    temp_scrubber.close()
                else:
                    output_error("Please provide text to preview")
            
            elif command == 'scrub':
                if not base_url:
                    output_error("No URL set. Use 'init <url>' first.")
                    continue
                if not targets and not detect_pii_enabled:
                    output_error("No targets defined and PII detection is off.")
                    continue
                
                output_info(f"Starting scrub of {base_url}...")
                
                scrubber = WordScrubber(
                    base_url=base_url,
                    targets=targets,
                    detect_pii=detect_pii_enabled,
                    scrub_mode=scrub_mode,
                    verbose=True
                )
                
                if RICH_AVAILABLE:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TimeElapsedColumn(),
                        console=console
                    ) as progress:
                        task = progress.add_task("Scrubbing...", total=None)
                        results = scrubber.scrub_site()
                        progress.update(task, completed=True)
                else:
                    results = scrubber.scrub_site()
                
                stats = scrubber.get_stats()
                output_success(f"Scrubbing complete! Found {stats['total_matches']} matches in {stats['processed_urls']} URLs")
            
            elif command == 'stats':
                if scrubber:
                    stats = scrubber.get_stats()
                    display_results_table(results, stats)
                else:
                    output_warning("No scrubbing session active")
            
            elif command == 'matches':
                if scrubber and scrubber.scrub_report:
                    limit = int(arg) if arg and arg.isdigit() else 20
                    display_matches_detail(scrubber.scrub_report, limit)
                else:
                    output_warning("No matches to display")
            
            elif command == 'save':
                if scrubber and results:
                    out_dir = arg or 'scrubbed_output'
                    scrubber.save_results(out_dir)
                    output_success(f"Results saved to {out_dir}")
                else:
                    output_warning("No results to save")
            
            elif command == 'export':
                if scrubber and results:
                    fmt = arg or 'json'
                    out_dir = 'scrubbed_output'
                    scrubber.save_results(out_dir, formats=[fmt])
                    output_success(f"Exported {fmt} report to {out_dir}")
                else:
                    output_warning("No results to export")
            
            elif command == 'undo':
                if scrubber and scrubber.token_vault:
                    output_info("Detokenization available for tokenized content")
                else:
                    output_warning("Undo not available (tokenization not enabled)")
            
            elif command in ['quit', 'exit', 'q']:
                if scrubber:
                    scrubber.close()
                output_info("Goodbye!")
                break
            
            else:
                output_error(f"Unknown command: {command}. Type 'help' for available commands.")
        
        except KeyboardInterrupt:
            print()
            output_info("Use 'quit' to exit")
        except Exception as e:
            output_error(f"Error: {e}")


def run_api_server(args):
    """Run REST API server mode"""
    if not FLASK_AVAILABLE:
        output_error("Flask not available. Install with: pip install flask flask-cors")
        sys.exit(1)
    
    app = Flask(__name__)
    CORS(app)
    
    # Store active scrubbers
    scrubbers = {}
    
    @app.route('/api/health', methods=['GET'])
    def health():
        return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})
    
    @app.route('/api/scrub/text', methods=['POST'])
    def scrub_text_api():
        data = request.json
        text = data.get('text', '')
        targets = data.get('targets', [])
        options = data.get('options', {})
        
        scrubber = WordScrubber(
            base_url="",
            targets=targets,
            detect_pii=options.get('detect_pii', True),
            scrub_mode=ScrubMode[options.get('scrub_mode', 'REDACT').upper()],
            **{k: v for k, v in options.items() if k not in ['detect_pii', 'scrub_mode']}
        )
        
        scrubbed, matches = scrubber.scrub_text(text)
        scrubber.close()
        
        return jsonify({
            'original': text,
            'scrubbed': scrubbed,
            'matches': [
                {
                    'pattern': m.pattern,
                    'matched_text': m.matched_text,
                    'replacement': m.replacement,
                    'pii_type': m.pii_type.name if m.pii_type else None,
                    'confidence': m.confidence
                } for m in matches
            ]
        })
    
    @app.route('/api/scrub/url', methods=['POST'])
    def scrub_url_api():
        data = request.json
        url = data.get('url', '')
        targets = data.get('targets', [])
        options = data.get('options', {})
        
        scrubber = WordScrubber(
            base_url=url,
            targets=targets,
            detect_pii=options.get('detect_pii', True),
            scrub_mode=ScrubMode[options.get('scrub_mode', 'REDACT').upper()],
            max_depth=options.get('max_depth', 1),
            **{k: v for k, v in options.items() if k not in ['detect_pii', 'scrub_mode', 'max_depth']}
        )
        
        results = scrubber.scrub_site()
        stats = scrubber.get_stats()
        
        response = {
            'stats': stats,
            'results': {
                url: {
                    'scrubbed_content': result.scrubbed_content[:1000] + '...' if len(result.scrubbed_content) > 1000 else result.scrubbed_content,
                    'matches_count': len(result.matches),
                    'content_type': result.content_type.name
                } for url, result in results.items()
            }
        }
        
        scrubber.close()
        return jsonify(response)
    
    @app.route('/api/detect/pii', methods=['POST'])
    def detect_pii_api():
        data = request.json
        text = data.get('text', '')
        
        detections = detect_pii(text)
        
        return jsonify({
            'text': text,
            'detections': [
                {
                    'type': d[0].name,
                    'value': d[1],
                    'start': d[2],
                    'end': d[3],
                    'confidence': d[4]
                } for d in detections
            ]
        })
    
    host = args.api_host or '0.0.0.0'
    port = args.api_port or 5000
    
    output_info(f"Starting API server on {host}:{port}")
    app.run(host=host, port=port, debug=args.verbose)


def run_watch_mode(args):
    """Run file watch mode"""
    if not WATCHDOG_AVAILABLE:
        output_error("Watchdog not available. Install with: pip install watchdog")
        sys.exit(1)
    
    class ScrubHandler(FileSystemEventHandler):
        def __init__(self, scrubber, patterns):
            self.scrubber = scrubber
            self.patterns = patterns or ['*.html', '*.txt', '*.json']
        
        def on_modified(self, event):
            if event.is_directory:
                return
            
            path = event.src_path
            if any(path.endswith(p.replace('*', '')) for p in self.patterns):
                output_info(f"File modified: {path}")
                result = self.scrubber.scrub_file(path)
                if result and result.matches:
                    output_warning(f"Found {len(result.matches)} matches in {path}")
    
    watch_dir = args.watch_dir or '.'
    targets = args.words or []
    
    if args.targets_file:
        targets.extend(load_targets_from_file(args.targets_file))
    
    scrubber = WordScrubber(
        base_url="",
        targets=targets,
        detect_pii=args.detect_pii,
        dry_run=True  # Don't modify files, just report
    )
    
    handler = ScrubHandler(scrubber, args.watch_patterns if hasattr(args, 'watch_patterns') else None)
    observer = Observer()
    observer.schedule(handler, watch_dir, recursive=True)
    observer.start()
    
    output_info(f"Watching {watch_dir} for changes... (Ctrl+C to stop)")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()
    scrubber.close()


def run_batch_mode(args):
    """Run batch processing mode"""
    urls = []
    
    if args.urls_file:
        urls = load_urls_from_file(args.urls_file)
    elif args.url:
        urls = [args.url]
    
    if not urls:
        output_error("No URLs provided")
        sys.exit(1)
    
    targets = args.words or []
    if args.targets_file:
        targets.extend(load_targets_from_file(args.targets_file))
    
    all_results = {}
    total_matches = 0
    
    output_info(f"Processing {len(urls)} URLs...")
    
    for i, url in enumerate(urls, 1):
        if RICH_AVAILABLE:
            console.print(f"[{i}/{len(urls)}] Processing: [cyan]{url}[/cyan]")
        else:
            print(f"[{i}/{len(urls)}] Processing: {url}")
        
        try:
            scrubber = WordScrubber(
                base_url=url,
                targets=targets,
                detect_pii=args.detect_pii if hasattr(args, 'detect_pii') else True,
                scrub_mode=ScrubMode[args.scrub_mode.upper()] if hasattr(args, 'scrub_mode') and args.scrub_mode else ScrubMode.REDACT,
                max_depth=args.max_depth if hasattr(args, 'max_depth') else 1,
                verbose=args.verbose if hasattr(args, 'verbose') else False
            )
            
            results = scrubber.scrub_site()
            stats = scrubber.get_stats()
            
            all_results[url] = {
                'results': results,
                'stats': stats
            }
            total_matches += stats['total_matches']
            
            if args.out_dir:
                url_dir = os.path.join(args.out_dir, url.replace('://', '_').replace('/', '_')[:50])
                scrubber.save_results(url_dir)
            
            scrubber.close()
            
        except Exception as e:
            output_error(f"Error processing {url}: {e}")
    
    output_success(f"Batch complete! Processed {len(urls)} URLs, found {total_matches} total matches")
    
    # Save summary
    if args.out_dir:
        summary = {
            'processed_urls': len(urls),
            'total_matches': total_matches,
            'timestamp': datetime.now().isoformat(),
            'urls': list(all_results.keys())
        }
        with open(os.path.join(args.out_dir, 'batch_summary.json'), 'w') as f:
            json.dump(summary, f, indent=2)


def send_notification(args, stats: Dict, matches_count: int):
    """Send notification via email or webhook"""
    message = f"""
Word Scrubber Results
=====================
URL: {args.url}
Total Matches: {matches_count}
Processed URLs: {stats.get('processed_urls', 0)}
Processing Time: {stats.get('processing_time_seconds', 0):.2f}s
Timestamp: {datetime.now().isoformat()}
    """
    
    # Send email
    if hasattr(args, 'notify_email') and args.notify_email and EMAIL_AVAILABLE:
        try:
            smtp_server = os.environ.get('SMTP_SERVER', 'localhost')
            smtp_port = int(os.environ.get('SMTP_PORT', 587))
            smtp_user = os.environ.get('SMTP_USER', '')
            smtp_pass = os.environ.get('SMTP_PASS', '')
            
            msg = MIMEMultipart()
            msg['From'] = smtp_user or 'wordscrubber@localhost'
            msg['To'] = args.notify_email
            msg['Subject'] = f'Word Scrubber Results - {matches_count} matches found'
            msg.attach(MIMEText(message, 'plain'))
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if smtp_user and smtp_pass:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            
            output_success(f"Email notification sent to {args.notify_email}")
        except Exception as e:
            output_error(f"Failed to send email: {e}")
    
    # Send webhook
    if hasattr(args, 'webhook_url') and args.webhook_url and REQUESTS_AVAILABLE:
        try:
            payload = {
                'url': args.url,
                'matches_count': matches_count,
                'stats': stats,
                'timestamp': datetime.now().isoformat()
            }
            resp = http_requests.post(args.webhook_url, json=payload, timeout=10)
            if resp.ok:
                output_success(f"Webhook notification sent")
            else:
                output_error(f"Webhook returned {resp.status_code}")
        except Exception as e:
            output_error(f"Failed to send webhook: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="ULTRA ADVANCED Word Scrubber CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scrubbing
  %(prog)s https://example.com -w password secret api_key
  
  # With PII detection
  %(prog)s https://example.com --detect-pii --pii-types EMAIL PHONE SSN
  
  # Using config file
  %(prog)s --config scrubber.yaml
  
  # Batch mode
  %(prog)s --batch --urls-file urls.txt -w secret --out-dir results
  
  # Interactive mode
  %(prog)s --interactive
  
  # API server mode
  %(prog)s --api --api-port 8080
  
  # Watch mode
  %(prog)s --watch --watch-dir ./content -w password
        """
    )
    
    # Mode selection
    mode_group = parser.add_argument_group('Mode Selection')
    mode_group.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    mode_group.add_argument("--api", action="store_true", help="Run as REST API server")
    mode_group.add_argument("--batch", action="store_true", help="Batch processing mode")
    mode_group.add_argument("--watch", action="store_true", help="File watch mode")
    
    # Basic options
    basic_group = parser.add_argument_group('Basic Options')
    basic_group.add_argument("url", nargs="?", help="Base URL to scrub (or first positional argument)")
    basic_group.add_argument("-w", "--words", nargs="*", help="Words/phrases/regex patterns to scrub")
    basic_group.add_argument("-r", "--replacement", default="[REDACTED]", help="Replacement text or mode")
    basic_group.add_argument("-d", "--max-depth", type=int, default=2, help="Max crawl depth")
    basic_group.add_argument("--out-dir", default="scrubbed_site", help="Output directory")
    
    # Target options
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument("--targets-file", help="File containing target words (one per line)")
    target_group.add_argument("--word-boundary", action="store_true", help="Match whole words only")
    target_group.add_argument("--partial-match", action="store_true", help="Allow partial matches")
    target_group.add_argument("--case-sensitive", action="store_true", help="Case-sensitive matching")
    
    # PII detection
    pii_group = parser.add_argument_group('PII Detection')
    pii_group.add_argument("--detect-pii", action="store_true", default=True, help="Enable PII detection")
    pii_group.add_argument("--no-detect-pii", action="store_false", dest="detect_pii", help="Disable PII detection")
    pii_group.add_argument("--pii-types", nargs="*", choices=[t.name for t in PIIType], 
                          help="PII types to detect")
    pii_group.add_argument("--min-confidence", type=float, default=0.7, help="Min confidence for PII detection")
    pii_group.add_argument("--use-ml", action="store_true", help="Use ML models for enhanced detection")
    
    # Scrub mode
    mode_opts = parser.add_argument_group('Scrub Mode Options')
    mode_opts.add_argument("--scrub-mode", choices=[m.name.lower() for m in ScrubMode], default="redact",
                          help="Scrubbing mode")
    mode_opts.add_argument("--enable-tokenization", action="store_true", help="Enable reversible tokenization")
    mode_opts.add_argument("--encryption-key", help="Key for encrypted tokenization")
    
    # Crawling options
    crawl_group = parser.add_argument_group('Crawling Options')
    crawl_group.add_argument("--same-domain", action="store_true", default=True, help="Restrict to same domain")
    crawl_group.add_argument("--no-same-domain", action="store_false", dest="same_domain")
    crawl_group.add_argument("--include-tags", nargs="*", help="Only scrub these HTML tags")
    crawl_group.add_argument("--exclude-tags", nargs="*", help="Skip these HTML tags")
    crawl_group.add_argument("--ignore-urls", nargs="*", help="URL patterns to skip")
    crawl_group.add_argument("--include-urls", nargs="*", help="URL patterns to include")
    crawl_group.add_argument("--parallelism", type=int, default=8, help="Number of parallel threads")
    crawl_group.add_argument("--rate-limit", type=float, default=0, help="Seconds between requests")
    crawl_group.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    crawl_group.add_argument("--retries", type=int, default=3, help="Retries per request")
    
    # Authentication
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument("--login-url", help="Login URL for session auth")
    auth_group.add_argument("--login-data", help="POST data for login (JSON)")
    auth_group.add_argument("--login-headers", help="Headers for login (JSON)")
    auth_group.add_argument("--cookies", help="Cookies (JSON)")
    auth_group.add_argument("--headers", help="Custom headers (JSON)")
    auth_group.add_argument("--user-agent", help="Custom User-Agent string")
    
    # Browser/JavaScript
    browser_group = parser.add_argument_group('Browser Options')
    browser_group.add_argument("--use-browser", action="store_true", help="Use headless browser for JS rendering")
    browser_group.add_argument("--browser-engine", choices=['playwright', 'selenium'], default='playwright',
                              help="Browser engine to use")
    
    # Proxy options
    proxy_group = parser.add_argument_group('Proxy Options')
    proxy_group.add_argument("--proxies", nargs="*", help="Proxy URLs for rotation")
    proxy_group.add_argument("--use-tor", action="store_true", help="Use TOR network")
    
    # PROTOCOL BYPASS OPTIONS - Override ANY website protection
    bypass_group = parser.add_argument_group('Protocol Bypass Options (Override Website Protections)')
    bypass_group.add_argument("--enable-bypass", action="store_true", default=True,
                             help="Enable protocol bypass engine (default: enabled)")
    bypass_group.add_argument("--no-bypass", action="store_false", dest="enable_bypass",
                             help="Disable protocol bypass")
    bypass_group.add_argument("--bypass-mode", choices=[m.name.lower() for m in BypassMode], default="aggressive",
                             help="Bypass mode: standard, stealth, cloudflare, akamai, imperva, datadome, "
                                  "perimeterx, aggressive, nuclear, undetectable, residential, mobile, api")
    bypass_group.add_argument("--captcha-solver", choices=['2captcha', 'anticaptcha', 'capsolver'],
                             help="CAPTCHA solving service to use")
    bypass_group.add_argument("--captcha-api-key", help="API key for CAPTCHA solver")
    bypass_group.add_argument("--rotate-user-agents", action="store_true", default=True,
                             help="Rotate user agents (default: enabled)")
    bypass_group.add_argument("--impersonate-browser", choices=['chrome_win', 'chrome_mac', 'chrome_linux', 
                             'firefox_win', 'firefox_mac', 'safari_mac', 'edge_win'],
                             default='chrome_win', help="Browser fingerprint to impersonate")
    bypass_group.add_argument("--max-bypass-attempts", type=int, default=5,
                             help="Maximum bypass attempts per URL")
    bypass_group.add_argument("--bypass-cloudflare", action="store_true", default=True,
                             help="Enable Cloudflare bypass")
    bypass_group.add_argument("--bypass-akamai", action="store_true", default=True,
                             help="Enable Akamai Bot Manager bypass")
    bypass_group.add_argument("--bypass-imperva", action="store_true", default=True,
                             help="Enable Imperva/Incapsula bypass")
    bypass_group.add_argument("--force-browser-on-block", action="store_true", default=True,
                             help="Use real browser if request is blocked")
    bypass_group.add_argument("--stealth-mode", action="store_true", default=True,
                             help="Enable all stealth features")
    bypass_group.add_argument("--randomize-timing", action="store_true", default=True,
                             help="Add random delays between requests")
    bypass_group.add_argument("--min-request-delay", type=float, default=0.5,
                             help="Minimum delay between requests (seconds)")
    bypass_group.add_argument("--max-request-delay", type=float, default=3.0,
                             help="Maximum delay between requests (seconds)")
    
    # Content processing
    content_group = parser.add_argument_group('Content Processing')
    content_group.add_argument("--process-pdfs", action="store_true", default=True, help="Process PDF files")
    content_group.add_argument("--process-images", action="store_true", help="Process images (OCR)")
    content_group.add_argument("--process-documents", action="store_true", default=True, help="Process DOCX files")
    content_group.add_argument("--scrub-metadata", action="store_true", default=True, help="Scrub metadata/attributes")
    
    # Export options
    export_group = parser.add_argument_group('Export Options')
    export_group.add_argument("--export-format", nargs="*", choices=["json", "csv", "xml", "diff", "html"],
                             default=["json", "html"], help="Export formats")
    export_group.add_argument("--enable-audit", action="store_true", default=True, help="Enable audit trail")
    
    # Notification options
    notify_group = parser.add_argument_group('Notification Options')
    notify_group.add_argument("--notify-email", help="Email address for notifications")
    notify_group.add_argument("--webhook-url", help="Webhook URL for notifications")
    
    # API server options
    api_group = parser.add_argument_group('API Server Options')
    api_group.add_argument("--api-host", default="0.0.0.0", help="API server host")
    api_group.add_argument("--api-port", type=int, default=5000, help="API server port")
    
    # Watch mode options
    watch_group = parser.add_argument_group('Watch Mode Options')
    watch_group.add_argument("--watch-dir", help="Directory to watch")
    watch_group.add_argument("--watch-patterns", nargs="*", help="File patterns to watch")
    
    # Batch mode options
    batch_group = parser.add_argument_group('Batch Mode Options')
    batch_group.add_argument("--urls-file", help="File containing URLs to process")
    
    # Config and misc
    misc_group = parser.add_argument_group('Miscellaneous')
    misc_group.add_argument("--config", "-c", help="Config file (YAML or JSON)")
    misc_group.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    misc_group.add_argument("--dry-run", action="store_true", help="Preview without making changes")
    misc_group.add_argument("--report", action="store_true", default=True, help="Generate report")
    misc_group.add_argument("--version", action="version", version="Word Scrubber CLI v2.0.0")
    
    args = parser.parse_args()
    
    # Load config file if specified
    if args.config:
        config = load_config(args.config)
        # Override args with config values
        for key, value in config.items():
            if not getattr(args, key, None):
                setattr(args, key, value)
    
    # Run appropriate mode
    if args.interactive:
        interactive_mode(args)
    elif args.api:
        run_api_server(args)
    elif args.watch:
        run_watch_mode(args)
    elif args.batch:
        run_batch_mode(args)
    else:
        # Standard scrubbing mode
        if not args.url:
            parser.print_help()
            sys.exit(1)
        
        targets = args.words or []
        if hasattr(args, 'targets_file') and args.targets_file:
            targets.extend(load_targets_from_file(args.targets_file))
        
        if not targets and not args.detect_pii:
            output_error("No targets specified and PII detection is disabled")
            sys.exit(1)
        
        # Build login config
        login = None
        if args.login_url:
            login = {"login_url": args.login_url}
            if args.login_data:
                login["data"] = json.loads(args.login_data)
            if args.login_headers:
                login["headers"] = json.loads(args.login_headers)
        
        # Parse optional JSON args
        cookies = json.loads(args.cookies) if args.cookies else None
        custom_headers = json.loads(args.headers) if args.headers else None
        pii_types = [PIIType[t] for t in args.pii_types] if args.pii_types else None
        
        output_info(f"Starting scrub of {args.url}")
        
        # Show bypass mode if enabled
        if hasattr(args, 'enable_bypass') and args.enable_bypass:
            bypass_mode = args.bypass_mode.upper() if hasattr(args, 'bypass_mode') else 'AGGRESSIVE'
            output_info(f"Protocol Bypass Engine: ENABLED ({bypass_mode} mode)")
            if hasattr(args, 'captcha_solver') and args.captcha_solver:
                output_info(f"CAPTCHA Solver: {args.captcha_solver}")
        
        # Create scrubber with all options including BYPASS capabilities
        scrubber = WordScrubber(
            base_url=args.url,
            targets=targets,
            replacement=args.replacement,
            max_depth=args.max_depth,
            same_domain=args.same_domain,
            word_boundary=args.word_boundary,
            partial_match=args.partial_match,
            report=args.report,
            login=login,
            rate_limit=args.rate_limit,
            retries=args.retries,
            include_tags=args.include_tags,
            exclude_tags=args.exclude_tags,
            ignore_urls=args.ignore_urls,
            include_urls=args.include_urls,
            parallelism=args.parallelism,
            verbose=args.verbose,
            # Advanced options
            scrub_mode=ScrubMode[args.scrub_mode.upper()],
            detect_pii=args.detect_pii,
            pii_types=pii_types,
            use_browser=args.use_browser,
            browser_engine=args.browser_engine,
            use_ml=args.use_ml if hasattr(args, 'use_ml') else False,
            enable_audit=args.enable_audit,
            enable_tokenization=args.enable_tokenization if hasattr(args, 'enable_tokenization') else False,
            encryption_key=args.encryption_key if hasattr(args, 'encryption_key') else None,
            proxies=args.proxies,
            use_tor=args.use_tor if hasattr(args, 'use_tor') else False,
            user_agent=args.user_agent,
            timeout=args.timeout,
            custom_headers=custom_headers,
            cookies=cookies,
            process_pdfs=args.process_pdfs,
            process_images=args.process_images if hasattr(args, 'process_images') else False,
            process_documents=args.process_documents if hasattr(args, 'process_documents') else True,
            scrub_metadata=args.scrub_metadata if hasattr(args, 'scrub_metadata') else True,
            dry_run=args.dry_run,
            min_confidence=args.min_confidence if hasattr(args, 'min_confidence') else 0.7,
            case_sensitive=args.case_sensitive if hasattr(args, 'case_sensitive') else False,
            # PROTOCOL BYPASS OPTIONS - Defeat any website protection
            bypass_mode=BypassMode[args.bypass_mode.upper()] if hasattr(args, 'bypass_mode') and args.bypass_mode else BypassMode.AGGRESSIVE,
            enable_bypass=args.enable_bypass if hasattr(args, 'enable_bypass') else True,
            captcha_solver=args.captcha_solver if hasattr(args, 'captcha_solver') else None,
            captcha_api_key=args.captcha_api_key if hasattr(args, 'captcha_api_key') else None,
            rotate_user_agents=args.rotate_user_agents if hasattr(args, 'rotate_user_agents') else True,
            impersonate_browser=args.impersonate_browser if hasattr(args, 'impersonate_browser') else 'chrome_win',
            max_bypass_attempts=args.max_bypass_attempts if hasattr(args, 'max_bypass_attempts') else 5,
            bypass_cloudflare=args.bypass_cloudflare if hasattr(args, 'bypass_cloudflare') else True,
            bypass_akamai=args.bypass_akamai if hasattr(args, 'bypass_akamai') else True,
            bypass_imperva=args.bypass_imperva if hasattr(args, 'bypass_imperva') else True,
            force_browser_on_block=args.force_browser_on_block if hasattr(args, 'force_browser_on_block') else True,
            stealth_mode=args.stealth_mode if hasattr(args, 'stealth_mode') else True,
            randomize_timing=args.randomize_timing if hasattr(args, 'randomize_timing') else True,
            min_request_delay=args.min_request_delay if hasattr(args, 'min_request_delay') else 0.5,
            max_request_delay=args.max_request_delay if hasattr(args, 'max_request_delay') else 3.0,
        )
        
        # Run scrubbing with progress indicator
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Scrubbing website...", total=None)
                results = scrubber.scrub_site()
                progress.update(task, completed=True)
        else:
            print("Scrubbing website...")
            results = scrubber.scrub_site()
        
        # Get stats and display results
        stats = scrubber.get_stats()
        display_results_table(results, stats)
        
        if args.verbose and scrubber.scrub_report:
            display_matches_detail(scrubber.scrub_report)
        
        # Save results
        scrubber.save_results(args.out_dir, formats=args.export_format)
        output_success(f"Results saved to {args.out_dir}")
        
        # Send notifications if configured
        if args.notify_email or args.webhook_url:
            send_notification(args, stats, stats['total_matches'])
        
        # Verify audit chain if enabled
        if args.enable_audit:
            valid, errors = scrubber.verify_audit_chain()
            if valid:
                output_success("Audit chain integrity verified")
            else:
                output_error(f"Audit chain errors: {errors}")
        
        scrubber.close()
        output_success("Scrubbing complete!")


if __name__ == "__main__":
    main()
