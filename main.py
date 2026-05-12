#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║            VULXOR - Authorized Use Only                      ║
║  Use exclusively on systems you own or have written          ║
║  authorization to test. Unauthorized use is illegal.         ║
╚══════════════════════════════════════════════════════════════╝
"""

import argparse
import sys
import os
import urllib3
from datetime import datetime

from config.settings import Settings
from core.engine import Engine
from core.logger import Logger
from utils.banner import print_banner
from reports.generator import ReportGenerator

# just to avoid console flooding
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Vulxor - Web Application Security Testing Framework",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument(
        "--modules",
        nargs="+",
        choices=[
            "recon", "sqli", "xss", "auth", "idor",
            "upload", "lfi", "ssrf", "xxe", "ssti",
            "nosql", "cors", "jwt", "waf", "csrf",
            "desync", "race", "ratelimit", "websocket",
            "graphql", "2fa", "captcha", "all"
        ],
        default=["all"],
        help="Modules to run (default: all)",
    )
    parser.add_argument("--output", default="reports", help="Output directory for reports")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--cookies", help="Session cookies (format: name=value; name2=value2)")
    parser.add_argument("--headers", help="Custom headers (format: Header:Value,Header2:Value2)")
    parser.add_argument("--auth", help="Basic auth (format: user:pass)")
    parser.add_argument("--wordlist", help="Custom wordlist for directory brute-forcing")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests (seconds)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")
    parser.add_argument("--report-format", choices=["json", "html", "txt", "all"], default="all")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.no_banner:
        print_banner()

    if not args.target.startswith(("http://", "https://")):
        print("[!] Target must start with http:// or https://")
        sys.exit(1)

    settings = Settings(
        target=args.target,
        modules=args.modules,
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        cookies=args.cookies,
        headers=args.headers,
        auth=args.auth,
        wordlist=args.wordlist,
        delay=args.delay,
        verbose=args.verbose,
        output_dir=args.output,
        report_format=args.report_format,
    )

    log = Logger(verbose=args.verbose)
    log.info(f"Target   : {args.target}")
    log.info(f"Modules  : {', '.join(args.modules)}")
    log.info(f"Threads  : {args.threads}")
    log.info(f"Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.separator()

    engine = Engine(settings, log)
    results = engine.run()

    os.makedirs(args.output, exist_ok=True)
    reporter = ReportGenerator(results, settings)
    reporter.generate(args.report_format)

    log.separator()
    log.success(f"Scan complete. Findings: {sum(len(v) for v in results.findings.values())}")
    log.info(f"Report saved to: {args.output}/")


if __name__ == "__main__":
    main()
