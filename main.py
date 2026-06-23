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
        "--profile",
        choices=["safe", "aggressive"],
        default="safe",
        help="Scan intensity profile (default: safe)",
    )
    parser.add_argument(
        "--modules",
        nargs="+",
        choices=[
            "recon", "sqli", "xss", "auth", "idor",
            "crawl", "tools",
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
    parser.add_argument("--crawl-depth", type=int, default=2, help="Maximum crawl depth")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl")
    parser.add_argument(
        "--external-tools",
        action="store_true",
        help="Allow optional external tool integrations when the tools module runs",
    )
    parser.add_argument(
        "--tools",
        help="Comma-separated external tools to run (default: nmap,nikto,whatweb,wafw00f,sqlmap,zap-baseline)",
    )
    parser.add_argument("--tool-timeout", type=int, default=120, help="External tool timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests (seconds)")
    parser.add_argument(
        "--no-soft-404-filter",
        action="store_true",
        help="Disable custom 404 / soft-404 response filtering",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")
    parser.add_argument("--report-format", choices=["json", "html", "txt", "all"], default="all")
    return parser.parse_args()


def apply_profile_defaults(args):
    if args.profile != "aggressive":
        return
    args.threads = max(args.threads, 20)
    args.timeout = max(args.timeout, 15)
    args.crawl_depth = max(args.crawl_depth, 3)
    args.max_pages = max(args.max_pages, 150)
    args.tool_timeout = max(args.tool_timeout, 240)


def main():
    args = parse_args()
    apply_profile_defaults(args)

    if not args.no_banner:
        print_banner()

    if not args.target.startswith(("http://", "https://")):
        print("[!] Target must start with http:// or https://")
        sys.exit(1)

    settings = Settings(
        target=args.target,
        modules=args.modules,
        profile=args.profile,
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        cookies=args.cookies,
        headers=args.headers,
        auth=args.auth,
        wordlist=args.wordlist,
        crawl_depth=args.crawl_depth,
        max_pages=args.max_pages,
        external_tools=args.external_tools,
        tools=args.tools,
        tool_timeout=args.tool_timeout,
        delay=args.delay,
        filter_soft_404=not args.no_soft_404_filter,
        verbose=args.verbose,
        output_dir=args.output,
        report_format=args.report_format,
    )

    log = Logger(verbose=args.verbose)
    log.info(f"Target   : {args.target}")
    log.info(f"Modules  : {', '.join(args.modules)}")
    log.info(f"Profile  : {args.profile}")
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
