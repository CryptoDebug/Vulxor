# Vulxor

Vulxor is a Python-based web application security testing toolkit for authorised assessments. It runs a set of focused checks against a target URL, collects findings, and exports reports in JSON, TXT, and HTML formats.

> Warning: use Vulxor only on systems you own or have explicit written permission to test. Unauthorised scanning or exploitation is illegal.

## Highlights

- Modular scan engine with selectable checks.
- Shared HTTP session support for cookies, headers, proxy, basic auth, timeout, and delay.
- Reconnaissance and vulnerability-oriented modules for common web security issues.
- Scoped crawler with form/link discovery and wordlist-based path discovery.
- Optional wrappers for installed external tools such as Nmap, Nikto, WhatWeb, WAFW00F, SQLMap, and ZAP baseline.
- Report generation in machine-readable and human-readable formats.
- Simple module API for extending the toolkit.

## Modules

| Module | Purpose |
| --- | --- |
| `recon` | Basic reconnaissance and information gathering |
| `sqli` | SQL injection checks |
| `xss` | Reflected and DOM XSS checks |
| `auth` | Authentication bypass and default credential checks |
| `idor` | Insecure direct object reference checks |
| `crawl` | Scoped crawling, form discovery, and wordlist path discovery |
| `tools` | Optional external tool integrations, disabled unless `--external-tools` is set |
| `upload` | Unrestricted file upload checks |
| `lfi` | Local and remote file inclusion checks |
| `ssrf` | Server-side request forgery checks |
| `xxe` | XML external entity checks |
| `ssti` | Server-side template injection checks |
| `nosql` | NoSQL injection checks |
| `cors` | CORS misconfiguration checks |
| `csrf` | Missing CSRF protection checks |
| `jwt` | JWT misconfiguration checks |
| `waf` | WAF detection checks |
| `ratelimit` | Rate-limit weakness checks |
| `desync` | HTTP request smuggling checks |
| `race` | Race condition checks |
| `websocket` | WebSocket security checks |
| `graphql` | GraphQL introspection and injection checks |
| `2fa` | Two-factor authentication bypass checks |
| `captcha` | CAPTCHA-related weakness checks |

## Project Structure

```text
vulxor/
|-- main.py                 # CLI entry point
|-- requirements.txt        # Python dependencies
|-- config/
|   `-- settings.py         # Runtime settings dataclass
|-- core/
|   |-- engine.py           # Module orchestration
|   |-- logger.py           # Console logging helpers
|   `-- results.py          # Finding and scan result models
|-- modules/
|   |-- base.py             # Base module class
|   |-- recon.py            # Reconnaissance module
|   |-- sqli.py             # SQL injection module
|   |-- xss.py              # XSS module
|   `-- ...                 # Additional security modules
|-- reports/
|   `-- generator.py        # JSON, TXT, and HTML report generation
`-- utils/
    `-- banner.py           # CLI banner
```

## Requirements

- Python 3.10 or newer
- Network access to the authorised target
- Optional: an intercepting proxy such as Burp Suite or OWASP ZAP
- Optional external tools on `PATH`: `nmap`, `nikto`, `whatweb`, `wafw00f`, `sqlmap`, or `zap-baseline.py`

## Installation

```bash
git clone https://github.com/CryptoDebug/Vulxor.git
cd Vulxor
python -m venv .venv
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

On macOS/Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run all modules:

```bash
python main.py https://target.example.com
```

Run selected modules:

```bash
python main.py https://target.example.com --modules recon sqli xss jwt
```

Use the aggressive profile for deeper, slower non-destructive checks:

```bash
python main.py https://target.example.com --profile aggressive
```

Send traffic through a proxy:

```bash
python main.py https://target.example.com --proxy http://127.0.0.1:8080
```

Use cookies and custom headers:

```bash
python main.py https://target.example.com \
  --cookies "session=abc123; role=user" \
  --headers "X-API-Key:secret,Accept:application/json"
```

Generate only one report format:

```bash
python main.py https://target.example.com --report-format html
```

Map pages and discover paths with a custom wordlist:

```bash
python main.py https://target.example.com --modules crawl --wordlist wordlists/common.txt --crawl-depth 2 --max-pages 100
```

Run optional external integrations:

```bash
python main.py https://target.example.com --modules tools --external-tools --tools nmap,nikto,whatweb
```

Display the built-in help:

```bash
python main.py --help
```

## CLI Options

| Option | Description |
| --- | --- |
| `-h`, `--help` | Show the built-in CLI help and exit |
| `target` | Target URL, including `http://` or `https://` |
| `--profile` | Scan intensity: `safe` by default, or `aggressive` for deeper checks |
| `--modules` | Modules to run, or `all` for every module |
| `--output` | Output directory for generated reports |
| `--threads` | Number of worker threads exposed in settings |
| `--timeout` | Request timeout in seconds |
| `--proxy` | HTTP/HTTPS proxy URL |
| `--cookies` | Cookies in `name=value; name2=value2` format |
| `--headers` | Headers in `Header:Value,Header2:Value2` format |
| `--auth` | Basic auth credentials in `user:pass` format |
| `--wordlist` | Custom wordlist path for modules that support it |
| `--crawl-depth` | Maximum in-scope crawl depth |
| `--max-pages` | Maximum number of pages to crawl |
| `--external-tools` | Permit the `tools` module to execute installed external commands |
| `--tools` | Comma-separated external tool list |
| `--tool-timeout` | Timeout for each external tool command |
| `--delay` | Delay between requests in seconds |
| `--verbose`, `-v` | Enable verbose output |
| `--no-banner` | Hide the startup banner |
| `--report-format` | `json`, `txt`, `html`, or `all` |

## Reports

Reports are written to the `reports/` directory by default. Generated report files are intentionally ignored by Git so scan output does not get committed accidentally. Reports include findings, a non-sensitive scan configuration summary, and metadata such as crawled pages, forms, discovered paths, and external tool execution status.

| Format | Use case |
| --- | --- |
| JSON | Machine-readable output for automation and later processing |
| TXT | Plain-text summary for quick review |
| HTML | Browser-friendly report for sharing findings internally |

## Extending Vulxor

1. Create a new file in `modules/`, for example `modules/mycheck.py`.
2. Inherit from `BaseModule`.
3. Set `NAME` and `DESCRIPTION`.
4. Implement `run(self)`.
5. Register the module in `MODULE_MAP` inside `core/engine.py`.
6. Add the module name to the CLI `choices` list in `main.py`.

Example:

```python
from modules.base import BaseModule


class MycheckModule(BaseModule):
    NAME = "mycheck"
    DESCRIPTION = "Custom security check"

    def run(self):
        response = self.get("/")
        if response and "sensitive" in response.text.lower():
            self.add_finding(
                severity="HIGH",
                title="Sensitive data exposed",
                url=self.url("/"),
                detail="The home page appears to expose sensitive data.",
                remediation="Restrict sensitive output and review access controls.",
            )
```

## Development Notes

- Keep generated scan reports out of commits unless they are intentionally added as documentation samples.
- Keep modules small and focused on one vulnerability class.
- Prefer clear evidence and remediation text for every finding.
- Keep exploitation checks non-destructive: prove impact with the smallest safe signal and document anything that needs manual validation.
- Test only in legal lab environments or on authorised targets.

## Legal Notice

Vulxor is provided for authorised security testing, education, and controlled lab use. You are responsible for ensuring that every target you test is in scope and that you have permission to assess it.
