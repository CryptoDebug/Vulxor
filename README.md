# Vulxor

> **⚠️ For authorised security testing only.**
> Run exclusively on systems you own or have explicit written permission to test.

---

## Project Structure

```
vulxor/
├── main.py                  # Entry point & CLI
├── requirements.txt
├── config/
│   └── settings.py          # Settings dataclass
├── core/
│   ├── engine.py            # Module orchestrator
│   ├── logger.py            # Colored logger
│   └── results.py           # Finding / ScanResults containers
├── modules/
│   ├── base.py              # BaseModule (all modules inherit from this)
│   ├── recon.py             # Reconnaissance & info gathering
│   ├── sqli.py              # SQL injection (error, blind, time, union)
│   ├── xss.py               # Reflected / DOM XSS
│   ├── auth.py              # Auth bypass, default creds
│   ├── idor.py              # Insecure direct object reference
│   ├── upload.py            # Unrestricted file upload
│   ├── lfi.py               # Local/Remote file inclusion
│   ├── ssrf.py              # Server-side request forgery
│   ├── xxe.py               # XML external entity
│   ├── ssti.py              # Server-side template injection
│   ├── nosql.py             # NoSQL (MongoDB) injection
│   ├── cors.py              # CORS misconfiguration
│   ├── csrf.py              # Missing CSRF tokens
│   ├── jwt.py               # JWT: alg:none, weak secrets
│   ├── waf.py               # WAF detection & evasion
│   ├── ratelimit.py         # Rate-limit absence
│   ├── desync.py            # HTTP request smuggling
│   ├── race.py              # Race conditions
│   ├── websocket.py         # WebSocket injection
│   ├── graphql.py           # GraphQL introspection & injection
│   ├── twofa.py             # 2FA bypass
│   └── captcha.py           # CAPTCHA bypass
├── reports/
│   └── generator.py         # JSON / TXT / HTML report generator
└── utils/
    └── banner.py            # ASCII banner
```

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage

### Full scan (all modules)
```bash
python main.py https://target.example.com
```

### Specific modules only
```bash
python main.py https://target.example.com --modules sqli xss auth
```

### With proxy (e.g. Burp Suite)
```bash
python main.py https://target.example.com --proxy http://127.0.0.1:8080
```

### With custom cookies and headers
```bash
python main.py https://target.example.com \
  --cookies "session=abc123; role=user" \
  --headers "X-API-Key:secret"
```

### All options
```
positional arguments:
  target                Target URL (e.g. https://example.com)

optional arguments:
  --modules             Modules to run (default: all)
  --output              Output directory (default: reports/)
  --threads N           Number of threads (default: 10)
  --timeout N           Request timeout in seconds (default: 10)
  --proxy URL           Proxy (e.g. http://127.0.0.1:8080)
  --cookies STR         Cookies: name=val; name2=val2
  --headers STR         Headers: Key:Val,Key2:Val2
  --auth STR            Basic auth: user:pass
  --wordlist PATH       Custom wordlist for directory brute-force
  --delay FLOAT         Delay between requests (seconds)
  --verbose / -v        Verbose output
  --no-banner           Suppress banner
  --report-format       json | txt | html | all (default: all)
```

---

## Extending - Adding a new module

1. Create `modules/my_module.py`
2. Inherit from `BaseModule`, set `NAME` and `DESCRIPTION`
3. Implement the `run(self)` method
4. Register it in `core/engine.py` → `MODULE_MAP`

```python
from modules.base import BaseModule

class MyModule(BaseModule):
    NAME = "mymodule"
    DESCRIPTION = "Description shown in progress bar"

    def run(self):
        resp = self.get("/some-endpoint")
        if resp and "sensitive" in resp.text:
            self.add_finding(
                severity="HIGH",
                title="Sensitive data exposed",
                url=self.url("/some-endpoint"),
                detail="The endpoint returns sensitive information.",
                remediation="Restrict access.",
            )
```

---

## Reports

Three formats are generated in the `reports/` directory:

| Format | Contents |
|--------|----------|
| `.json` | Machine-readable full findings object |
| `.txt`  | Plain-text summary for terminal/email |
| `.html` | Styled dark-mode interactive report |

---

## Legal Notice

This tool is intended for **authorised penetration testing** only.
Unauthorised use against systems you do not own or lack explicit permission to test is **illegal** and may result in criminal prosecution.
