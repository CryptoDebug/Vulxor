import json
import os
from datetime import datetime
from typing import Literal

from config.settings import Settings
from core.results import ScanResults


class ReportGenerator:
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    SEVERITY_COLORS = {
        "CRITICAL": "#e74c3c",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f1c40f",
        "LOW":      "#3498db",
        "INFO":     "#95a5a6",
    }

    def __init__(self, results: ScanResults, settings: Settings):
        self.results = results
        self.settings = settings
        self.ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(settings.output_dir, exist_ok=True)

    def generate(self, fmt: str):
        self.results.finish()
        if fmt in ("json", "all"):
            self._write_json()
        if fmt in ("txt", "all"):
            self._write_txt()
        if fmt in ("html", "all"):
            self._write_html()

    # ── JSON ───────────────────────────────────────────────────────────────

    def _write_json(self):
        path = os.path.join(self.settings.output_dir, f"report_{self.ts}.json")
        with open(path, "w") as f:
            json.dump(self.results.to_dict(), f, indent=2)

    # ── TXT ────────────────────────────────────────────────────────────────

    def _write_txt(self):
        path = os.path.join(self.settings.output_dir, f"report_{self.ts}.txt")
        lines = [
            "=" * 70,
            "  VULXOR - SECURITY ASSESSMENT REPORT",
            "=" * 70,
            f"  Target    : {self.results.target}",
            f"  Started   : {self.results.started_at}",
            f"  Finished  : {self.results.finished_at}",
            "",
            "  SUMMARY",
            "  " + "-" * 30,
        ]
        for sev in self.SEVERITY_ORDER:
            count = self.results.count_by_severity().get(sev, 0)
            lines.append(f"  {sev:<10}: {count}")
        lines += ["", "  FINDINGS", "  " + "-" * 30]
        for f in self.results.all_findings():
            lines += [
                f"\n  [{f.severity}] {f.module.upper()} - {f.title}",
                f"  URL      : {f.url}",
                f"  Detail   : {f.detail}",
            ]
            if f.payload:
                lines.append(f"  Payload  : {f.payload}")
            if f.evidence:
                lines.append(f"  Evidence : {f.evidence[:120]}")
            if f.remediation:
                lines.append(f"  Fix      : {f.remediation}")
        lines.append("\n" + "=" * 70)
        with open(path, "w") as fh:
            fh.write("\n".join(lines))

    # ── HTML ───────────────────────────────────────────────────────────────

    def _write_html(self):
        path = os.path.join(self.settings.output_dir, f"report_{self.ts}.html")
        summary = self.results.count_by_severity()
        total   = sum(summary.values())
        findings_html = ""
        for f in self.results.all_findings():
            color = self.SEVERITY_COLORS.get(f.severity, "#aaa")
            evidence_row = (
                f'<tr><th>Evidence</th><td><code>{self._esc(f.evidence[:300])}</code></td></tr>'
                if f.evidence else ""
            )
            payload_row = (
                f'<tr><th>Payload</th><td><code>{self._esc(f.payload)}</code></td></tr>'
                if f.payload else ""
            )
            fix_row = (
                f'<tr><th>Remediation</th><td>{self._esc(f.remediation)}</td></tr>'
                if f.remediation else ""
            )
            findings_html += f"""
            <div class="finding">
              <div class="finding-header" style="border-left:5px solid {color}">
                <span class="badge" style="background:{color}">{f.severity}</span>
                <span class="module">{f.module}</span>
                <span class="title">{self._esc(f.title)}</span>
              </div>
              <table class="finding-table">
                <tr><th>URL</th><td><a href="{self._esc(f.url)}">{self._esc(f.url)}</a></td></tr>
                <tr><th>Detail</th><td>{self._esc(f.detail)}</td></tr>
                {payload_row}
                {evidence_row}
                {fix_row}
                <tr><th>Time</th><td>{f.timestamp}</td></tr>
              </table>
            </div>
            """

        # Summary cards
        cards_html = ""
        for sev in self.SEVERITY_ORDER:
            cnt = summary.get(sev, 0)
            color = self.SEVERITY_COLORS[sev]
            cards_html += f"""
            <div class="card" style="border-top:4px solid {color}">
              <div class="card-count" style="color:{color}">{cnt}</div>
              <div class="card-label">{sev}</div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vulxor Report - {self._esc(self.results.target)}</title>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --text2: #8b949e;
    --accent: #58a6ff; --font: 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  header h1 {{ font-size: 1.6rem; color: var(--accent); letter-spacing: 2px; }}
  header p {{ color: var(--text2); font-size: .85rem; margin-top: .4rem; }}
  .meta {{ display:flex; gap:2rem; margin: 1rem 0; flex-wrap:wrap; }}
  .meta-item {{ background: var(--bg2); padding: .5rem 1rem; border-radius: 6px;
                font-size: .8rem; border: 1px solid var(--border); }}
  .meta-item span {{ color: var(--accent); }}
  .cards {{ display:flex; gap:1rem; margin: 1.5rem 0; flex-wrap:wrap; }}
  .card {{ background: var(--bg2); border: 1px solid var(--border); border-radius:8px;
           padding:1rem 1.5rem; min-width:100px; text-align:center; }}
  .card-count {{ font-size:2rem; font-weight:700; }}
  .card-label {{ font-size:.75rem; color: var(--text2); letter-spacing:1px; margin-top:.3rem; }}
  .finding {{ background: var(--bg2); border: 1px solid var(--border); border-radius:8px;
              margin-bottom:1.2rem; overflow:hidden; }}
  .finding-header {{ display:flex; align-items:center; gap:.8rem; padding:.8rem 1.2rem;
                     background: var(--bg3); }}
  .badge {{ font-size:.7rem; font-weight:700; padding:.25rem .6rem; border-radius:4px;
            color:#000; letter-spacing:1px; }}
  .module {{ font-size:.75rem; color: var(--text2); text-transform:uppercase; letter-spacing:1px; }}
  .title {{ font-size:.95rem; color: var(--text); }}
  .finding-table {{ width:100%; border-collapse:collapse; font-size:.82rem; }}
  .finding-table th {{ width:130px; background: var(--bg3); color: var(--text2);
                       padding:.5rem 1rem; text-align:left; vertical-align:top;
                       border-top: 1px solid var(--border); font-weight:normal; }}
  .finding-table td {{ padding:.5rem 1rem; border-top: 1px solid var(--border);
                       word-break:break-all; }}
  .finding-table td a {{ color: var(--accent); text-decoration:none; }}
  code {{ background: var(--bg); padding:.1rem .4rem; border-radius:3px;
          font-family: var(--font); font-size:.8rem; }}
  h2 {{ margin: 2rem 0 1rem; font-size:1rem; letter-spacing:2px; color: var(--text2);
        text-transform:uppercase; border-bottom:1px solid var(--border); padding-bottom:.5rem; }}
  footer {{ margin-top:3rem; text-align:center; color: var(--text2); font-size:.75rem; }}
</style>
</head>
<body>
<header>
  <h1>⬡ VULXOR REPORT</h1>
  <p>Advanced web application security assessment</p>
  <div class="meta">
    <div class="meta-item">Target <span>{self._esc(self.results.target)}</span></div>
    <div class="meta-item">Started <span>{self.results.started_at}</span></div>
    <div class="meta-item">Finished <span>{self.results.finished_at}</span></div>
    <div class="meta-item">Total findings <span>{total}</span></div>
  </div>
</header>

<h2>Severity Summary</h2>
<div class="cards">{cards_html}</div>

<h2>Findings ({total})</h2>
{findings_html if findings_html else '<p style="color:#8b949e">No findings recorded.</p>'}

<footer>Generated by Vulxor &mdash; Authorised use only</footer>
</body>
</html>"""
        with open(path, "w") as fh:
            fh.write(html)

    @staticmethod
    def _esc(s: str) -> str:
        if not s:
            return ""
        return (s.replace("&", "&amp;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;")
                  .replace('"', "&quot;"))
