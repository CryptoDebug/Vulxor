from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional


@dataclass
class Finding:
    module:     str
    severity:   str
    title:      str
    url:        str
    detail:     str
    payload:    Optional[str] = None
    evidence:   Optional[str] = None
    remediation: Optional[str] = None
    timestamp:  str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "module":      self.module,
            "severity":    self.severity,
            "title":       self.title,
            "url":         self.url,
            "detail":      self.detail,
            "payload":     self.payload,
            "evidence":    self.evidence,
            "remediation": self.remediation,
            "timestamp":   self.timestamp,
        }


class ScanResults:
    def __init__(self, target: str):
        self.target = target
        self.started_at = datetime.now().isoformat()
        self.finished_at: Optional[str] = None
        self.findings: Dict[str, List[Finding]] = {}
        self.meta: Dict[str, Any] = {}

    def add(self, finding: Finding):
        self.findings.setdefault(finding.module, []).append(finding)

    def all_findings(self) -> List[Finding]:
        out = []
        for findings in self.findings.values():
            out.extend(findings)
        return sorted(out, key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(f.severity))

    def count_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.all_findings():
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def finish(self):
        self.finished_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "target":      self.target,
            "started_at":  self.started_at,
            "finished_at": self.finished_at,
            "summary":     self.count_by_severity(),
            "findings":    [f.to_dict() for f in self.all_findings()],
            "meta":        self.meta,
        }
