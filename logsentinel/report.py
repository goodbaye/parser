"""Rendering of findings: console table, JSON, CSV."""

from __future__ import annotations

import csv
import json
import sys
from typing import List

from .detectors import Finding

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.timestamp))


def print_console_report(findings: List[Finding]) -> None:
    findings = sort_findings(findings)
    if not findings:
        print("No suspicious activity detected.")
        return

    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    print(f"Findings: {len(findings)}  "
          f"(high={counts.get('high', 0)}, medium={counts.get('medium', 0)}, low={counts.get('low', 0)})")
    print("-" * 100)
    for f in findings:
        print(f"[{f.severity.upper():6}] {f.timestamp}  rule={f.rule:<24} ip={f.ip:<15} user={f.user}")
        print(f"          {f.detail}")
    print("-" * 100)


def write_json_report(findings: List[Finding], path: str) -> None:
    findings = sort_findings(findings)
    data = [f.__dict__ for f in findings]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def write_csv_report(findings: List[Finding], path: str) -> None:
    findings = sort_findings(findings)
    fieldnames = ["rule", "severity", "ip", "user", "timestamp", "detail"]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow(f.__dict__)
