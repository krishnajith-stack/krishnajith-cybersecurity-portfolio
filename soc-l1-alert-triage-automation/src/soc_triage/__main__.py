"""Command-line entry point for the triage engine."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .engine import TriageEngine
from .report import markdown_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Triage a normalized SOC alert.")
    parser.add_argument("--input", required=True, help="Path to an alert JSON file")
    parser.add_argument("--indicators", default="config/indicators.json", help="Path to local IOC data")
    parser.add_argument("--output-dir", default="reports", help="Directory for JSON and Markdown outputs")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    try:
        alert = json.loads(input_path.read_text(encoding="utf-8"))
        engine = TriageEngine.from_file(args.indicators)
        result = engine.triage(alert)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Triage failed: {exc}", file=sys.stderr)
        return 1

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = str(result["alert_id"]).replace("/", "-")
    json_path = output_dir / f"{stem}.json"
    report_path = output_dir / f"{stem}.md"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    report_path.write_text(markdown_report(alert, result), encoding="utf-8")

    print(json.dumps({
        "alert_id": result["alert_id"],
        "risk_score": result["risk_score"],
        "priority": result["priority"],
        "disposition": result["disposition"],
        "json_report": str(json_path),
        "markdown_report": str(report_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
