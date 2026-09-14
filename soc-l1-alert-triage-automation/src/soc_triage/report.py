"""Human-readable case report generation."""

from __future__ import annotations

from typing import Any


def markdown_report(alert: dict[str, Any], result: dict[str, Any]) -> str:
    findings = "\n".join(
        f"- **{item['label']} ({item['points']:+d}):** {item['evidence']}"
        for item in result["findings"]
    )
    actions = "\n".join(f"{index}. {action}" for index, action in enumerate(result["recommended_actions"], 1))
    mitre = ", ".join(
        f"{item['technique_id']} – {item['name']}" for item in result["mitre_attack"]
    ) or "No automatic mapping"
    entity_labels = {"users": "Users", "hosts": "Hosts", "ips": "IPs", "domains": "Domains", "hashes": "Hashes"}
    entities = "\n".join(
        f"- **{entity_labels.get(key, key.title())}:** {', '.join(values)}" for key, values in result["entities"].items()
    ) or "- No normalized entities"

    return f"""# SOC Triage Case: {result['alert_id']}

## Decision

| Field | Result |
| --- | --- |
| Alert | {result['title']} |
| Risk score | **{result['risk_score']}/100** |
| Priority | **{result['priority']}** |
| Disposition | **{result['disposition']}** |
| Confidence | {result['confidence']} |
| Triaged at | {result['triaged_at']} |

## Analyst Summary

{result['summary']}

## Evidence and Scoring

{findings}

## Entities

{entities}

## MITRE ATT&CK

{mitre}

## Recommended Actions

{actions}

## Source Alert

- Source: {alert['source']}
- Timestamp: {alert['timestamp']}
- User: {alert.get('user', 'N/A')}
- Host: {alert.get('host', 'N/A')}
- Source IP: {alert.get('src_ip', 'N/A')}

> {result['analyst_note']}
"""
