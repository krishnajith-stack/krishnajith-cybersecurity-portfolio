"""Deterministic alert enrichment, scoring, and routing logic."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
from typing import Any


SEVERITY_SCORE = {"informational": 0, "low": 10, "medium": 25, "high": 40, "critical": 55}
CRITICALITY_SCORE = {"standard": 0, "important": 10, "critical": 20}


@dataclass(frozen=True)
class Finding:
    label: str
    points: int
    evidence: str


class TriageEngine:
    """Apply transparent SOC L1 triage rules to one normalized alert."""

    def __init__(self, indicators: dict[str, Any]):
        self.indicators = indicators
        self.malicious_ips = set(indicators.get("malicious_ips", []))
        self.suspicious_ips = set(indicators.get("suspicious_ips", []))
        self.malicious_domains = {x.lower() for x in indicators.get("malicious_domains", [])}
        self.malicious_hashes = {x.lower() for x in indicators.get("malicious_hashes", [])}
        self.allowlisted_ips = set(indicators.get("allowlisted_ips", []))

    @classmethod
    def from_file(cls, path: str | Path) -> "TriageEngine":
        with Path(path).open("r", encoding="utf-8") as handle:
            return cls(json.load(handle))

    def triage(self, alert: dict[str, Any]) -> dict[str, Any]:
        self._validate(alert)
        findings: list[Finding] = []
        tags: set[str] = set()
        mitre: dict[str, str] = {}

        severity = str(alert.get("severity", "low")).lower()
        base = SEVERITY_SCORE[severity]
        findings.append(Finding("Source severity", base, f"Normalized severity is {severity}."))

        criticality = str(alert.get("asset_criticality", "standard")).lower()
        asset_points = CRITICALITY_SCORE.get(criticality, 0)
        if asset_points:
            findings.append(Finding("Asset criticality", asset_points, f"Asset is classified as {criticality}."))

        if alert.get("privileged_account"):
            findings.append(Finding("Privileged identity", 15, "Alert involves a privileged account."))
            tags.add("privileged-account")

        self._evaluate_iocs(alert, findings, tags)
        self._evaluate_authentication(alert, findings, tags, mitre)
        self._evaluate_process(alert, findings, tags, mitre)
        self._evaluate_identity_patterns(alert, findings, tags, mitre)

        if alert.get("known_benign"):
            findings.append(Finding("Known benign activity", -50, "Alert matches an approved test or known administrative activity."))
            tags.add("known-benign")

        raw_score = sum(item.points for item in findings)
        risk_score = max(0, min(100, raw_score))
        disposition, priority = self._route(risk_score, alert, findings)

        return {
            "schema_version": "1.0",
            "alert_id": alert["id"],
            "title": alert["title"],
            "triaged_at": datetime.now(timezone.utc).isoformat(),
            "risk_score": risk_score,
            "priority": priority,
            "disposition": disposition,
            "confidence": self._confidence(findings),
            "summary": self._summary(alert, risk_score, disposition, findings),
            "findings": [item.__dict__ for item in findings],
            "entities": self._entities(alert),
            "mitre_attack": [
                {"technique_id": technique_id, "name": name}
                for technique_id, name in sorted(mitre.items())
            ],
            "tags": sorted(tags),
            "recommended_actions": self._actions(disposition, alert, tags),
            "analyst_note": "Automation provides decision support; a human analyst owns containment and closure.",
        }

    @staticmethod
    def _validate(alert: dict[str, Any]) -> None:
        required = ("id", "title", "timestamp", "source", "severity")
        missing = [field for field in required if not alert.get(field)]
        if missing:
            raise ValueError(f"Missing required alert field(s): {', '.join(missing)}")
        severity = str(alert["severity"]).lower()
        if severity not in SEVERITY_SCORE:
            raise ValueError(f"Unsupported severity: {alert['severity']}")

    def _evaluate_iocs(self, alert: dict[str, Any], findings: list[Finding], tags: set[str]) -> None:
        ips = {str(x) for x in alert.get("iocs", {}).get("ips", [])}
        if alert.get("src_ip"):
            ips.add(str(alert["src_ip"]))

        for value in sorted(ips):
            if value in self.allowlisted_ips:
                findings.append(Finding("Allowlisted IP", -20, f"{value} is on the local allowlist."))
                tags.add("allowlisted-ioc")
            elif value in self.malicious_ips:
                findings.append(Finding("Malicious IP match", 30, f"{value} matches the local malicious indicator list."))
                tags.add("malicious-ioc")
            elif value in self.suspicious_ips:
                findings.append(Finding("Suspicious IP match", 15, f"{value} matches the local suspicious indicator list."))
                tags.add("suspicious-ioc")
            elif self._is_public_ip(value):
                tags.add("public-source-ip")

        for domain in alert.get("iocs", {}).get("domains", []):
            if str(domain).lower() in self.malicious_domains:
                findings.append(Finding("Malicious domain match", 30, f"{domain} matches the local malicious indicator list."))
                tags.add("malicious-ioc")

        for file_hash in alert.get("iocs", {}).get("hashes", []):
            if str(file_hash).lower() in self.malicious_hashes:
                findings.append(Finding("Malicious hash match", 30, "A file hash matches the local malicious indicator list."))
                tags.add("malicious-ioc")

    @staticmethod
    def _evaluate_authentication(alert: dict[str, Any], findings: list[Finding], tags: set[str], mitre: dict[str, str]) -> None:
        count = int(alert.get("event_count", 0) or 0)
        auth_result = str(alert.get("authentication_result", "")).lower()
        text = f"{alert.get('title', '')} {alert.get('description', '')}".lower()
        is_failed_auth = auth_result == "failure" or any(term in text for term in ("brute force", "failed login", "password spray"))
        if is_failed_auth and count >= 20:
            findings.append(Finding("High-volume authentication failures", 20, f"{count} related failures were observed."))
            tags.add("authentication-attack")
            mitre["T1110"] = "Brute Force"
        elif is_failed_auth and count >= 5:
            findings.append(Finding("Repeated authentication failures", 10, f"{count} related failures were observed."))
            tags.add("authentication-anomaly")
            mitre["T1110"] = "Brute Force"

    @staticmethod
    def _evaluate_process(alert: dict[str, Any], findings: list[Finding], tags: set[str], mitre: dict[str, str]) -> None:
        process = str(alert.get("process", "")).lower()
        command = str(alert.get("command_line", "")).lower()
        text = f"{alert.get('title', '')} {alert.get('description', '')}".lower()
        if "powershell" in process or "powershell" in text:
            mitre["T1059.001"] = "PowerShell"
            tags.add("powershell")
            if re.search(r"(?:-enc(?:odedcommand)?\b|frombase64string|iex\s*\()", command):
                findings.append(Finding("Obfuscated PowerShell", 25, "Command line contains encoded or in-memory execution indicators."))
                tags.add("obfuscated-command")
        if any(term in f"{process} {command} {text}" for term in ("mimikatz", "sekurlsa", "lsass dump", "credential dumping")):
            findings.append(Finding("Credential access indicator", 30, "Process or command content indicates credential dumping activity."))
            tags.add("credential-access")
            mitre["T1003"] = "OS Credential Dumping"

    @staticmethod
    def _evaluate_identity_patterns(alert: dict[str, Any], findings: list[Finding], tags: set[str], mitre: dict[str, str]) -> None:
        text = f"{alert.get('title', '')} {alert.get('description', '')}".lower()
        if "impossible travel" in text:
            findings.append(Finding("Impossible travel", 25, "Identity telemetry indicates geographically implausible sign-ins."))
            tags.add("identity-anomaly")
            mitre["T1078"] = "Valid Accounts"
        if "mfa fatigue" in text or "mfa bombing" in text:
            findings.append(Finding("MFA fatigue pattern", 25, "Repeated MFA prompts indicate possible push-notification abuse."))
            tags.add("mfa-abuse")
            mitre["T1621"] = "Multi-Factor Authentication Request Generation"

    @staticmethod
    def _route(score: int, alert: dict[str, Any], findings: list[Finding]) -> tuple[str, str]:
        confirmed_malicious = any(item.label.startswith("Malicious") for item in findings)
        if score >= 70 or confirmed_malicious:
            return "ESCALATE_TO_L2", "P1" if score >= 90 else "P2"
        if score >= 40:
            return "ANALYST_INVESTIGATION", "P3"
        if alert.get("known_benign") or score < 20:
            return "CLOSE_AS_BENIGN", "P4"
        return "MONITOR_AND_DOCUMENT", "P4"

    @staticmethod
    def _confidence(findings: list[Finding]) -> str:
        positive = sum(1 for item in findings if item.points > 0)
        return "HIGH" if positive >= 4 else "MEDIUM" if positive >= 2 else "LOW"

    @staticmethod
    def _entities(alert: dict[str, Any]) -> dict[str, list[str]]:
        result = {"users": [], "hosts": [], "ips": [], "domains": [], "hashes": []}
        if alert.get("user"):
            result["users"].append(str(alert["user"]))
        if alert.get("host"):
            result["hosts"].append(str(alert["host"]))
        for field in ("src_ip", "dst_ip"):
            if alert.get(field):
                result["ips"].append(str(alert[field]))
        for key, target in (("ips", "ips"), ("domains", "domains"), ("hashes", "hashes")):
            result[target].extend(str(x) for x in alert.get("iocs", {}).get(key, []))
        return {key: sorted(set(values)) for key, values in result.items() if values}

    @staticmethod
    def _summary(alert: dict[str, Any], score: int, disposition: str, findings: list[Finding]) -> str:
        drivers = [item.label for item in findings if item.points >= 15]
        reason = ", ".join(drivers[:3]) if drivers else "limited risk indicators"
        return f"{alert['title']} scored {score}/100 and was routed to {disposition}. Primary drivers: {reason}."

    @staticmethod
    def _actions(disposition: str, alert: dict[str, Any], tags: set[str]) -> list[str]:
        actions = ["Validate the alert time range and source telemetry.", "Record findings and evidence in the incident ticket."]
        if "authentication-attack" in tags or "identity-anomaly" in tags or "mfa-abuse" in tags:
            actions.insert(1, "Review sign-in history, MFA events, device state, and recent identity changes.")
        if "powershell" in tags or "credential-access" in tags:
            actions.insert(1, "Review the process tree, command line, parent process, and endpoint timeline.")
        if "malicious-ioc" in tags:
            actions.insert(1, "Search the matched indicator across SIEM, EDR, DNS, proxy, and firewall telemetry.")
        if disposition == "ESCALATE_TO_L2":
            actions.extend(["Escalate with the generated evidence package.", "L2 to determine containment after validating business impact."])
        elif disposition == "CLOSE_AS_BENIGN":
            actions.append("Confirm the allowlist or approved activity before closing with a documented reason.")
        else:
            actions.append("Continue analyst investigation and update the disposition after validation.")
        return actions

    @staticmethod
    def _is_public_ip(value: str) -> bool:
        try:
            return ipaddress.ip_address(value).is_global
        except ValueError:
            return False
