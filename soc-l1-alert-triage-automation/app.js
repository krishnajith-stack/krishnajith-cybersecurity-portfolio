const scenarios = {
  powershell: {
    alert: {
      id: "INC-2026-001", title: "Encoded PowerShell execution", timestamp: "2026-09-14 08:42 UTC",
      source: "Defender for Endpoint", severity: "high", user: "aisha.khan@contoso.example", host: "FIN-WS-042",
      src_ip: "203.0.113.66", process: "powershell.exe", asset: "Important finance endpoint"
    },
    result: {
      score: 100, disposition: "ESCALATE TO L2", priority: "P1 · CRITICAL", confidence: "HIGH CONFIDENCE",
      summary: "Encoded PowerShell on an important finance endpoint matched a malicious test indicator. The combined evidence requires immediate L2 validation.",
      evidence: [["Source severity", "+40"], ["Asset criticality", "+10"], ["Malicious IP match", "+30"], ["Obfuscated PowerShell", "+25"]],
      mitre: ["T1059.001 · PowerShell"],
      actions: ["Review process tree and endpoint timeline.", "Hunt the indicator across SIEM, EDR, DNS, proxy, and firewall logs.", "Escalate the evidence package to L2.", "L2 validates business impact before containment."]
    }
  },
  bruteforce: {
    alert: {
      id: "INC-2026-002", title: "Privileged identity brute force", timestamp: "2026-09-14 10:15 UTC",
      source: "Microsoft Entra ID", severity: "medium", user: "cloud.admin@contoso.example", host: "Cloud identity",
      src_ip: "192.0.2.44", process: "37 failed authentication events", asset: "Critical privileged account"
    },
    result: {
      score: 95, disposition: "ESCALATE TO L2", priority: "P1 · CRITICAL", confidence: "HIGH CONFIDENCE",
      summary: "High-volume failures against a critical privileged identity originated from a suspicious test indicator. L2 validation is required.",
      evidence: [["Source severity", "+25"], ["Asset criticality", "+20"], ["Privileged identity", "+15"], ["Suspicious IP match", "+15"], ["Authentication failures", "+20"]],
      mitre: ["T1110 · Brute Force"],
      actions: ["Review sign-in and MFA history.", "Confirm device state and recent identity changes.", "Search the source indicator across telemetry.", "Escalate with evidence to L2."]
    }
  },
  travel: {
    alert: {
      id: "INC-2026-003", title: "Impossible travel sign-in", timestamp: "2026-09-14 12:05 UTC",
      source: "Entra ID Protection", severity: "medium", user: "samir.rao@contoso.example", host: "Cloud identity",
      src_ip: "8.8.8.8", process: "India → Germany in 24 minutes", asset: "Important user identity"
    },
    result: {
      score: 60, disposition: "ANALYST INVESTIGATION", priority: "P3 · MEDIUM", confidence: "MEDIUM CONFIDENCE",
      summary: "Geographically implausible sign-ins on an important identity require user, device, VPN, and authentication-context validation by L1.",
      evidence: [["Source severity", "+25"], ["Asset criticality", "+10"], ["Impossible travel", "+25"]],
      mitre: ["T1078 · Valid Accounts"],
      actions: ["Review sign-in locations, timestamps, and device IDs.", "Check VPN or corporate proxy egress.", "Validate MFA and user activity.", "Update the disposition after investigation."]
    }
  },
  benign: {
    alert: {
      id: "INC-2026-004", title: "Approved vulnerability scanner", timestamp: "2026-09-14 02:00 UTC",
      source: "Firewall", severity: "low", user: "Scheduled service", host: "10.20.30.40",
      src_ip: "198.51.100.10", process: "200 scheduled connections", asset: "Standard test target"
    },
    result: {
      score: 0, disposition: "CLOSE AS BENIGN", priority: "P4 · LOW", confidence: "LOW CONFIDENCE",
      summary: "The alert matches an allowlisted scanner and an approved scheduled activity. Closure still requires verification of the scan window and owner.",
      evidence: [["Source severity", "+10"], ["Allowlisted IP", "−20"], ["Known benign activity", "−50"]],
      mitre: [],
      actions: ["Validate the approved scanner inventory.", "Confirm the authorized scan window and target scope.", "Document the closure reason.", "Tune only after reviewing missed-detection risk."]
    }
  }
};

const tabs = [...document.querySelectorAll("[data-scenario]")];
const title = document.querySelector("#alert-title");
const severity = document.querySelector("#alert-severity");
const details = document.querySelector("#alert-details");
const alertJson = document.querySelector("#alert-json");
const runButton = document.querySelector("#run-triage");
const emptyState = document.querySelector("#empty-state");
const resultContent = document.querySelector("#result-content");
let selected = "powershell";

function labelFor(key) {
  const labels = {id: "Alert ID", timestamp: "Timestamp", source: "Source", user: "User", host: "Host", src_ip: "Source IP", process: "Observed behavior", asset: "Business context"};
  return labels[key] || key;
}

function renderAlert(key) {
  selected = key;
  const alert = scenarios[key].alert;
  title.textContent = alert.title;
  severity.textContent = alert.severity.toUpperCase();
  severity.className = `severity ${alert.severity}`;
  const visibleKeys = ["id", "timestamp", "source", "user", "host", "src_ip", "process", "asset"];
  details.innerHTML = visibleKeys.map(field => `<div><dt>${labelFor(field)}</dt><dd>${alert[field]}</dd></div>`).join("");
  alertJson.textContent = JSON.stringify(alert, null, 2);
  emptyState.hidden = false;
  resultContent.hidden = true;
}

function renderResult() {
  const result = scenarios[selected].result;
  runButton.disabled = true;
  runButton.textContent = "Analyzing alert…";
  window.setTimeout(() => {
    emptyState.hidden = true;
    resultContent.hidden = false;
    const scoreRing = document.querySelector("#score-ring");
    scoreRing.className = `score-ring ${result.score < 40 ? "low" : result.score < 70 ? "medium" : "high"}`;
    document.querySelector("#risk-score").textContent = result.score;
    document.querySelector("#disposition").textContent = result.disposition;
    document.querySelector("#priority").textContent = result.priority;
    document.querySelector("#confidence").textContent = result.confidence;
    document.querySelector("#result-summary").textContent = result.summary;
    document.querySelector("#score-evidence").innerHTML = result.evidence.map(([name, points]) => `<li><b>${points}</b> · ${name}</li>`).join("");
    document.querySelector("#mitre-list").innerHTML = result.mitre.length ? result.mitre.map(item => `<span>${item}</span>`).join("") : "<span>No automatic mapping</span>";
    document.querySelector("#action-list").innerHTML = result.actions.map(item => `<li>${item}</li>`).join("");
    runButton.disabled = false;
    runButton.textContent = "Run automated triage";
  }, 520);
}

tabs.forEach(tab => tab.addEventListener("click", () => {
  tabs.forEach(item => item.setAttribute("aria-selected", String(item === tab)));
  renderAlert(tab.dataset.scenario);
}));
runButton.addEventListener("click", renderResult);
renderAlert(selected);
