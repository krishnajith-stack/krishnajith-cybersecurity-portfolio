# Implementation and Publishing Guide

This guide takes the project from a local test to its public GitHub source folder, a live GitHub Pages demo, and a clickable portfolio project.

## Phase 1 — Understand the Alert Contract

The automation expects normalized JSON. SIEM products use different field names, so a production connector should translate vendor fields into this contract before triage.

Required fields:

```json
{
  "id": "INC-2026-001",
  "title": "Encoded PowerShell execution",
  "timestamp": "2026-09-14T08:42:11Z",
  "source": "Microsoft Defender for Endpoint",
  "severity": "high"
}
```

Useful optional fields include `user`, `host`, `src_ip`, `dst_ip`, `process`, `command_line`, `authentication_result`, `event_count`, `asset_criticality`, `privileged_account`, `known_benign`, and `iocs`.

## Phase 2 — Run the Offline Lab

1. Open PowerShell or a terminal in the project folder.
2. Confirm Python with `python --version`; use Python 3.10 or newer.
3. Run a high-risk example: `python triage.py --input samples/alert-powershell.json`.
4. Open the generated `.md` and `.json` files in `reports/`.
5. Run the remaining three samples and compare their decisions.
6. Run validation: `python -m unittest discover -s tests -v`.

No virtual environment or package installation is required. For development, you may optionally create a virtual environment and run `python -m pip install -e .`.

Expected test result: five tests pass.

## Phase 3 — Explain the Triage Decision

For every demo, explain the result in this order:

1. What triggered the alert?
2. Which user, host, and network indicators were extracted?
3. Which enrichment matches were found?
4. What raised or lowered the risk score?
5. Which ATT&CK technique was mapped, and why?
6. Why was it closed, investigated, or escalated?
7. What must the human analyst validate next?

This sequence shows operational judgment, not only coding.

## Phase 4 — GitHub Deployment

The project is deployed under `soc-l1-alert-triage-automation/` in the public `krishnajith-cybersecurity-portfolio` repository. This keeps the live project and main portfolio under one GitHub Pages site.

- Public source: `https://github.com/krishnajith-stack/krishnajith-cybersecurity-portfolio/tree/main/soc-l1-alert-triage-automation`
- Live application: `https://krishnajith-stack.github.io/krishnajith-cybersecurity-portfolio/soc-l1-alert-triage-automation/`
- Automated tests: `.github/workflows/soc-triage-test.yml`

## Phase 5 — Verify the Live Demo

The existing portfolio already uses GitHub Pages. After the project files reach `main`, allow GitHub a few minutes to publish the updated site, then open `https://krishnajith-stack.github.io/krishnajith-cybersecurity-portfolio/soc-l1-alert-triage-automation/`.

The separate `soc-triage-test.yml` workflow validates the Python automation. It is independent of the portfolio's Pages publishing configuration.

## Phase 6 — Make the Main Portfolio Clickable

Open your portfolio repository `krishnajith-cybersecurity-portfolio` and locate the SOC L1 project card in `index.html`. Add these links inside the card:

```html
<div class="project-actions">
  <a class="project-link primary"
     href="https://krishnajith-stack.github.io/krishnajith-cybersecurity-portfolio/soc-l1-alert-triage-automation/"
     target="_blank" rel="noopener noreferrer">View Live Demo</a>
  <a class="project-link"
     href="https://github.com/krishnajith-stack/krishnajith-cybersecurity-portfolio/tree/main/soc-l1-alert-triage-automation"
     target="_blank" rel="noopener noreferrer">View GitHub</a>
</div>
```

Copy the CSS from `portfolio/portfolio-project-links.css` into the portfolio stylesheet. A complete card example is in `portfolio/soc-project-card.html`.

Commit the portfolio change with:

```text
Add live SOC triage automation project links
```

Then test both buttons in a private/incognito window. This verifies that recruiters who are not signed into your GitHub account can access everything.

## Phase 7 — Portfolio Evidence Checklist

Before sharing the project on LinkedIn or in applications, verify:

- Repository is public.
- README badges load.
- GitHub Actions test workflow passes.
- Live demo loads on desktop and mobile.
- Each of the four demo scenarios returns the expected decision.
- No real company data, user details, customer names, internal IPs, or secrets exist.
- Portfolio **View Live Demo** and **View GitHub** buttons open in a new tab.
- Resume project entry uses precise wording: “portfolio lab” or “automation project,” not enterprise production deployment.

## Optional Phase 8 — Microsoft Sentinel Integration

Add this only after the offline version is understood and documented.

1. Create a Microsoft Sentinel automation rule triggered when an incident is created.
2. Call a Logic App playbook using a managed identity.
3. Normalize incident alerts and entities to the project schema.
4. Query approved TI sources or Sentinel threat-intelligence tables.
5. Apply the risk rules and prepare an analyst comment.
6. Add tags such as `auto-enriched`, `malicious-ioc`, and the recommended priority.
7. Write the summary back to the Sentinel incident.
8. Route high-risk incidents to the L2 queue.
9. Keep automated containment and closure disabled until formal approval, testing, and rollback controls exist.
10. Capture sanitized screenshots and add them to the case study.

Sentinel and Logic Apps can incur Azure charges. The offline project does not require them.

## Interview Explanation

“I built a vendor-neutral SOC L1 triage automation in Python. It validates normalized alerts, extracts entities, enriches indicators against a controlled local dataset, applies an explainable risk model, maps supported behavior to MITRE ATT&CK, and generates both JSON and Markdown evidence packages. I tested high-risk PowerShell, privileged brute-force, identity anomaly, and known-benign scenarios. It supports the analyst rather than autonomously containing or closing production incidents. I also designed the extension point for Sentinel automation rules and Logic Apps.”
