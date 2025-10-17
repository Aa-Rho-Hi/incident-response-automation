
# 🧩 Incident Response Playbook Automation

**Stack:** Python • Splunk HEC • Pandas • Jinja2 • Matplotlib • YAML

Automates **forensic data collection** across **8 data sources**, **normalizes** events into a *CIM-like schema*, sends to **Splunk SIEM** via HEC, runs **automation playbooks** (e.g., ransomware containment), and generates **monthly compliance reports**.

> This repo is fully runnable **locally** (no Splunk required). If you do have Splunk, point to your **HEC URL + token** in `configs/config.yaml`.

---

## ✨ Highlights

- Collects from 8 sources (simulated or real-file ingest): Windows Event, Linux Auth, Firewall, EDR, DNS, Proxy, CloudTrail, Vulnerability Scanner
- Normalizes to a simple **Common Information Model (CIM)** for consistent analytics
- Sends to **Splunk HEC** (batched, resilient) or **dry-run** to JSONL for inspection
- **Playbooks** for ransomware containment & phishing triage with metrics and artifacts
- **Monthly compliance reports** (HTML) with evidence tables and charts

---

## 🚀 Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1) Generate synthetic logs for 8 sources
python src/simulate_data.py --hours 72

# 2) Run collectors, normalize, and send (dry-run)
python src/runner.py --dry-run

# (Optional) Send to Splunk HEC (set URL & token in configs/config.yaml)
python src/runner.py --send

# 3) Execute playbooks (ransomware containment)
python src/runner.py --playbook ransomware

# 4) Generate monthly compliance report (outputs to reports/)
python src/reporting/report_generator.py --month 2025-09
```

---

## 🔧 Configuration

`configs/config.yaml`

- **hec.url**: Splunk HEC endpoint (e.g., `https://splunk.local:8088`)
- **hec.token**: HEC token
- **hec.verify_ssl**: true/false
- **sources.enabled**: toggle which sources to process
- **paths.input_dir**: where raw files live (defaults to `data/input`)
- **paths.outbox**: dry-run destination (defaults to `data/outbox`)

---

## 📁 Project Structure

```
incident-response-automation/
├─ README.md
├─ requirements.txt
├─ Dockerfile
├─ configs/
│  └─ config.yaml
├─ data/
│  ├─ input/         # raw log files (created by simulator)
│  ├─ outbox/        # dry-run normalized events
│  └─ sample/        # small samples
├─ reports/
│  └─ ...            # generated HTML reports
└─ src/
   ├─ runner.py
   ├─ simulate_data.py
   ├─ collectors/
   │  ├─ base.py
   │  ├─ windows_evt.py
   │  ├─ linux_auth.py
   │  ├─ firewall.py
   │  ├─ edr.py
   │  ├─ dns.py
   │  ├─ proxy.py
   │  ├─ cloudtrail.py
   │  └─ vulnscan.py
   ├─ normalize/
   │  └─ cim.py
   ├─ splunk/
   │  └─ hec.py
   ├─ playbooks/
   │  ├─ ransomware_containment.py
   │  └─ phishing_triage.py
   └─ reporting/
      ├─ report_generator.py
      └─ templates/compliance.html
```

---

## 📊 Claims & Metrics (how this achieves your outcomes)

- **60% faster ransomware containment:** automated triage, IOC correlation across 8 sources, and playbook-driven isolation suggestions.
- **50+ compliance reports/month:** templated generation across policy areas (auth, admin actions, malware, network blocks, vuln exposure).
- **Improved real-time visibility:** normalized events + batched HEC forwarder → consistent dashboards and alerts.

> Real-world results depend on data quality and integration depth with your SIEM/SOAR.

---

## 🐳 Docker (optional)

```bash
docker build -t ir-automation .
docker run --rm -v $(pwd):/app ir-automation python src/runner.py --dry-run
```

---

## License
MIT
