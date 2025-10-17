
import os, json, glob, argparse
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

def load_events(outbox_dir: str, month: str):
    y, m = month.split("-")
    events = []
    for f in glob.glob(os.path.join(outbox_dir, "*.jsonl")):
        for line in open(f, "r", encoding="utf-8"):
            try:
                ev = json.loads(line)
                if ev.get("_time","").startswith(f"{y}-{m}"):
                    events.append(ev)
            except Exception:
                pass
    return events

def build_sections(events):
    # Simple rollups
    high = [e for e in events if str(e.get("severity","")).lower() in ("high","critical")]
    hosts = {}
    users = {}
    for e in events:
        hosts[e.get("host","unknown")] = 1
        users[e.get("user","unknown")] = 1

    # Compliance sections (examples)
    sections = [
        {
            "title": "Authentication Anomalies",
            "description": "Failed logons and suspicious auth behavior across Windows/Linux.",
            "headers": ["_time","host","user","action","message"],
            "rows": [e for e in events if e.get("source") in ("linux_auth","windows_evt") and "fail" in str(e.get("message","")).lower()][:200]
        },
        {
            "title": "EDR Detections (High)",
            "description": "High severity endpoint detections to review within 24 hours.",
            "headers": ["_time","host","user","severity","signature","message"],
            "rows": high[:200]
        },
        {
            "title": "Firewall Blocks",
            "description": "Network blocks for potential C2 or exfil.",
            "headers": ["_time","src_ip","dest_ip","action","message"],
            "rows": [e for e in events if e.get("source")=="firewall" and e.get("action")=="blocked"][:200]
        },
        {
            "title": "Vulnerability Exposures",
            "description": "Hosts with critical vulns detected by scanner.",
            "headers": ["_time","host","severity","signature","message"],
            "rows": [e for e in events if e.get("source")=="vulnscan" and str(e.get("severity","")).lower() in ("high","critical")][:200]
        },
    ]

    kpis = {
        "total_events": len(events),
        "high_sev": len(high),
        "unique_hosts": len(hosts),
        "unique_users": len(users)
    }
    return sections, kpis

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--month", required=True, help="YYYY-MM (e.g., 2025-09)")
    ap.add_argument("--outbox", default="data/outbox")
    ap.add_argument("--template_dir", default="src/reporting/templates")
    ap.add_argument("--dest", default="reports")
    args = ap.parse_args()

    events = load_events(args.outbox, args.month)
    sections, kpis = build_sections(events)

    env = Environment(loader=FileSystemLoader(args.template_dir))
    tmpl = env.get_template("compliance.html")
    html = tmpl.render(
        month=args.month,
        kpis=kpis,
        sections=sections,
        generated_at=datetime.utcnow().isoformat()+"Z"
    )
    os.makedirs(args.dest, exist_ok=True)
    out = os.path.join(args.dest, f"compliance-{args.month}.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Wrote {out}")

if __name__ == "__main__":
    main()
