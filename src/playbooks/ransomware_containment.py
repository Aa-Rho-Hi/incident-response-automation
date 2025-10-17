
from typing import List, Dict, Any, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

def run(events: List[Dict[str,Any]]) -> Dict[str,Any]:
    # Heuristics: high volume file ops + EDR alerts + auth anomalies within short window
    by_host = defaultdict(list)
    for ev in events:
        host = ev.get("host","unknown")
        by_host[host].append(ev)

    suspects = []
    for host, evs in by_host.items():
        edr_hits = sum(1 for e in evs if "EDR" in str(e.get("signature","")).upper() or e.get("source")=="edr")
        auth_fail = sum(1 for e in evs if e.get("source") in ("linux_auth","windows_evt") and "fail" in str(e.get("message","")).lower())
        proxy_spike = sum(1 for e in evs if e.get("source")=="proxy" and "tor" in str(e.get("message","")).lower())
        score = edr_hits*3 + auth_fail + proxy_spike*2
        if score >= 3:
            suspects.append({"host": host, "score": score, "edr_hits": edr_hits, "auth_fail": auth_fail, "proxy_tor": proxy_spike})

    actions = []
    for s in suspects:
        actions.append({
            "host": s["host"],
            "recommendations": [
                "Isolate endpoint from network (EDR/MDM).",
                "Block associated hashes and C2 IOCs in EDR/Firewall.",
                "Disable compromised accounts; rotate credentials.",
                "Acquire memory + disk triage (Velociraptor/EDR live response)."
            ]
        })

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "suspects": sorted(suspects, key=lambda x: x["score"], reverse=True),
        "actions": actions
    }
