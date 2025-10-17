
from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime

def run(events: List[Dict[str,Any]]) -> Dict[str,Any]:
    # Correlate DNS + Proxy + EDR to flag risky links clicked by users
    user_iocs = defaultdict(lambda: {"dns":0,"proxy":0,"edr":0})
    for e in events:
        u = e.get("user") or "unknown"
        if e.get("source") == "dns": user_iocs[u]["dns"] += 1
        if e.get("source") == "proxy": user_iocs[u]["proxy"] += 1
        if e.get("source") == "edr": user_iocs[u]["edr"] += 1
    table = [{"user": u, **c, "score": c["dns"] + 2*c["proxy"] + 3*c["edr"]} for u,c in user_iocs.items()]
    table.sort(key=lambda x: x["score"], reverse=True)
    return {"generated_at": datetime.utcnow().isoformat()+"Z", "users": table[:20]}
