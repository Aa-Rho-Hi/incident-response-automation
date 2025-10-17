
from datetime import datetime
from typing import Dict, Any

# minimal Common Information Model mapping
def normalize(event: Dict[str, Any], source: str) -> Dict[str, Any]:
    ts = event.get("timestamp") or event.get("@timestamp")
    if isinstance(ts, str):
        try:
            ts_parsed = datetime.fromisoformat(ts.replace("Z","+00:00"))
        except Exception:
            ts_parsed = datetime.utcnow()
    elif ts:
        ts_parsed = ts
    else:
        ts_parsed = datetime.utcnow()

    cim = {
        "_time": ts_parsed.isoformat(),
        "host": event.get("host") or event.get("device") or "unknown",
        "src_ip": event.get("src_ip") or event.get("source_ip"),
        "dest_ip": event.get("dest_ip") or event.get("dst_ip"),
        "user": event.get("user") or event.get("username"),
        "action": event.get("action") or event.get("event") or "info",
        "severity": event.get("severity","info"),
        "signature": event.get("signature") or event.get("rule") or event.get("event_code"),
        "message": event.get("message") or event.get("desc") or "",
        "source": source,
        "_raw": event
    }
    return cim
