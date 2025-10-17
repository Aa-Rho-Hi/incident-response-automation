
import os, json, argparse, yaml
from typing import List, Dict
from normalize.cim import normalize

def load_config(path="configs/config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def load_collector(mod_name, input_dir):
    mod = __import__(f"collectors.{mod_name}", fromlist=["CollectorImpl"])
    return mod.CollectorImpl(input_dir)

def write_outbox(events, outbox, filename):
    os.makedirs(outbox, exist_ok=True)
    path = os.path.join(outbox, filename)
    with open(path, "a", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e)+"\n")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true", help="Send to Splunk HEC")
    ap.add_argument("--dry-run", action="store_true", help="Write normalized events to outbox")
    args = ap.parse_args()
    cfg = load_config()

    enabled = [k for k,v in cfg["sources"]["enabled"].items() if v]
    input_dir = cfg["paths"]["input_dir"]
    outbox = cfg["paths"]["outbox"]

    if args.send:
        from splunk.hec import HECClient
        hec = HECClient(cfg["hec"]["url"], cfg["hec"]["token"], cfg["hec"]["verify_ssl"], cfg["batch"]["size"], cfg["batch"]["flush_seconds"])
    else:
        hec = None

    all_norm = []
    for name in enabled:
        col = load_collector(name, input_dir)
        raw_events = list(col.collect())
        normed = [normalize(e, source=name) for e in raw_events]
        if args.send and hec:
            hec.send(normed, sourcetype=f'{cfg["normalize"]["sourcetype_prefix"]}{name}')
        if args.dry_run or not args.send:
            write_outbox(normed, outbox, f"{name}.jsonl")
        all_norm.extend(normed)

    if hec:
        hec.close()

    print(f"Processed {len(all_norm)} events from sources: {', '.join(enabled)}")
    print("Mode:", "send->HEC" if args.send else "dry-run")

if __name__ == "__main__":
    main()
