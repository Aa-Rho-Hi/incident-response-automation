
import os, json, random, argparse
from datetime import datetime, timedelta

SOURCES = ["windows_evt","linux_auth","firewall","edr","dns","proxy","cloudtrail","vulnscan"]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--hours", type=int, default=72)
    p.add_argument("--input_dir", default="data/input")
    args = p.parse_args()
    os.makedirs(args.input_dir, exist_ok=True)
    start = datetime.utcnow() - timedelta(hours=args.hours)

    # synthesize per-source JSONL
    for s in SOURCES:
        path = os.path.join(args.input_dir, f"{s}.jsonl")
        with open(path, "w", encoding="utf-8") as f:
            t = start
            for i in range(args.hours):
                recs = []
                if s == "windows_evt":
                    recs.append({
                        "timestamp": t.isoformat()+"Z", "host": "win-"+str(random.randint(1,5)), "user": random.choice(["alice","bob","svc_sql","carol"]),
                        "event_code": random.choice(["4624","4625","4688"]), "message": random.choice(["Login success","Login fail","Process created"]),
                        "severity": random.choice(["low","medium","high"])
                    })
                elif s == "linux_auth":
                    recs.append({
                        "timestamp": t.isoformat()+"Z", "host":"lin-"+str(random.randint(1,5)), "user": random.choice(["root","alice","bob","deploy"]),
                        "message": random.choice(["sshd accepted password","sshd failed password","sudo invoked"]),
                        "severity": random.choice(["low","medium","high"])
                    })
                elif s == "firewall":
                    recs.append({
                        "timestamp": t.isoformat()+"Z", "src_ip": f"10.0.{random.randint(0,9)}.{random.randint(1,254)}",
                        "dest_ip": random.choice(["8.8.8.8","1.1.1.1","198.51.100.10"]), "action": random.choice(["allowed","blocked"]),
                        "message": random.choice(["rule match","suspicious outbound","dns exfil attempt"]), "severity": random.choice(["low","high"])
                    })
                elif s == "edr":
                    recs.append({
                        "timestamp": t.isoformat()+"Z", "host":"lap-"+str(random.randint(1,8)), "user": random.choice(["alice","bob","carol","dave"]),
                        "signature": random.choice(["EDR_RANSOM_SUSPECT","EDR_PUA","EDR_MAL_DOC"]), "message": random.choice(["suspicious encryption","macro dropper","persistence"]),
                        "severity": random.choice(["medium","high","critical"])
                    })
                elif s == "dns":
                    recs.append({
                        "timestamp": t.isoformat()+"Z", "host":"dns-edge", "user": random.choice(["alice","bob","carol","unknown"]),
                        "message": random.choice(["query bad.tld","query tor.exit","query corp.local"]), "severity": "low"
                    })
                elif s == "proxy":
                    recs.append({
                        "timestamp": t.isoformat()+"Z", "host":"proxy-1", "user": random.choice(["alice","bob","carol","unknown"]),
                        "message": random.choice(["GET http://shady.example","CONNECT tor","POST http://ok.site"]), "severity": random.choice(["low","medium"])
                    })
                elif s == "cloudtrail":
                    recs.append({
                        "timestamp": t.isoformat()+"Z", "user":"aws:"+random.choice(["ci","admin","developer"]), "action": random.choice(["CreateUser","AttachPolicy","ConsoleLogin"]),
                        "message": random.choice(["successful login","policy modified","access key created"]), "severity": random.choice(["low","medium","high"])
                    })
                elif s == "vulnscan":
                    recs.append({
                        "timestamp": t.isoformat()+"Z", "host":"srv-"+str(random.randint(1,6)), "severity": random.choice(["low","medium","high","critical"]),
                        "signature": random.choice(["CVE-2024-1234","CVE-2023-9999","WeakCipher"]), "message": random.choice(["OpenSSL vuln","Kernel vuln","TLS weak cipher"])
                    })
                for r in recs:
                    f.write(json.dumps(r)+"\n")
                t += timedelta(hours=1)
    print(f"Wrote synthetic logs to {args.input_dir}")

if __name__ == "__main__":
    main()
