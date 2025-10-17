
import json, os
from typing import Iterable, Dict, Any
from .base import Collector

class CollectorImpl(Collector):
    name = "dns"
    sourcetype = "ir:dns"
    def __init__(self, input_dir: str):
        self.path = os.path.join(input_dir, "dns.jsonl")
    def collect(self) -> Iterable[Dict[str,Any]]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line=line.strip()
                if not line: continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue
