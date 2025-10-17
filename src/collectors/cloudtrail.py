
import json, os
from typing import Iterable, Dict, Any
from .base import Collector

class CollectorImpl(Collector):
    name = "cloudtrail"
    sourcetype = "ir:cloudtrail"
    def __init__(self, input_dir: str):
        self.path = os.path.join(input_dir, "cloudtrail.jsonl")
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
