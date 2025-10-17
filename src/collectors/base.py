
from typing import Iterable, Dict, Any

class Collector:
    name = "base"
    sourcetype = "ir:base"
    def collect(self) -> Iterable[Dict[str,Any]]:
        raise NotImplementedError
