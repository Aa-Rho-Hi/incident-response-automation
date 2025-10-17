
import time, json, queue, threading, requests
from typing import Iterable, Dict, Any

class HECClient:
    def __init__(self, url: str, token: str, verify_ssl: bool = False, batch_size: int = 500, flush_seconds: int = 2):
        self.url = url.rstrip('/') + '/services/collector/event'
        self.headers = {"Authorization": f"Splunk {token}"}
        self.verify_ssl = verify_ssl
        self.batch_size = batch_size
        self.flush_seconds = flush_seconds
        self.q = queue.Queue()
        self._stop = threading.Event()
        self.worker = threading.Thread(target=self._run, daemon=True)
        self.worker.start()

    def send(self, events: Iterable[Dict[str, Any]], sourcetype: str = "ir:generic", index: str = None):
        for ev in events:
            payload = {"event": ev, "sourcetype": sourcetype}
            if index: payload["index"] = index
            self.q.put(payload)

    def _run(self):
        buf = []
        last = time.time()
        while not self._stop.is_set():
            try:
                item = self.q.get(timeout=0.5)
                buf.append(item)
            except queue.Empty:
                pass
            now = time.time()
            if buf and (len(buf) >= self.batch_size or (now - last) >= self.flush_seconds):
                self._flush(buf); buf = []; last = now

        if buf:
            self._flush(buf)

    def _flush(self, buf):
        data = "
".join(json.dumps(x) for x in buf)
        try:
            r = requests.post(self.url, headers=self.headers, data=data, verify=self.verify_ssl, timeout=10)
            r.raise_for_status()
        except Exception as e:
            print(f"[HEC] post failed: {e} (buffer len={len(buf)})")

    def close(self):
        self._stop.set()
        self.worker.join(timeout=3)
