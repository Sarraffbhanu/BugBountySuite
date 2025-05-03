import os
import json
from pathlib import Path

class PayloadManager:
    def __init__(self):
        self.payload_dir = Path(__file__).parent.parent / "payloads"
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        payloads = {}
        for payload_file in self.payload_dir.glob("*.json"):
            with open(payload_file) as f:
                payloads[payload_file.stem] = json.load(f)
        return payloads
    
    def get_payloads(self, vulnerability_type):
        return self.payloads.get(vulnerability_type, [])
