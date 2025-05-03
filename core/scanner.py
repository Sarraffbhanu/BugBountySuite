import requests
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

class AdvancedScanner:
    def __init__(self, target_url):
        self.target = target_url
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36',
            'Accept': '*/*'
        }
    
    def _is_valid_response(self, response):
        return 200 <= response.status_code < 400

    def scan_xss(self):
        from core.payload_manager import PayloadManager
        pm = PayloadManager()
        payloads = pm.get_payloads('xss')
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for payload in payloads:
                futures.append(executor.submit(
                    self._test_payload, 
                    payload,
                    "XSS"
                ))
            
            results = []
            for future in tqdm(futures, desc="Scanning XSS"):
                result = future.result()
                if result:
                    results.append(result)
            return results

    def _test_payload(self, payload, vuln_type):
        try:
            test_url = f"{self.target}?q={payload['payload']}"
            response = self.session.get(test_url, timeout=15)
            
            if payload['payload'] in response.text:
                return {
                    'type': vuln_type,
                    'payload': payload['payload'],
                    'url': test_url,
                    'confidence': 90 if response.status_code == 200 else 50
                }
        except Exception as e:
            return None
