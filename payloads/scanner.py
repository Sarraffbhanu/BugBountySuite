def scan_ssrf(self):
    findings = []
    for payload in self.payload_manager.get_payloads('ssrf_internal'):
        test_url = self.target.replace('PAYLOAD', payload['payload'])
        response = self.session.get(test_url)
        if self._detect_ssrf(response):
            findings.append({
                'type': 'SSRF',
                'payload': payload['payload'],
                'confidence': 90
            })
    return findings

def _detect_ssrf(self, response):
    indicators = [
        "EC2 Metadata", 
        "root:x:0:0",
        "ERR wrong number of arguments"
    ]
    return any(indicator in response.text for indicator in indicators)
