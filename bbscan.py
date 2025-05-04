#!/data/data/com.termux/files/usr/bin/python
import argparse
import json
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode

import requests
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)

BANNER = f"""
{Fore.CYAN}
▓█████▄  ██▀███   ▒█████   █     █░ ▄▄▄       ██▀███  
▒██▀ ██▌▓██ ▒ ██▒▒██▒  ██▒▓█░ █ ░█░▒████▄    ▓██ ▒ ██▒
░██   █▌▓██ ░▄█ ▒▒██░  ██▒▒█░ █ ░█ ▒██  ▀█▄  ▓██ ░▄█ ▒
░▓█▄   ▌▒██▀▀█▄  ▒██   ██░░█░ █ ░█ ░██▄▄▄▄██ ▒██▀▀█▄  
░▒████▓ ░██▓ ▒██▒░ ████▓▒░░░██▒██▓  ▓█   ▓██▒░██▓ ▒██▒
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒▓ ░▒▓░
 ░ ▒  ▒   ░▒ ░ ▒░  ░ ▒ ▒░   ▒ ░ ░    ▒   ▒▒ ░  ░▒ ░ ▒░
 ░ ░  ░   ░░   ░ ░ ░ ░ ▒    ░   ░    ░   ▒     ░░   ░ 
   ░       ░         ░ ░      ░          ░  ░   ░     
{Fore.YELLOW}Termux Advanced Bug Bounty Scanner v3.2
{Fore.RED}=============================================
"""

class PayloadManager:
    def __init__(self):
        self.payload_dir = "payloads"
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        payload_db = {}
        try:
            if not os.path.exists(self.payload_dir):
                print(f"{Fore.RED}[!] Payload folder '{self.payload_dir}' not found.")
                sys.exit(1)
            with open(f"{self.payload_dir}/ssrf/internal.json") as f:
                payload_db['ssrf'] = json.load(f)
            for vuln_type in ['xss', 'sqli']:
                with open(f"{self.payload_dir}/{vuln_type}.json") as f:
                    payload_db[vuln_type] = json.load(f)
        except Exception as e:
            print(f"{Fore.RED}Error loading payloads: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)
        return payload_db

    def get_payloads(self, vulnerability: str) -> list:
        return self.payloads.get(vulnerability, [])

class AdvancedScanner:
    def __init__(self, target_url, config=None):
        self.target = target_url
        self.default_config = {
            'max_threads': 5,
            'rate_limit': 1.2,
            'timeout': 15,
            'user_agents': [
                'Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0',
                'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Mobile Safari/537.36'
            ]
        }
        self.config = self.default_config.copy()
        if config:
            self.config.update(config)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self._random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        self.parameters = []
        self.vulnerabilities = []
        self.payload_manager = PayloadManager()
        
        if self.config.get('proxy'):
            self.session.proxies.update({'http': self.config['proxy']})

    def _random_user_agent(self):
        return random.choice(self.config['user_agents'])

    def discover_parameters(self):
        try:
            response = self.session.get(self.target, timeout=self.config['timeout'])
            self.parameters = list(parse_qs(urlparse(self.target).query).keys())
            return True
        except Exception as e:
            print(f"{Fore.RED}[-] Parameter discovery failed: {str(e)}{Style.RESET_ALL}")
            return False

    def scan(self, module='all'):
        if not self.discover_parameters():
            return False

        modules = {
            'xss': self._scan_xss,
            'sqli': self._scan_sqli,
            'ssrf': self._scan_ssrf,
            'all': self._scan_all
        }
        
        try:
            scanner_func = modules.get(module, self._scan_all)
            scanner_func()
            return True
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Scan interrupted{Style.RESET_ALL}")
            return False

    def _scan_all(self):
        self._scan_xss()
        self._scan_sqli()
        self._scan_ssrf()

    def _scan_xss(self):
        self._run_scan('xss', self._check_xss)

    def _scan_sqli(self):
        self._run_scan('sqli', self._check_sqli)

    def _scan_ssrf(self):
        self._run_scan('ssrf', self._check_ssrf)

    def _run_scan(self, vuln_type, check_func):
        payloads = self.payload_manager.get_payloads(vuln_type)
        if not payloads:
            print(f"{Fore.YELLOW}[!] No {vuln_type.upper()} payloads found{Style.RESET_ALL}")
            return

        total_tests = len(payloads) * len(self.parameters)
        progress_desc = f"{Fore.CYAN}Scanning {vuln_type.upper()}{Style.RESET_ALL}"
        
        with ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
            futures = []
            for payload in payloads:
                for param in self.parameters:
                    futures.append(executor.submit(
                        check_func,
                        param,
                        payload
                    ))
                    time.sleep(self.config['rate_limit'])

            with tqdm(total=total_tests, desc=progress_desc, unit="test") as pbar:
                for future in futures:
                    result = future.result()
                    if result:
                        self.vulnerabilities.append(result)
                    pbar.update(1)

    def _check_xss(self, param, payload):
        test_url = self._inject_payload(param, payload['payload'])
        try:
            response = self.session.get(test_url, timeout=self.config['timeout'])
            detection_points = self._analyze_reflection(response, payload['payload'])
            
            if detection_points['score'] > 40:
                return {
                    'type': 'XSS',
                    'param': param,
                    'payload': payload['payload'],
                    'url': test_url,
                    'confidence': min(100, detection_points['score'] * 10),
                    'evidence': detection_points['evidence']
                }
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[!] XSS test error: {str(e)}{Style.RESET_ALL}")
        return None

    def _check_sqli(self, param, payload):
        test_url = self._inject_payload(param, payload['payload'])
        try:
            response = self.session.get(test_url, timeout=self.config['timeout'])
            if self._detect_sqli(response):
                return {
                    'type': 'SQLi',
                    'param': param,
                    'payload': payload['payload'],
                    'url': test_url,
                    'confidence': 80,
                    'evidence': "Database error detected"
                }
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[!] SQLi test error: {str(e)}{Style.RESET_ALL}")
        return None

    def _check_ssrf(self, param, payload):
        test_url = self._inject_payload(param, payload['payload'])
        try:
            response = self.session.get(test_url, timeout=self.config['timeout'])
            if self._detect_ssrf(response):
                return {
                    'type': 'SSRF',
                    'param': param,
                    'payload': payload['payload'],
                    'url': test_url,
                    'confidence': 90,
                    'evidence': "SSRF indicators detected"
                }
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[!] SSRF test error: {str(e)}{Style.RESET_ALL}")
        return None

    def _inject_payload(self, param, payload_str):
        parsed = urlparse(self.target)
        query = parse_qs(parsed.query)
        query[param] = payload_str
        return parsed._replace(query=urlencode(query, doseq=True)).geturl()

    def _analyze_reflection(self, response, payload):
        detection = {
            'body': payload in response.text,
            'header': any(payload in value for value in response.headers.values()),
            'status_code': response.status_code == 200,
            'score': 0
        }
        
        detection['score'] = sum([
            40 if detection['body'] else 0,
            30 if detection['header'] else 0,
            20 if detection['status_code'] else 0
        ])
        
        evidence = []
        if detection['body']:
            evidence.append("Reflected in body")
        if detection['header']:
            evidence.append("Reflected in headers")
            
        detection['evidence'] = " | ".join(evidence)
        return detection

    def _detect_sqli(self, response):
        sqli_errors = [
            'SQL syntax', 'mysql_fetch', 'syntax error',
            'unclosed quotation', 'pg_query', 'ORA-'
        ]
        return any(error in response.text for error in sqli_errors)

    def _detect_ssrf(self, response):
        ssrf_indicators = [
            "EC2 Metadata", "root:x:0:0", "AWS_SECRET",
            "Metadata Service", "Internal Server Error",
            "Connection refused", "Redis"
        ]
        return any(indicator in response.text for indicator in ssrf_indicators)

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Bug Bounty Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameters")
    parser.add_argument("-m", "--module", choices=["xss", "sqli", "ssrf", "all"], default="all", help="Scan module")
    parser.add_argument("--proxy", help="Optional HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()

    config = {
        "proxy": args.proxy,
        "verbose": args.verbose
    }

    scanner = AdvancedScanner(args.url, config=config)
    success = scanner.scan(module=args.module)
    
    if success:
        print(f"\n{Fore.GREEN}[+] Scan completed. Found {len(scanner.vulnerabilities)} potential issues.{Style.RESET_ALL}")
        for vuln in scanner.vulnerabilities:
            print(f"{Fore.YELLOW}Type: {vuln['type']} | Param: {vuln['param']} | Payload: {vuln['payload']}\nURL: {vuln['url']}\nEvidence: {vuln['evidence']}\nConfidence: {vuln['confidence']}%{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
