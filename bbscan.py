#!/data/data/com.termux/files/usr/bin/python
import argparse
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

import requests
from colorama import Fore, Style, init
from tqdm import tqdm

# Local imports
from core.discovery import ParameterDiscover
from core.payload_manager import PayloadManager

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
{Fore.YELLOW}Termux Advanced Bug Bounty Scanner v3.1
{Fore.RED}=============================================
"""

class AdvancedScanner:
    def __init__(self, target_url, config=None):
        self.target = target_url
        
        # Default configuration
        self.default_config = {
            'max_threads': 5,
            'rate_limit': 1.2,
            'timeout': 15,
            'user_agents': [
                'Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0',
                'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Mobile Safari/537.36'
            ]
        }
        
        # Merge user config with defaults
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
            self.parameters = ParameterDiscover.from_response(response.text)
            
            # Add parameters from URL
            url_params = ParameterDiscover.from_url(self.target)
            self.parameters.extend(url_params)
            
            # Remove duplicates
            self.parameters = list(set(self.parameters))
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
            'all': self._scan_all
        }
        
        try:
            scanner_func = modules.get(module, self._scan_all)
            scanner_func()
            return True
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
            return False

    def _scan_all(self):
        self._scan_xss()
        self._scan_sqli()

    def _scan_xss(self):
        self._run_scan('xss', self._check_xss)

    def _scan_sqli(self):
        self._run_scan('sqli', self._check_sqli)

    def _run_scan(self, vuln_type, check_func):
        payloads = self.payload_manager.get_payloads(vuln_type)
        if not payloads:
            print(f"{Fore.YELLOW}[!] No payloads found for {vuln_type}{Style.RESET_ALL}")
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
                print(f"{Fore.YELLOW}[!] Error testing {param}: {str(e)}{Style.RESET_ALL}")
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
                print(f"{Fore.YELLOW}[!] Error testing {param}: {str(e)}{Style.RESET_ALL}")
        return None

    def _inject_payload(self, param, payload):
        parsed = urlparse(self.target)
        query = parse_qs(parsed.query)
        query[param] = payload
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
            evidence.append("Payload reflected in response body")
        if detection['header']:
            evidence.append("Payload reflected in headers")
            
        detection['evidence'] = " | ".join(evidence)
        return detection

    def _detect_sqli(self, response):
        sqli_errors = [
            'SQL syntax',
            'mysql_fetch',
            'syntax error',
            'unclosed quotation',
            'pg_query'
        ]
        return any(error in response.text for error in sqli_errors)

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description=f"{Fore.GREEN}Advanced Vulnerability Scanner for Termux{Style.RESET_ALL}",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-u', '--url', required=True, help="Target URL")
    parser.add_argument('-m', '--module', choices=['xss', 'sqli', 'all'], 
                      default='all', help="Scan modules")
    parser.add_argument('-o', '--output', help="Output file (JSON/HTML)")
    parser.add_argument('-p', '--proxy', help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Show detailed output")
    parser.add_argument('-t', '--threads', type=int, default=5, 
                      help="Maximum concurrent threads (default: 5)")
    
    args = parser.parse_args()
    
    config = {
        'max_threads': args.threads,
        'verbose': args.verbose,
        'proxy': args.proxy
    }
    
    scanner = AdvancedScanner(args.url, config)
    
    print(f"{Fore.MAGENTA}[*] Target URL: {args.url}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}[*] Using {args.threads} threads with {args.module} module{Style.RESET_ALL}")
    
    if scanner.scan(args.module):
        print(f"\n{Fore.CYAN}[+] Scan completed. Found {len(scanner.vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
        
        if scanner.vulnerabilities:
            for vuln in scanner.vulnerabilities:
                print(f"""
{Fore.YELLOW}=== {vuln['type']} Vulnerability ==={Style.RESET_ALL}
{Fore.WHITE}Parameter: {vuln['param']}
{Fore.CYAN}Payload: {vuln['payload']}
{Fore.GREEN}Confidence: {vuln['confidence']}%
{Fore.BLUE}Evidence: {vuln['evidence']}
{Fore.MAGENTA}URL: {vuln['url']}
{'-'*60}""")
        else:
            print(f"{Fore.YELLOW}[!] No vulnerabilities found{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[-] Scan failed{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
