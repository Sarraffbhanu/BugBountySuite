# 🐞 BugBountySuite [![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Advanced bug bounty toolkit optimized for Termux and mobile security research.

![Banner](https://i.imgur.com/5XzZJ9C.png)

## Features 🔍

- **XSS Scanner** - Detect reflected & stored XSS vulnerabilities
- **SQLi Detector** - Identify SQL injection points with error-based detection
- **Smart Parameter Discovery** - Auto-find parameters from HTML forms & URLs
- **Multi-threaded Scanning** - Fast parallel testing with configurable workers
- **Confidence Scoring** - Risk assessment for found vulnerabilities
- **Termux Optimized** - Works seamlessly on Android devices

## Requirements 📦

- Termux (Android 8+ recommended)
- Python 3.8+
- Internet connection

## Installation 📥

```bash
# 1. Update packages
pkg update && pkg upgrade -y

# 2. Install dependencies
pkg install python git -y

# 3. Clone repository
git clone https://github.com/Sarraffbhanu/BugBountySuite.git
cd BugBountySuite

# 4. Install Python requirements
pip install -r requirements.txt
