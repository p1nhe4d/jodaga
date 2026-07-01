# JODAGA - Joint Offensive Detection & Advanced Global Assessment

Advanced Recon Scanner for Security Professionals

## Features

- **Subdomain Enumeration** - DNS brute-force with multiple record types
- **Port Scanning** - Fast asynchronous TCP port scanner
- **Tech Stack Detection** - Identify servers, CMS, CDN, and frameworks
- **Security Headers Check** - Scan for missing security headers
- **Path Brute-Force** - Directory and file discovery with wordlists
- **Screenshots** - Visual documentation of discovered pages
- **Proxy Support** - Route traffic through Burp Suite or other proxies
- **Multi-Target** - Scan multiple domains from a file
- **JSON Output** - Structured results for further analysis

## Installation

# Clone the repository
- git clone https://github.com/p1nhe4d/jodaga.git

- cd jodaga

# Install dependencies
pip install -r requirements.txt

# Install Playwright for screenshots (optional)
playwright install chromium


## Usage

# Basic scan
python3 jodaga.py -t example.com -w wordlist.txt

# With proxy (Burp Suite)
python3 jodaga.py -t example.com -w wordlist.txt --proxy http://127.0.0.1:8080

# With screenshots
python3 jodaga.py -t example.com -w wordlist.txt --screenshots

# Multi-target scan
python3 jodaga.py -t targets.txt -w wordlist.txt -o results.json

# Custom port range
python3 jodaga.py -t example.com -w wordlist.txt -p 80,443,8080





# Disclaimer
This tool is for authorized security testing and educational purposes only. Use only on systems you own or have explicit permission to test.
