# aPyi-URL-File-Spider
A python script that scans files and URLs against VirusTotal, Hybrid-Analysis, including VirusTotal, HybridAnalysis, and URLScan.io. It leverages their available APIs to investigate the given input for malicious behavior.

---

## Features

✅ Scan files and URLs with VirusTotal
✅ Query HybridAnalysis for known threats
✅ Use URLScan.io to check URLs for phishing/malware
✅ Save results for further analysis



---

### Installation

1. Install dependencies:

pip install requests


2. Obtain API keys:

VirusTotal API Key
How to find your API key
Sign in into your account and you will find your public API in the corresponding menu item under your user name.
https://docs.virustotal.com/docs/api-overview

HybridAnalysis API Key
How do I obtain an API key?
Please visit your profile page at the top right menu and navigate to the API key tab. Then press the 'Create API key' button as following: Generate API key
https://www.hybrid-analysis.com/docs/api/v2

URLScan.io API Key
To use the APIs, you should create a user account, attach an API key and supply it when calling the API. Unauthenticated users only received minor quotas for API calls
https://urlscan.io/docs/api/


---


### Usage

Scan a File

python scanner.py -f malware.exe

Scan a URL

python scanner.py -u "http://suspicious-site.com"


---
