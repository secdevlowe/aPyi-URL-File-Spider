import requests
import hashlib
import argparse
import time

# API Keys (Replace with your own)
VT_API_KEY = "your_virustotal_api_key"
HA_API_KEY = "your_hybridanalysis_api_key"
URLSCAN_API_KEY = "your_urlscan_api_key"

# Scan a file with VirusTotal
def scan_file_virustotal(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    
    with open(file_path, "rb") as file:
        files = {"file": file}
        response = requests.post(url, headers=headers, files=files)
    
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.text}

# Check file hash on VirusTotal
def check_hash_virustotal(file_path):
    with open(file_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.text}

# Scan a URL with VirusTotal
def scan_url_virustotal(url_to_scan):
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url_to_scan}

    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.text}

# Scan URL with URLScan.io
def scan_url_urlscan(url_to_scan):
    url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": url_to_scan, "visibility": "public"}

    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.text}

# Scan a file with HybridAnalysis
def scan_file_hybridanalysis(file_path):
    url = "https://www.hybrid-analysis.com/api/v2/submit/file"
    headers = {"api-key": HA_API_KEY, "User-Agent": "Falcon Sandbox"}
    
    with open(file_path, "rb") as file:
        files = {"file": file}
        response = requests.post(url, headers=headers, files=files)
    
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.text}

# CLI Parser
def main():
    parser = argparse.ArgumentParser(description="Scan files and URLs with security tools.")
    parser.add_argument("-f", "--file", help="File path to scan")
    parser.add_argument("-u", "--url", help="URL to scan")
    args = parser.parse_args()

    if args.file:
        print("[*] Scanning file with VirusTotal...")
        vt_result = scan_file_virustotal(args.file)
        print(vt_result)

        print("[*] Checking file hash with VirusTotal...")
        vt_hash_result = check_hash_virustotal(args.file)
        print(vt_hash_result)

        print("[*] Scanning file with HybridAnalysis...")
        ha_result = scan_file_hybridanalysis(args.file)
        print(ha_result)

    if args.url:
        print("[*] Scanning URL with VirusTotal...")
        vt_url_result = scan_url_virustotal(args.url)
        print(vt_url_result)

        print("[*] Scanning URL with URLScan.io...")
        urlscan_result = scan_url_urlscan(args.url)
        print(urlscan_result)

if __name__ == "__main__":
    main()
