#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Recon Analyst Pro - by @hatemaliyan
⚔️ Automated Recon & Analysis Tool

This script performs:
- Subdomain enumeration (subfinder)
- Tech stack fingerprinting (httpx)
- GraphQL introspection detection
- CDN detection
"""

import os
import sys
import json
import socket
import time
import requests
import subprocess

# Settings
TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 (Recon Analyst Pro)"}

class Color:
    G = '\033[92m'  # Green
    Y = '\033[93m'  # Yellow
    R = '\033[91m'  # Red
    B = '\033[94m'  # Blue
    END = '\033[0m'

def banner():
    print(rf"""{Color.B}
   ____                           _         _          _     
  |  _ \ ___  ___ ___  _ __ ___ | |__  ___| |_ ___   (_)___ 
  | |_) / _ \/ __/ _ \| '_ ` _ \| '_ \/ __| __/ _ \  | / __|
  |  _ <  __/ (_| (_) | | | | | | |_) \__ \ || (_) | | \__ \
  |_| \_\___|\___\___/|_| |_| |_|_.__/|___/\__\___/  |_|___/
    Recon Analyst Pro // by @hatemaliyan // ⚔️ Automated Recon & Analysis
{Color.END}""")

def resolve(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"{Color.G}[IP] {domain} → {ip}{Color.END}")
        return ip
    except:
        print(f"{Color.R}[!] Failed to resolve domain.{Color.END}")
        return None

def detect_cdn(domain):
    cdns = ['cloudflare', 'akamai', 'imperva', 'sucuri', 'fastly', 'incapsula', 'cloudfront']
    try:
        ip = resolve(domain)
        if not ip:
            return

        try:
            host = socket.gethostbyaddr(ip)[0]
            for c in cdns:
                if c in host.lower():
                    print(f"{Color.Y}[CDN] Detected: {c} via DNS ({host}){Color.END}")
                    return
        except:
            pass

        for proto in ["https", "http"]:
            try:
                r = requests.get(f"{proto}://{domain}", headers=HEADERS, timeout=TIMEOUT)
                for v in r.headers.values():
                    for c in cdns:
                        if c in v.lower():
                            print(f"{Color.Y}[CDN] Detected: {c} via Headers ({proto.upper()}){Color.END}")
                            return
            except:
                continue

        print(f"{Color.G}[CDN] No CDN detected{Color.END}")
    except Exception as e:
        print(f"{Color.R}[CDN] Error: {e}{Color.END}")

def run_httpx(domain):
    try:
        print(f"{Color.B}[HTTPX] Running subfinder and scanning subdomains...{Color.END}")
        subprocess.run(f"subfinder -d {domain} -silent -o temp_subs.txt", shell=True, check=True)
        time.sleep(2)

        result = subprocess.run(
            f"httpx -l temp_subs.txt -silent -json -title -tech-detect -status-code -web-server -path /graphql",
            shell=True, capture_output=True, text=True, timeout=300
        )
        os.remove('temp_subs.txt')
        lines = result.stdout.strip().splitlines()
        return [json.loads(l) for l in lines if l.strip()]
    except Exception as e:
        print(f"{Color.R}[HTTPX] Error: {e}{Color.END}")
        return []

def analyze_services(results):
    print(f"\n{Color.Y}=== Services Analysis ==={Color.END}")
    for r in results:
        url = r.get("url")
        status = r.get("status-code", 0) or "??"
        tech = ", ".join(r.get("tech", [])) or r.get("web-server", "")
        notes = []

        if "/admin" in url or "admin." in url:
            notes.append("⚙️ Admin")
        if "/auth" in url or "auth." in url:
            notes.append("🔐 Auth")
        if "graphql" in url:
            notes.append("🧬 GraphQL")
        if "/api" in url or "api." in url:
            notes.append("🔧 API")
        if "cdn." in url:
            notes.append("📦 CDN")
        if "dev." in url:
            notes.append("🧪 Dev")

        note_str = " | " + " ".join(notes) if notes else ""

        if status == 200:
            color = Color.G
        elif status == 403:
            color = Color.Y
        else:
            color = Color.R

        print(f"{color}[{status}] {url} - {tech}{note_str}{Color.END}")
        time.sleep(0.4)

def detect_graphql(results):
    print(f"\n{Color.B}[*] Detecting GraphQL endpoints...{Color.END}")
    for r in results:
        if "/graphql" in r["url"]:
            try:
                res = requests.post(r["url"], json={"query": "{__schema{types{name}}}"}, headers=HEADERS, timeout=TIMEOUT)
                if "data" in res.text:
                    print(f"{Color.Y}[GRAPHQL] {r['url']} → Introspection Enabled! 🧬{Color.END}")
            except:
                pass
            time.sleep(0.4)

def main():
    if len(sys.argv) != 2:
        print(f"{Color.R}Usage: python3 recon.py domain.com{Color.END}")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()
    banner()
    resolve(domain)
    time.sleep(1)
    detect_cdn(domain)
    time.sleep(1)
    results = run_httpx(domain)
    if results:
        analyze_services(results)
        detect_graphql(results)
    else:
        print(f"{Color.R}[-] No active subdomains found.{Color.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{Color.R}\n[!] Interrupted by user.{Color.END}")
    except Exception as e:
        print(f"{Color.R}[!] Critical Error: {str(e)}{Color.END}")
