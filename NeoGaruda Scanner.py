#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Neo-Garud4 v3.0
# Author : NeoGarud4
# Note   : Toolkit recon + vuln scanner + report generator (TXT + HTML)
#

import os
import re
import sys
import socket
import json
import requests
import whois
import dns.resolver
from datetime import datetime
from prettytable import PrettyTable
from colorama import Fore, Style, init

init(autoreset=True)

# ===============================
# ASCII ART HEADER
# ===============================
ASCII_ART = r"""
 _   _             ____                  _       
| \ | | ___   ___ / ___|  __ _ _   _  __| |_   _ 
|  \| |/ _ \ / _ \ |  _  / _` | | | |/ _` | | | |
| |\  | (_) |  __/ |_| | (_| | |_| | (_| | |_| |
|_| \_|\___/ \___|\____| \__,_|\__,_|\__,_|\__, |
                                           |___/ 
         Neo-Garud4 v3.0  |  By Mr.Seven
"""

# ===============================
# UTILS
# ===============================
def normalize_url(target):
    """Hapus http/https dari target"""
    return target.replace("http://", "").replace("https://", "").strip("/")

def save_txt_report(filename, scan_results):
    with open(filename, "w") as f:
        f.write("Neo-Garud4 v3.0 - Report\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write("="*60 + "\n\n")
        for section, data in scan_results.items():
            f.write(f"[{section}]\n")
            f.write(str(data) + "\n\n")

def save_html_report(filename, scan_results):
    with open(filename, "w") as f:
        f.write("<html><head><title>Neo-Garud4 Report</title></head><body>")
        f.write("<h1>Neo-Garud4 v3.0 - Report</h1>")
        f.write(f"<p>Generated: {datetime.now()}</p><hr>")
        for section, data in scan_results.items():
            f.write(f"<h2>{section}</h2>")
            f.write("<pre>" + str(data) + "</pre>")
        f.write("</body></html>")

# ===============================
# WHOIS LOOKUP
# ===============================
def whois_lookup(domain):
    try:
        data = whois.whois(domain)
        return {
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers
        }
    except Exception as e:
        return {"error": str(e)}

# ===============================
# DNS & IP RESOLVER
# ===============================
def dns_resolve(domain):
    result = {}
    try:
        result["A"] = [str(r) for r in dns.resolver.resolve(domain, "A")]
    except:
        result["A"] = []
    try:
        result["MX"] = [str(r) for r in dns.resolver.resolve(domain, "MX")]
    except:
        result["MX"] = []
    try:
        result["NS"] = [str(r) for r in dns.resolver.resolve(domain, "NS")]
    except:
        result["NS"] = []
    return result

# ===============================
# PORT SCANNER
# ===============================
def port_scan(domain):
    common_ports = [21,22,23,25,53,80,110,143,443,3306,8080,8443]
    open_ports = []
    ip = socket.gethostbyname(domain)
    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((ip, port))
            open_ports.append(port)
            s.close()
        except:
            pass
    return open_ports

# ===============================
# CMS DETECTOR
# ===============================
def detect_cms(url):
    cms = "Unknown"
    try:
        r = requests.get("http://" + url, timeout=5)
        if "wp-content" in r.text or "WordPress" in r.text:
            cms = "WordPress"
        elif "Joomla" in r.text:
            cms = "Joomla"
        elif "Drupal" in r.text:
            cms = "Drupal"
        elif "Laravel" in r.text:
            cms = "Laravel"
        elif "Flask" in r.text:
            cms = "Flask"
    except:
        pass
    return cms

# ===============================
# BASIC SQLi CHECK
# ===============================
def check_sqli(url):
    payload = "' OR '1'='1"
    try:
        r = requests.get(f"http://{url}?id={payload}", timeout=5)
        if "mysql" in r.text.lower() or "syntax" in r.text.lower():
            return "Vulnerable"
    except:
        pass
    return "Not Vulnerable"

# ===============================
# XSS DEEP SCANNER
# ===============================
def xss_deep_scan(url):
    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>"
    ]
    findings = []
    for p in payloads:
        test_url = f"http://{url}?q={requests.utils.quote(p)}"
        try:
            r = requests.get(test_url, timeout=5)
            if p.strip("<>\"") in r.text:
                findings.append({
                    "payload": p,
                    "url": test_url
                })
        except:
            continue
    return findings

# ===============================
# GEOIP LOOKUP
# ===============================
def geoip_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        resp = requests.get(f"http://ip-api.com/json/{ip}").json()
        return {
            "ip": ip,
            "country": resp.get("country"),
            "region": resp.get("regionName"),
            "city": resp.get("city"),
            "isp": resp.get("isp")
        }
    except:
        return {}

# ===============================
# MAIN
# ===============================
def main():
    if len(sys.argv) < 3 or sys.argv[1] != "-u":
        print(Fore.RED + "Usage: python neo_garud4.py -u <target>")
        sys.exit(1)

    target = normalize_url(sys.argv[2])
    print(Fore.CYAN + ASCII_ART)
    print(Fore.YELLOW + f"[~] Scanning target: {target}\n")

    results = {}

    # WHOIS
    print(Fore.GREEN + "[*] WHOIS Lookup...")
    results["WHOIS"] = whois_lookup(target)

    # DNS
    print(Fore.GREEN + "[*] DNS & IP Resolve...")
    results["DNS"] = dns_resolve(target)

    # PORTS
    print(Fore.GREEN + "[*] Port Scanning...")
    results["Open Ports"] = port_scan(target)

    # CMS
    print(Fore.GREEN + "[*] CMS Detection...")
    results["CMS"] = detect_cms(target)

    # SQLi
    print(Fore.GREEN + "[*] SQL Injection Check...")
    results["SQLi"] = check_sqli(target)

    # XSS
    print(Fore.GREEN + "[*] XSS Deep Scan...")
    results["XSS"] = xss_deep_scan(target)

    # GEOIP
    print(Fore.GREEN + "[*] GeoIP Lookup...")
    results["GeoIP"] = geoip_lookup(target)

    # SHOW TABLE
    table = PrettyTable(["Scan Type", "Result"])
    for k,v in results.items():
        table.add_row([k, str(v)[:80] + ("..." if len(str(v))>80 else "")])
    print(Fore.CYAN + str(table))

    # SAVE REPORT
    os.makedirs("reports", exist_ok=True)
    txt_file = f"reports/report_{target}_{datetime.now().strftime('%Y%m%d%H%M')}.txt"
    html_file = f"reports/report_{target}_{datetime.now().strftime('%Y%m%d%H%M')}.html"
    save_txt_report(txt_file, results)
    save_html_report(html_file, results)
    print(Fore.YELLOW + f"\n[+] Report saved: {txt_file}, {html_file}")

if __name__ == "__main__":
    main()
