#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Neo Garuda v1.0
# Made by NeoGarud4

import socket
import requests
import os
from tabulate import tabulate
try:
    from fpdf import FPDF
    PDF_ENABLED = True
except ImportError:
    PDF_ENABLED = False

# =============================
# ASCII ART
# =============================
ASCII_ART = r"""
███╗   ██╗███████╗ ██████╗      ██████╗  █████╗ ██████╗ ██╗   ██╗
████╗  ██║██╔════╝██╔═══██╗    ██╔════╝ ██╔══██╗██╔══██╗╚██╗ ██╔╝
██╔██╗ ██║█████╗  ██║   ██║    ██║  ███╗███████║██████╔╝ ╚████╔╝ 
██║╚██╗██║██╔══╝  ██║   ██║    ██║   ██║██╔══██║██╔═══╝   ╚██╔╝  
██║ ╚████║███████╗╚██████╔╝    ╚██████╔╝██║  ██║██║        ██║   
╚═╝  ╚═══╝╚══════╝ ╚═════╝      ╚═════╝ ╚═╝  ╚═╝╚═╝        ╚═╝   
                 >> Neo Garuda v1.0 <<
"""

# =============================
# FUNCTIONS
# =============================

def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return "Tidak dapat resolve"

def check_website_status(url):
    try:
        r = requests.get(url, timeout=5)
        return f"{r.status_code} OK"
    except Exception:
        return "Tidak dapat diakses"

def get_server_headers(url):
    try:
        r = requests.get(url, timeout=5)
        return r.headers.get("Server", "Tidak diketahui")
    except Exception:
        return "Gagal mengambil headers"

def generate_report(data, filename="neo_garuda_report"):
    # TXT Report
    txt_file = f"{filename}.txt"
    with open(txt_file, "w") as f:
        f.write("Neo Garuda Scan Report\n")
        f.write("=======================\n\n")
        for row in data:
            f.write(f"{row[0]}: {row[1]}\n")
    print(f"[+] Report saved: {txt_file}")

    # PDF Report (optional)
    if PDF_ENABLED:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, "Neo Garuda Scan Report", ln=True, align="C")
        pdf.ln(10)
        for row in data:
            pdf.cell(200, 10, f"{row[0]}: {row[1]}", ln=True)
        pdf_file = f"{filename}.pdf"
        pdf.output(pdf_file)
        print(f"[+] PDF Report saved: {pdf_file}")
    else:
        print("[!] PDF not generated (install fpdf for PDF output)")

# =============================
# MAIN
# =============================
def main():
    os.system("clear")
    print(ASCII_ART)
    print("Author: Mr.Seven | Neo Garuda Security Toolkit\n")

    target = input("[?] Masukkan domain atau URL target: ").strip()
    if target.startswith("http://") or target.startswith("https://"):
        url = target
        domain = target.split("//")[1].split("/")[0]
    else:
        domain = target
        url = "http://" + target

    ip_address = resolve_ip(domain)
    status = check_website_status(url)
    server = get_server_headers(url)

    results = [
        ["Target Domain", domain],
        ["Target IP", ip_address],
        ["Website Status", status],
        ["Server Header", server],
    ]

    print("\n=== Scan Results ===\n")
    print(tabulate(results, headers=["Item", "Result"], tablefmt="grid"))

    generate_report(results, "neo_garuda_scan")

if __name__ == "__main__":
    main()
