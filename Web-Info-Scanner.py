#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ICSF Recon Scanner v4 — Ultra Brutal Edition
-------------------------------------------
Brutal Recon Suite (Educational / Authorized Use Only)

Features:
- HTTP(S) header + body fingerprinting (techs, JS assets)
- SSL/TLS certificate analysis (subject, issuer, validity)
- WHOIS lookup (python-whois)
- DNS records enumeration (A, AAAA, MX, NS, TXT, CNAME)
- Subdomain enumeration (wordlist)
- Directory brute-force (wordlist; rate-limited; safe defaults)
- Security header checks (CSP, HSTS, X-Frame-Options, etc.)
- Geo-IP lookup (ipinfo.io)
- Reverse DNS
- TCP port scan (ports 1-1024 by default; threaded & rate-limited)
- UDP port scan (ports 1-1024; best-effort; may be slow)
- Save comprehensive report on Desktop (Windows-friendly)
- PyInstaller-compatible resource_path() for bundling wordlists
- Safety prompts, rate limiting, and polite delays

Dependencies:
pip install requests python-whois dnspython beautifulsoup4 colorama pyopenssl
(If packaging: pyinstaller)
"""

# --------- imports ----------
import os
import sys
import socket
import ssl
import json
import time
import ctypes
import datetime
import threading
import concurrent.futures
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
from colorama import init, Fore, Style

# suppress insecure request warnings only if deliberately using verify=False
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# init colors
init(autoreset=True)

# -------------------------
# Configuration (tweak with care)
# -------------------------
USER_AGENT = "ICSF-Recon-v4 (edu; authorized-testing-only)"
REQUEST_TIMEOUT = 8             # HTTP request timeout
TCP_TIMEOUT = 1.2               # TCP connect timeout per port
UDP_TIMEOUT = 2.0               # UDP probe timeout
THREADS_TCP = 200               # thread pool size for TCP scan (adjust to machine/network)
THREADS_UDP = 120               # threads for UDP probing
SLEEP_BETWEEN_HTTP = 0.12       # polite delay between HTTP-based calls
SLEEP_SUBENUM = 0.08            # delay between subdomain DNS checks
VERIFY_TLS = True               # set False to ignore cert verification (not recommended)
MAX_DIR_PROBES = 200            # cap directories checked by default to avoid abuse
TCP_PORT_RANGE = range(1, 1025) # full 1-1024
UDP_PORT_RANGE = range(1, 1025) # full 1-1024 (best-effort)
SUBDOMAIN_WORDLIST_FILE = "SUBDOMAIN_WORDLIST.txt"  # optional
DIR_WORDLIST_FILE = "DIR_WORDLIST.txt"              # optional
GEOIP_API = "https://ipinfo.io/{ip}/json"

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "expect-ct",
]

# Light default wordlist (if no external file provided)
DEFAULT_SUBS = ["www", "api", "admin", "dev", "staging", "test", "mail", "webmail", "ftp", "portal", "beta", "cdn"]
DEFAULT_DIRS = ["admin", "login", "dashboard", "uploads", "api", "assets", "config", "wp-admin", "server-status"]

# Thread-safe print
print_lock = threading.Lock()
def safe_print(*a, **k):
    with print_lock:
        print(*a, **k)

# -------------------------
# Resource path (PyInstaller-safe)
# -------------------------
def resource_path(rel_path):
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, rel_path)
    return os.path.join(os.path.abspath("."), rel_path)

# -------------------------
# Desktop path (Windows robust)
# -------------------------
def get_desktop_path():
    if os.name == "nt":
        try:
            from ctypes import wintypes, windll
            buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
            # CSIDL_DESKTOPDIRECTORY = 0x10
            res = windll.shell32.SHGetFolderPathW(None, 0x10, None, 0, buf)
            if res == 0 and buf.value:
                return buf.value
        except Exception:
            pass
        up = os.environ.get("USERPROFILE")
        if up:
            return os.path.join(up, "Desktop")
    # fallback for mac/linux
    return os.path.join(Path.home(), "Desktop")

# -------------------------
# Basic network helpers
# -------------------------
def ensure_url_scheme(url):
    p = urlparse(url)
    if not p.scheme:
        return "http://" + url
    return url

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        return None

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# -------------------------
# HTTP fetch & analysis
# -------------------------
def fetch_http(url, verify_tls=VERIFY_TLS, timeout=REQUEST_TIMEOUT):
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=verify_tls)
        return r
    except Exception as e:
        raise

def analyze_html_tech(html, headers):
    soup = BeautifulSoup(html or "", "html.parser")
    techs = set()
    # meta generator
    gen = soup.find("meta", attrs={"name":"generator"})
    if gen and gen.get("content"):
        techs.add(gen["content"])
    txt = (html or "").lower()
    sigs = {
        "WordPress": ["wp-content","wp-includes"],
        "Joomla": ["joomla"],
        "Drupal": ["drupal"],
        "React.js": ["react","__REACT_DEVTOOLS_GLOBAL_HOOK__","data-reactroot"],
        "Angular": ["ng-app","angular"],
        "Vue.js": ["vue","__VUE_DEVTOOLS_GLOBAL_HOOK__"],
        "Next.js": ["/_next/","next"],
        "Nuxt.js": ["/_nuxt/","nuxt"],
        "Laravel": ["laravel"],
        "Express.js": ["express"],
    }
    for name, keys in sigs.items():
        for k in keys:
            if k in txt:
                techs.add(name)
                break
    # headers
    xp = headers.get("X-Powered-By")
    if xp:
        techs.add(xp)
    server = headers.get("Server")
    if server:
        techs.add(server)
    return ", ".join(sorted(techs)) if techs else "Unbekannt"

def extract_js_assets(html):
    soup = BeautifulSoup(html or "", "html.parser")
    js = []
    for s in soup.find_all("script"):
        src = s.get("src")
        if src:
            js.append(src)
    return js

def check_security_headers(headers):
    d = {}
    lower_headers = {k.lower(): v for k,v in headers.items()}
    for h in SECURITY_HEADERS:
        d[h] = lower_headers.get(h) or None
    return d

# -------------------------
# SSL/TLS analysis
# -------------------------
def get_ssl_info(hostname, port=443, timeout=6):
    info = {}
    try:
        ctx = ssl.create_default_context()
        if not VERIFY_TLS:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        info['subject'] = cert.get('subject')
        info['issuer'] = cert.get('issuer')
        info['notBefore'] = cert.get('notBefore')
        info['notAfter'] = cert.get('notAfter')
        info['SAN'] = [v for (k,v) in cert.get('subjectAltName',()) if k.lower()=='dns']
    except Exception as e:
        info['error'] = str(e)
    return info

# -------------------------
# WHOIS
# -------------------------
def do_whois(domain):
    try:
        w = whois.whois(domain)
        # transform to JSON-serializable dict
        out = {}
        for k,v in w.items():
            try:
                out[k] = str(v)
            except Exception:
                out[k] = repr(v)
        return out
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# DNS records
# -------------------------
def get_dns_records(domain, rtypes=("A","AAAA","MX","NS","TXT","CNAME")):
    out = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    for r in rtypes:
        try:
            ans = resolver.resolve(domain, r, raise_on_no_answer=False)
            if ans.rrset is None:
                out[r] = []
            else:
                out[r] = [str(a.to_text()) for a in ans]
        except Exception as e:
            out[r] = ["error: " + str(e)]
    return out

# -------------------------
# GeoIP
# -------------------------
def geoip_lookup(ip):
    try:
        r = requests.get(GEOIP_API.format(ip=ip), timeout=6)
        if r.status_code == 200:
            return r.json()
        return {"error": f"status {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# Subdomain enumeration (wordlist)
# -------------------------
def enumerate_subdomains(domain, wordlist=None, rate=SLEEP_SUBENUM):
    found = []
    if wordlist is None:
        wordlist = DEFAULT_SUBS
    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            socket.gethostbyname(fqdn)
            found.append(fqdn)
        except Exception:
            pass
        time.sleep(rate)
    return sorted(set(found))

# -------------------------
# Directory brute (safe & rate-limited)
# -------------------------
def directory_bruteforce(target_base, wordlist=None, max_checks=MAX_DIR_PROBES, delay=0.12):
    found = []
    if wordlist is None:
        wordlist = DEFAULT_DIRS
    count = 0
    for d in wordlist:
        if count >= max_checks:
            break
        url = target_base.rstrip("/") + "/" + d.lstrip("/")
        try:
            resp = requests.get(url, headers={"User-Agent":USER_AGENT}, timeout=REQUEST_TIMEOUT, verify=VERIFY_TLS, allow_redirects=True)
            if resp.status_code not in (404, 400, 401):  # 401 could be valid protected path
                found.append((url, resp.status_code))
        except Exception:
            pass
        count += 1
        time.sleep(delay)
    return found

# -------------------------
# Port scanning - TCP (threaded)
# -------------------------
def tcp_connect(ip, port, timeout=TCP_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((ip, port))
        s.close()
        return port if res == 0 else None
    except Exception:
        try:
            s.close()
        except:
            pass
        return None

def tcp_scan(ip, ports, threads=THREADS_TCP):
    open_ports = []
    ports = list(ports)
    if not ports:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, len(ports))) as ex:
        futures = {ex.submit(tcp_connect, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            try:
                res = fut.result()
                if res:
                    open_ports.append(res)
            except Exception:
                pass
    return sorted(open_ports)

# -------------------------
# UDP probe (best-effort)
# -------------------------
def udp_probe(ip, port, timeout=UDP_TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        if port == 53:
            # minimal DNS query (for example.com) - raw bytes
            dns_query = b'\xaa\xaa' + b'\x01\x00' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00'
            for part in b"example.com".split(b'.'):
                dns_query += bytes([len(part)]) + part
            dns_query += b'\x00' + b'\x00\x01' + b'\x00\x01'
            try:
                sock.sendto(dns_query, (ip, port))
                data, _ = sock.recvfrom(512)
                sock.close()
                return True
            except socket.timeout:
                sock.close()
                return False
            except Exception:
                sock.close()
                return False
        else:
            try:
                sock.sendto(b'\x00', (ip, port))
                data, _ = sock.recvfrom(512)
                sock.close()
                return True
            except socket.timeout:
                sock.close()
                return False
            except Exception:
                sock.close()
                return False
    except Exception:
        try:
            sock.close()
        except:
            pass
        return False

def udp_scan(ip, ports, threads=THREADS_UDP):
    open_ports = []
    ports = list(ports)
    if not ports:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, len(ports))) as ex:
        futures = {ex.submit(udp_probe, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)

# -------------------------
# JS asset analysis (search for endpoints)
# -------------------------
def analyze_js_for_endpoints(js_urls, base_url):
    endpoints = set()
    for src in js_urls:
        # skip full remote libs to save time unless same host or relative
        if src.startswith("http") and base_url not in src:
            continue
        # attempt to fetch small scripts (polite)
        js_url = src if src.startswith("http") else base_url.rstrip("/") + "/" + src.lstrip("/")
        try:
            r = requests.get(js_url, headers={"User-Agent":USER_AGENT}, timeout=REQUEST_TIMEOUT, verify=VERIFY_TLS)
            txt = r.text[:20000]  # limit
            # crude endpoint detection (api/, /graphql, fetch('/api', ...)
            for token in ["api/", "/graphql", "fetch(", "axios(", "/_next/", "/_nuxt/"]:
                if token in txt:
                    endpoints.add(token)
        except Exception:
            pass
        time.sleep(0.08)
    return sorted(endpoints)

# -------------------------
# Report writing
# -------------------------
def write_report(report_text, name_hint="icsf_report"):
    desktop = get_desktop_path()
    if not os.path.isdir(desktop):
        desktop = os.path.expanduser("~")
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    fname = f"{name_hint}_{ts}.txt"
    path = os.path.join(desktop, fname)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report_text)
        safe_print(Fore.MAGENTA + f"[+] Report saved to: {path}")
    except Exception as e:
        safe_print(Fore.RED + f"[!] Failed saving report: {e}")

# -------------------------
# Orchestration: scan target
# -------------------------
def scan_target_cli(input_target):
    target = ensure_url = ensure_url_scheme(input_target.strip())
    parsed = urlparse(ensure_url)
    host = parsed.hostname
    scheme = parsed.scheme
    base_url = f"{scheme}://{host}"
    safe_print(Fore.CYAN + f"[+] Starting ICSF Recon v4 on {host} ({ensure_url})")
    safe_print(Fore.YELLOW + "[!] Make sure you have explicit permission to scan this host. Proceeding in 5s (Ctrl+C to abort)...")
    time.sleep(5)

    report = []
    report.append(f"ICSF Recon v4 report - {datetime.datetime.now().isoformat()}")
    report.append(f"Target: {input_target}")
    report.append("-" * 80)

    # DNS resolution
    ip = resolve_host(host)
    if not ip:
        safe_print(Fore.RED + f"[!] DNS resolution failed for {host}. Aborting.")
        report.append(f"DNS resolution failed for {host}")
        write_report("\n".join(report), f"icsf_{host}")
        return
    report.append(f"Resolved IP: {ip}")

    # Reverse DNS
    rev = reverse_dns(ip)
    report.append(f"Reverse DNS: {rev or 'None'}")

    # GeoIP
    time.sleep(SLEEP_BETWEEN_HTTP)
    geo = geoip_lookup(ip)
    report.append("GeoIP: " + json.dumps(geo, indent=2, ensure_ascii=False))

    # WHOIS
    time.sleep(SLEEP_BETWEEN_HTTP)
    who = do_whois(host)
    report.append("WHOIS: " + json.dumps(who, indent=2, ensure_ascii=False))

    # DNS Records
    time.sleep(SLEEP_BETWEEN_HTTP)
    try:
        dns_recs = get_dns_records(host)
        report.append("DNS Records: " + json.dumps(dns_recs, indent=2, ensure_ascii=False))
    except Exception as e:
        report.append("DNS enumerate error: " + str(e))

    # Subdomain enumeration from file or default
    subs_wordlist = None
    try:
        path = resource_path(SUBDOMAIN_WORDLIST_FILE)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                subs_wordlist = [l.strip() for l in fh if l.strip()]
            safe_print(Fore.GREEN + f"[+] Loaded {len(subs_wordlist)} subdomain words from {SUBDOMAIN_WORDLIST_FILE}")
        else:
            subs_wordlist = DEFAULT_SUBS
    except Exception:
        subs_wordlist = DEFAULT_SUBS
    time.sleep(SLEEP_SUBENUM)
    discovered_subs = enumerate_subdomains(host, wordlist=subs_wordlist, rate=SLEEP_SUBENUM)
    report.append("Discovered Subdomains:\n" + "\n".join(discovered_subs) if discovered_subs else "No subdomains discovered (or DNS filtered)")

    # HTTP fetch
    http_url = base_url if parsed.scheme else ("https://" if parsed.scheme=="https" else "http://") + host
    if not parsed.scheme:
        http_url = "http://" + host
    try:
        safe_print(Fore.YELLOW + f"[+] Fetching {http_url} ...")
        resp = fetch_http(http_url, verify_tls=VERIFY_TLS)
        report.append(f"HTTP Status: {resp.status_code}")
        report.append(f"Server Header: {resp.headers.get('Server')}")
        report.append(f"Content-Type: {resp.headers.get('Content-Type')}")
        report.append("Cookies: " + json.dumps(resp.cookies.get_dict(), ensure_ascii=False))
        techs = analyze_html_tech(resp.text, resp.headers)
        report.append("Technologies: " + techs)
        sec_headers = check_security_headers(resp.headers)
        report.append("Security Headers: " + json.dumps(sec_headers, indent=2, ensure_ascii=False))
        js_assets = extract_js_assets(resp.text)
        report.append("JS Assets: " + json.dumps(js_assets, indent=2, ensure_ascii=False))
    except Exception as e:
        report.append("HTTP fetch error: " + str(e))
        safe_print(Fore.RED + f"[!] HTTP fetch failed: {e}")

    # SSL/TLS
    time.sleep(SLEEP_BETWEEN_HTTP)
    ssl_info = get_ssl_info(host)
    report.append("SSL Info: " + json.dumps(ssl_info, indent=2, ensure_ascii=False))

    # JS analysis (look for endpoints)
    if js_assets:
        endpoints = analyze_js_for_endpoints(js_assets, base_url)
        report.append("JS-derived endpoints/tokens (heuristic): " + json.dumps(endpoints, indent=2, ensure_ascii=False))
    else:
        report.append("No JS assets to analyze (or blocked).")

    # Directory brute-force (limited)
    dirs_wordlist = None
    try:
        dpath = resource_path(DIR_WORDLIST_FILE)
        if os.path.exists(dpath):
            with open(dpath, "r", encoding="utf-8") as fh:
                dirs_wordlist = [l.strip() for l in fh if l.strip()]
            safe_print(Fore.GREEN + f"[+] Loaded {len(dirs_wordlist)} directory words from {DIR_WORDLIST_FILE}")
        else:
            dirs_wordlist = DEFAULT_DIRS
    except Exception:
        dirs_wordlist = DEFAULT_DIRS

    safe_print(Fore.YELLOW + f"[+] Running limited directory check (max {MAX_DIR_PROBES}) ...")
    dir_found = directory_bruteforce(base_url, wordlist=dirs_wordlist, max_checks=MAX_DIR_PROBES)
    report.append("Directory finds: " + json.dumps(dir_found, ensure_ascii=False))

    # TCP full scan 1-1024
    safe_print(Fore.YELLOW + f"[+] Starting TCP scan across ports 1-1024 (threads={THREADS_TCP}) — this may take a while.")
    t0 = time.time()
    tcp_open = tcp_scan(ip, TCP_PORT_RANGE, threads=THREADS_TCP)
    t1 = time.time()
    report.append(f"Open TCP ports (1-1024): {tcp_open}")
    report.append(f"TCP scan time: {t1-t0:.1f}s")

    # UDP scan 1-1024 - best-effort (can be slow and unreliable)
    safe_print(Fore.YELLOW + f"[+] Starting UDP best-effort scan across ports 1-1024 (threads={THREADS_UDP}) — this can be very slow.")
    t0 = time.time()
    udp_open = udp_scan(ip, UDP_PORT_RANGE, threads=THREADS_UDP)
    t1 = time.time()
    report.append(f"Responsive UDP ports (best-effort): {udp_open}")
    report.append(f"UDP scan time: {t1-t0:.1f}s")

    # Finalize
    final_report = "\n".join(report)
    safe_print(Fore.GREEN + "[+] Recon complete. Writing report to Desktop...")
    write_report(final_report, name_hint=f"icsf_{host}")
    safe_print(Fore.GREEN + "[+] Done. Report on Desktop. Use results responsibly.")

# -------------------------
# CLI Entrypoint
# -------------------------
def main():
    safe_print(Fore.RED + "ICSF Recon Scanner v4 — Ultra Brutal Edition")
    safe_print(Fore.YELLOW + "ONLY use this tool on systems you are explicitly authorized to test.")
    target = input(Fore.CYAN + "Target (domain or URL, e.g. example.com or https://example.com): " + Fore.WHITE).strip()
    if not target:
        safe_print(Fore.RED + "No target given. Exiting.")
        return

    # Confirm permission
    safe_print(Fore.MAGENTA + "Do you have explicit written permission to scan this target? Type 'I HAVE PERMISSION' to continue:")
    conf = input(Fore.WHITE + "> ").strip()
    if conf != "I HAVE PERMISSION":
        safe_print(Fore.RED + "Permission not confirmed. Exiting.")
        return

    # Warn about heavy scans
    safe_print(Fore.YELLOW + "This run will perform TCP & UDP scans across ports 1-1024 and other checks; it may be noisy.")
    safe_print(Fore.YELLOW + "Do you want to continue? (yes/no)")
    if input(Fore.WHITE + "> ").strip().lower() not in ("y","yes"):
        safe_print(Fore.RED + "Aborted by user.")
        return

    # Run scanner
    try:
        scan_target_cli(target)
    except KeyboardInterrupt:
        safe_print(Fore.RED + "\n[!] Interrupted by user.")
    except Exception as e:
        safe_print(Fore.RED + f"[!] Error during scan: {e}")

if __name__ == "__main__":
    main()
