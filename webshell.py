#!/usr/bin/env python3
"""
VulnPulse
Defensive Web Audit & Webshell Hygiene Toolkit

Author: OpenAI Assistant
Purpose:
    Defensive security auditing, incident response, and malware hunting.

Features:
- Recursive webshell scanning
- IOC detection
- Suspicious file analysis
- Entropy detection
- Log hunting
- YARA-lite matching
- Hash inventory
- Quarantine mode
- Interactive terminal dashboard
- Export reports (JSON)
- Multi-threaded scanning

Usage:
    python3 webshell.py

Requirements:
    pip install rich requests beautifulsoup4
"""

import os
import re
import json
import time
import math
import shutil
import hashlib
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress
from rich.layout import Layout
from rich.text import Text

console = Console()

# =========================================================
# SAFE DOMAIN SECURITY AUDIT
# =========================================================

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs

VULN_SCAN_MODULES = {
    "1": "File Upload Misconfiguration",
    "2": "SQL Injection Indicators",
    "3": "Directory Listing Exposure",
    "4": "Backup File Exposure",
    "5": "Missing Security Headers",
    "6": "Admin Panel Discovery",
    "7": "Sensitive File Exposure",
    "8": "CMS Fingerprint",
    "9": "Public Git Exposure",
    "10": "HTTP Method Misconfiguration",
    "11": "XSS Indicators (DOM/HTML)"
}

COMMON_UPLOAD_PATHS = [
    "/upload",
    "/uploads",
    "/file-upload",
    "/admin/upload",
    "/media/upload",
    "/api/upload"
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security"
]

DEFAULT_TIMEOUT = (5, 15)
DEFAULT_HEADERS = {
    "User-Agent": "WebScan/1.0 (defensive audit) requests"
}
MAX_WORKERS = 12
MAX_CRAWL_PAGES = 30
STATIC_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".css",
    ".js",
    ".map",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
    ".gz",
    ".tar",
    ".mp4",
    ".mp3"
}


def get_http_session():
    s = requests.Session()
    s.headers.update(DEFAULT_HEADERS)
    try:
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        retry = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    except Exception:
        pass
    return s


def safe_request(session, method, url, *, timeout=DEFAULT_TIMEOUT, allow_redirects=True):
    try:
        r = session.request(
            method,
            url,
            timeout=timeout,
            allow_redirects=allow_redirects
        )
        return r, None
    except Exception as e:
        return None, str(e)


def try_head_then_get(session, url, *, timeout=DEFAULT_TIMEOUT):
    r, err = safe_request(session, "HEAD", url, timeout=timeout)
    if r is not None and r.status_code not in [405, 501]:
        return r, err
    return safe_request(session, "GET", url, timeout=timeout)


def build_url(domain, path):
    base = normalize_domain(domain)
    if not base:
        return ""
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def is_probably_html_response(r):
    try:
        ctype = (r.headers.get("Content-Type") or "").lower()
    except Exception:
        ctype = ""

    if "text/html" in ctype or "application/xhtml" in ctype:
        return True

    if not ctype:
        return True

    return False


def extract_internal_links(html, base_url, base_host):
    links = set()
    try:
        soup = BeautifulSoup(html or "", "html.parser")
        for a in soup.find_all("a", href=True):
            href = (a.get("href") or "").strip()
            if not href:
                continue
            if href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            abs_url = urljoin(base_url.rstrip("/") + "/", href)
            p = urlparse(abs_url)
            if p.netloc and p.netloc != base_host:
                continue
            if p.fragment:
                abs_url = abs_url.split("#", 1)[0]
                p = urlparse(abs_url)
            ext = os.path.splitext(p.path.lower())[1]
            if ext and ext in STATIC_EXTENSIONS:
                continue
            links.add(abs_url)
    except Exception:
        return set()

    return links


def risk_label(score):
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "INFO"


def clamp_score(value, minimum=0, maximum=100):
    try:
        value = int(value)
    except Exception:
        value = 0
    if value < minimum:
        return minimum
    if value > maximum:
        return maximum
    return value


def check_xss_indicators(domain, *, session=None, show_progress=True, return_details=False):
    domain = normalize_domain(domain)
    if not domain:
        console.print("[red]Invalid domain[/red]")
        return {"score": 0, "findings": []} if return_details else False

    session = session or get_http_session()

    parsed_base = urlparse(domain)
    base_host = parsed_base.netloc

    queue = [domain]
    visited = set()
    findings = {}

    def add_finding(url, indicators):
        if not indicators:
            return
        existing = findings.get(url)
        if existing is None:
            findings[url] = set(indicators)
        else:
            existing.update(indicators)

    def analyze_html(url):
        r, err = safe_request(session, "GET", url, timeout=DEFAULT_TIMEOUT)
        if r is None:
            return set(), err

        if not is_probably_html_response(r):
            return set(), None

        text = r.text or ""
        text_l = text.lower()

        indicators = set()

        csp = r.headers.get("Content-Security-Policy") or ""
        if not csp:
            indicators.add("missing_csp")
        else:
            csp_l = csp.lower()
            if "unsafe-inline" in csp_l:
                indicators.add("csp_unsafe_inline")
            if "unsafe-eval" in csp_l:
                indicators.add("csp_unsafe_eval")

        for needle, label in [
            ("innerhtml", "innerHTML"),
            ("outerhtml", "outerHTML"),
            ("insertadjacenthtml", "insertAdjacentHTML"),
            ("document.write", "document.write"),
            ("document.writeln", "document.writeln"),
            ("eval(", "eval"),
            ("new function", "Function"),
            ("settimeout(", "setTimeout"),
            ("setinterval(", "setInterval"),
            ("location.hash", "location.hash"),
            ("location.search", "location.search"),
            ("document.location", "document.location"),
            ("document.url", "document.URL"),
            ("window.name", "window.name"),
        ]:
            if needle in text_l:
                indicators.add(label)

        if re.search(r"on[a-z0-9_]+\s*=", text_l):
            indicators.add("inline_event_handlers")

        try:
            soup = BeautifulSoup(text, "html.parser")
            inline_script_count = 0
            for s in soup.find_all("script"):
                if not s.get("src"):
                    content = (s.string or "").strip()
                    if content:
                        inline_script_count += 1
            if inline_script_count:
                indicators.add(f"inline_scripts:{inline_script_count}")
        except Exception:
            pass

        if indicators:
            add_finding(r.url, indicators)

        links = extract_internal_links(text, r.url, base_host)
        return links, None

    if show_progress:
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning XSS indicators...", total=MAX_CRAWL_PAGES)
            while queue and len(visited) < MAX_CRAWL_PAGES:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                links, _ = analyze_html(url)
                for link in links:
                    if link not in visited and link not in queue and (len(visited) + len(queue)) < MAX_CRAWL_PAGES:
                        queue.append(link)
                progress.advance(task)
    else:
        while queue and len(visited) < MAX_CRAWL_PAGES:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            links, _ = analyze_html(url)
            for link in links:
                if link not in visited and link not in queue and (len(visited) + len(queue)) < MAX_CRAWL_PAGES:
                    queue.append(link)

    if findings:
        if not return_details:
            table = Table(title="XSS Indicators (DOM/HTML)")
            table.add_column("URL", style="yellow")
            table.add_column("Indicator(s)", style="red")
            for u in sorted(findings.keys())[:50]:
                table.add_row(u, ", ".join(sorted(findings[u]))[:200])
            console.print(table)
            console.print("[yellow]Found XSS indicators (no payload injection attempted)[/yellow]")
        findings_list = []
        max_score = 0
        weights = {
            "missing_csp": 30,
            "csp_unsafe_inline": 40,
            "csp_unsafe_eval": 40,
            "inline_event_handlers": 25,
            "innerHTML": 20,
            "outerHTML": 15,
            "insertAdjacentHTML": 15,
            "document.write": 25,
            "document.writeln": 25,
            "eval": 35,
            "Function": 35,
            "setTimeout": 10,
            "setInterval": 10,
            "location.hash": 10,
            "location.search": 10,
            "document.location": 10,
            "document.URL": 10,
            "window.name": 10,
        }

        for url, indicators in findings.items():
            url_score = 0
            for ind in indicators:
                if ind.startswith("inline_scripts:"):
                    try:
                        count = int(ind.split(":", 1)[1])
                    except Exception:
                        count = 0
                    url_score += min(20, count * 3)
                    continue
                url_score += weights.get(ind, 5)

            url_score = clamp_score(min(90, url_score))
            max_score = max(max_score, url_score)
            findings_list.append({
                "module": "XSS Indicators",
                "url": url,
                "score": url_score,
                "risk": risk_label(url_score),
                "detail": ", ".join(sorted(indicators))[:200]
            })

        if not return_details:
            console.print(f"[bold]Score:[/bold] {max_score}/100 ({risk_label(max_score)})")

        if return_details:
            return {"score": max_score, "findings": findings_list}

        return True

    console.print("[green]No obvious XSS indicators detected[/green]")
    return {"score": 0, "findings": []} if return_details else False


def check_http_methods(domain, *, session=None, return_details=False):
    domain = normalize_domain(domain)
    if not domain:
        console.print("[red]Invalid domain[/red]")
        return {"score": 0, "findings": []} if return_details else False

    session = session or get_http_session()
    table = Table(title="Dangerous HTTP Methods")
    table.add_column("Method")
    table.add_column("Allowed")

    risky = False
    risky_methods = []

    try:
        r, err = safe_request(session, "OPTIONS", domain, timeout=DEFAULT_TIMEOUT)
        if r is None:
            raise RuntimeError(err or "request failed")
        allow = r.headers.get("Allow", "")

        for method in ["PUT", "DELETE", "TRACE", "CONNECT"]:
            if method in allow:
                table.add_row(method, "YES")
                risky = True
                risky_methods.append(method)
            else:
                table.add_row(method, "NO")

        if not return_details:
            console.print(table)

            if risky:
                console.print("[red]Potentially risky HTTP methods enabled[/red]")
                score = clamp_score(min(90, 55 + (len(risky_methods) * 10)))
                console.print(f"[bold]Score:[/bold] {score}/100 ({risk_label(score)})")
            else:
                console.print("[green]No risky HTTP methods detected[/green]")

    except Exception as e:
        console.print(f"[red]{e}[/red]")
        return {"score": 0, "findings": []} if return_details else False

    if return_details:
        if not risky_methods:
            return {"score": 0, "findings": []}

        score = clamp_score(min(90, 55 + (len(risky_methods) * 10)))
        findings = []
        for m in risky_methods:
            findings.append({
                "module": "HTTP Methods",
                "url": domain,
                "score": score,
                "risk": risk_label(score),
                "detail": f"Allow: {m}"
            })
        return {"score": score, "findings": findings}

    return risky


def check_directory_listing(domain, *, session=None, show_progress=True, return_details=False):
    domain = normalize_domain(domain)
    if not domain:
        console.print("[red]Invalid domain[/red]")
        return {"score": 0, "findings": []} if return_details else False

    session = session or get_http_session()
    paths = ["/uploads/", "/images/", "/backup/", "/files/"]

    table = Table(title="Directory Listing Check")
    table.add_column("Path")
    table.add_column("Status")

    found = False
    found_urls = []

    if show_progress:
        with Progress() as progress:
            task = progress.add_task("[cyan]Checking paths...", total=len(paths))
            for p in paths:
                url = build_url(domain, p)
                r, _ = safe_request(session, "GET", url, timeout=DEFAULT_TIMEOUT)
                if r is not None and r.status_code == 200:
                    text = (r.text or "").lower()
                    if "index of" in text or "<title>index of" in text:
                        table.add_row(url, "OPEN")
                        found = True
                        found_urls.append(url)
                progress.advance(task)
    else:
        for p in paths:
            url = build_url(domain, p)
            r, _ = safe_request(session, "GET", url, timeout=DEFAULT_TIMEOUT)
            if r is not None and r.status_code == 200:
                text = (r.text or "").lower()
                if "index of" in text or "<title>index of" in text:
                    table.add_row(url, "OPEN")
                    found = True
                    found_urls.append(url)

    if found:
        if not return_details:
            console.print(table)
            console.print(f"[bold]Score:[/bold] 75/100 ({risk_label(75)})")
        if return_details:
            findings = []
            for u in sorted(set(found_urls)):
                score = 75
                findings.append({
                    "module": "Directory Listing",
                    "url": u,
                    "score": score,
                    "risk": risk_label(score),
                    "detail": "Index of exposed"
                })
            return {"score": 75, "findings": findings}
        return True
    else:
        if not return_details:
            console.print("[green]No open directory listing detected[/green]")
        return {"score": 0, "findings": []} if return_details else False


def check_backup_files(domain, *, session=None, show_progress=True, return_details=False):
    domain = normalize_domain(domain)
    if not domain:
        console.print("[red]Invalid domain[/red]")
        return {"score": 0, "findings": []} if return_details else False

    session = session or get_http_session()
    backups = [
        "/backup.zip",
        "/website.zip",
        "/db.sql",
        "/backup.tar.gz",
        "/www.zip"
    ]

    table = Table(title="Exposed Backup Files")
    table.add_column("URL")
    table.add_column("HTTP")

    found = False
    found_urls = []

    if show_progress:
        with Progress() as progress:
            task = progress.add_task("[cyan]Checking backup files...", total=len(backups))
            for item in backups:
                url = build_url(domain, item)
                r, _ = try_head_then_get(session, url, timeout=DEFAULT_TIMEOUT)
                if r is not None and r.status_code == 200:
                    table.add_row(r.url, str(r.status_code))
                    found = True
                    found_urls.append(r.url)
                progress.advance(task)
    else:
        for item in backups:
            url = build_url(domain, item)
            r, _ = try_head_then_get(session, url, timeout=DEFAULT_TIMEOUT)
            if r is not None and r.status_code == 200:
                table.add_row(r.url, str(r.status_code))
                found = True
                found_urls.append(r.url)

    if found:
        if not return_details:
            console.print(table)
            console.print(f"[bold]Score:[/bold] 95/100 ({risk_label(95)})")
        if return_details:
            findings = []
            for u in sorted(set(found_urls)):
                score = 95
                findings.append({
                    "module": "Backup Files",
                    "url": u,
                    "score": score,
                    "risk": risk_label(score),
                    "detail": "Exposed backup file"
                })
            return {"score": 95, "findings": findings}
        return True
    else:
        if not return_details:
            console.print("[green]No exposed backup files detected[/green]")
        return {"score": 0, "findings": []} if return_details else False


def check_env_files(domain, *, session=None, show_progress=True, return_details=False):
    domain = normalize_domain(domain)
    if not domain:
        console.print("[red]Invalid domain[/red]")
        return {"score": 0, "findings": []} if return_details else False

    session = session or get_http_session()
    files = ["/.env", "/config.php.bak", "/.git/config"]

    table = Table(title="Sensitive File Exposure")
    table.add_column("URL")
    table.add_column("Status")

    found = False
    found_urls = []

    if show_progress:
        with Progress() as progress:
            task = progress.add_task("[cyan]Checking sensitive files...", total=len(files))
            for f in files:
                url = build_url(domain, f)
                r, _ = try_head_then_get(session, url, timeout=DEFAULT_TIMEOUT)
                if r is not None and r.status_code == 200:
                    table.add_row(r.url, "EXPOSED")
                    found = True
                    found_urls.append(r.url)
                progress.advance(task)
    else:
        for f in files:
            url = build_url(domain, f)
            r, _ = try_head_then_get(session, url, timeout=DEFAULT_TIMEOUT)
            if r is not None and r.status_code == 200:
                table.add_row(r.url, "EXPOSED")
                found = True
                found_urls.append(r.url)

    if found:
        if not return_details:
            console.print(table)
            console.print(f"[bold]Score:[/bold] 90/100 ({risk_label(90)})")
        if return_details:
            findings = []
            for u in sorted(set(found_urls)):
                score = 90
                findings.append({
                    "module": "Sensitive Files",
                    "url": u,
                    "score": score,
                    "risk": risk_label(score),
                    "detail": "Sensitive file exposed"
                })
            return {"score": 90, "findings": findings}
        return True
    else:
        if not return_details:
            console.print("[green]No sensitive file exposure detected[/green]")
        return {"score": 0, "findings": []} if return_details else False


def check_admin_panels(domain, *, session=None, show_progress=True, return_details=False):
    domain = normalize_domain(domain)
    if not domain:
        console.print("[red]Invalid domain[/red]")
        return {"score": 0, "findings": []} if return_details else False

    session = session or get_http_session()
    panels = [
        "/admin",
        "/administrator",
        "/wp-admin",
        "/login",
        "/cpanel"
    ]

    table = Table(title="Admin Panel Discovery")
    table.add_column("Panel")
    table.add_column("HTTP")

    found = False
    found_panels = []

    if show_progress:
        with Progress() as progress:
            task = progress.add_task("[cyan]Checking admin panels...", total=len(panels))
            for p in panels:
                url = build_url(domain, p)
                r, _ = safe_request(session, "GET", url, timeout=DEFAULT_TIMEOUT)
                if r is not None and r.status_code in [200, 301, 302, 403]:
                    table.add_row(r.url, str(r.status_code))
                    found = True
                    found_panels.append((r.url, r.status_code))
                progress.advance(task)
    else:
        for p in panels:
            url = build_url(domain, p)
            r, _ = safe_request(session, "GET", url, timeout=DEFAULT_TIMEOUT)
            if r is not None and r.status_code in [200, 301, 302, 403]:
                table.add_row(r.url, str(r.status_code))
                found = True
                found_panels.append((r.url, r.status_code))

    if found:
        if not return_details:
            console.print(table)
            score = 25 if any(sc == 200 for _, sc in found_panels) else 15
            console.print(f"[bold]Score:[/bold] {score}/100 ({risk_label(score)})")
        if return_details:
            findings = []
            max_score = 0
            for u, status_code in found_panels:
                score = 25 if status_code == 200 else 15
                max_score = max(max_score, score)
                findings.append({
                    "module": "Admin Panels",
                    "url": u,
                    "score": score,
                    "risk": risk_label(score),
                    "detail": f"HTTP {status_code}"
                })
            return {"score": max_score, "findings": findings}
        return True
    else:
        if not return_details:
            console.print("[green]No common admin panels detected[/green]")
        return {"score": 0, "findings": []} if return_details else False


def fingerprint_cms(domain, *, session=None, return_details=False):
    domain = normalize_domain(domain)
    if not domain:
        console.print("[red]Invalid domain[/red]")
        return {"score": 0, "findings": []} if return_details else False

    session = session or get_http_session()
    if not return_details:
        console.print("[cyan][*][/cyan] CMS Fingerprinting")

    try:
        r, err = safe_request(session, "GET", domain, timeout=DEFAULT_TIMEOUT)
        if r is None:
            raise RuntimeError(err or "request failed")

        text = (r.text or "").lower()
        headers = {k.lower(): v for k, v in (r.headers or {}).items()}

        if "wp-content" in text:
            console.print("[yellow]Possible WordPress detected[/yellow]")
            if return_details:
                return {"score": 10, "findings": [{"module": "CMS", "url": domain, "score": 10, "risk": risk_label(10), "detail": "WordPress indicators"}]}
            return True

        elif "joomla" in text:
            console.print("[yellow]Possible Joomla detected[/yellow]")
            if return_details:
                return {"score": 10, "findings": [{"module": "CMS", "url": domain, "score": 10, "risk": risk_label(10), "detail": "Joomla indicators"}]}
            return True

        elif "drupal" in text:
            console.print("[yellow]Possible Drupal detected[/yellow]")
            if return_details:
                return {"score": 10, "findings": [{"module": "CMS", "url": domain, "score": 10, "risk": risk_label(10), "detail": "Drupal indicators"}]}
            return True

        if "x-powered-by" in headers and headers["x-powered-by"]:
            console.print(f"[green]X-Powered-By:[/green] {headers['x-powered-by']}")
            if return_details:
                return {"score": 5, "findings": [{"module": "CMS", "url": domain, "score": 5, "risk": risk_label(5), "detail": f"X-Powered-By: {headers['x-powered-by']}"}]}
            return True

        console.print("[green]Unknown CMS[/green]")
        return {"score": 0, "findings": []} if return_details else False

    except Exception as e:
        console.print(f"[red]{e}[/red]")
        return {"score": 0, "findings": []} if return_details else False


def check_git_exposure(domain, *, session=None, return_details=False):
    domain = normalize_domain(domain)
    if not domain:
        console.print("[red]Invalid domain[/red]")
        return {"score": 0, "findings": []} if return_details else False

    session = session or get_http_session()
    try:
        url = build_url(domain, "/.git/")
        r, _ = try_head_then_get(session, url, timeout=DEFAULT_TIMEOUT)

        if r is not None and r.status_code == 200:
            if not return_details:
                console.print(f"[red]Potential .git exposure: {r.url}[/red]")
                console.print(f"[bold]Score:[/bold] 95/100 ({risk_label(95)})")
            if return_details:
                score = 95
                return {"score": score, "findings": [{"module": "Git Exposure", "url": r.url, "score": score, "risk": risk_label(score), "detail": "Public .git endpoint"}]}
            return True
        else:
            if not return_details:
                console.print("[green]No public .git exposure[/green]")
            return {"score": 0, "findings": []} if return_details else False

    except Exception as e:
        console.print(f"[red]{e}[/red]")
        return {"score": 0, "findings": []} if return_details else False


def audit_domain(domain):
    console.print(f"[cyan][*][/cyan] Auditing domain: {domain}")

    if not domain.startswith("http"):
        domain = f"https://{domain}"

    try:
        r = requests.get(domain, timeout=10)
    except Exception as e:
        console.print(f"[red]Connection failed:[/red] {e}")
        return

    table = Table(title="Security Audit")
    table.add_column("Check", style="yellow")
    table.add_column("Status", style="green")

    # Security headers
    for header in SECURITY_HEADERS:
        if header in r.headers:
            table.add_row(header, "Present")
        else:
            table.add_row(header, "Missing")

    # Server banner
    server = r.headers.get("Server", "Unknown")
    table.add_row("Server Banner", server)

    console.print(table)

    # Passive upload discovery
    upload_table = Table(title="Possible Upload Surfaces")
    upload_table.add_column("Path", style="yellow")
    upload_table.add_column("HTTP")

    found = False

    for path in COMMON_UPLOAD_PATHS:
        try:
            target = urljoin(domain, path)
            rr = requests.get(target, timeout=5)

            if rr.status_code in [200, 301, 302, 403]:
                upload_table.add_row(target, str(rr.status_code))
                found = True
        except Exception:
            pass

    if found:
        console.print(upload_table)
    else:
        console.print("[green]No common upload paths detected[/green]")

    # Forms analysis
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")

        form_table = Table(title="HTML Forms")
        form_table.add_column("Action")
        form_table.add_column("Method")

        for form in forms:
            action = form.get("action", "unknown")
            method = form.get("method", "GET")
            form_table.add_row(action, method.upper())

        if forms:
            console.print(form_table)

    except Exception:
        pass


def normalize_domain(domain):
    domain = (domain or "").strip()
    if not domain:
        return ""

    if not domain.startswith(("http://", "https://")):
        domain = f"https://{domain}"

    parsed = urlparse(domain)
    if not parsed.netloc and parsed.path:
        parsed = urlparse(f"https://{parsed.path}")

    base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return base


def check_missing_security_headers(domain, *, session=None, return_details=False):
    domain = normalize_domain(domain)
    if not domain:
        console.print("[red]Invalid domain[/red]")
        return {"score": 0, "findings": []} if return_details else False

    console.print("[cyan][*][/cyan] Checking missing security headers")

    session = session or get_http_session()
    try:
        r, err = try_head_then_get(session, domain, timeout=DEFAULT_TIMEOUT)
        if r is None:
            raise RuntimeError(err or "request failed")
    except Exception as e:
        console.print(f"[red]Connection failed:[/red] {e}")
        return {"score": 0, "findings": []} if return_details else False

    table = Table(title="Missing Security Headers")
    table.add_column("Header", style="yellow")
    table.add_column("Status", style="green")

    missing = 0
    findings = []
    weights = {
        "Content-Security-Policy": 35,
        "Strict-Transport-Security": 25,
        "X-Frame-Options": 10,
        "X-Content-Type-Options": 10,
    }

    for header in SECURITY_HEADERS:
        if header in r.headers:
            table.add_row(header, "Present")
        else:
            table.add_row(header, "Missing")
            missing += 1
            score = clamp_score(weights.get(header, 5))
            findings.append({
                "module": "Missing Headers",
                "url": domain,
                "score": score,
                "risk": risk_label(score),
                "detail": f"Missing: {header}"
            })

    if not return_details:
        console.print(table)

    if missing:
        if not return_details:
            console.print(f"[red]Missing {missing} security header(s)[/red]")
            max_score = max([f["score"] for f in findings], default=0)
            console.print(f"[bold]Score:[/bold] {max_score}/100 ({risk_label(max_score)})")
        if return_details:
            max_score = max([f["score"] for f in findings], default=0)
            return {"score": max_score, "findings": findings}
        return True

    if not return_details:
        console.print("[green]All recommended security headers detected[/green]")
    return {"score": 0, "findings": []} if return_details else False


def check_upload_misconfig(domain, *, session=None, show_progress=True, return_details=False):
    domain = normalize_domain(domain)
    if not domain:
        console.print("[red]Invalid domain[/red]")
        return {"score": 0, "findings": []} if return_details else False

    if not return_details:
        console.print("[cyan][*][/cyan] Scanning file upload misconfiguration (passive)")

    found = False
    endpoint_hits = []
    form_hits = []

    session = session or get_http_session()
    try:
        r, err = safe_request(session, "GET", domain, timeout=DEFAULT_TIMEOUT)
        if r is None:
            raise RuntimeError(err or "request failed")
    except Exception as e:
        console.print(f"[red]Connection failed:[/red] {e}")
        return {"score": 0, "findings": []} if return_details else False

    upload_table = None
    if not return_details:
        upload_table = Table(title="Possible Upload Endpoints (Passive)")
        upload_table.add_column("URL", style="yellow")
        upload_table.add_column("HTTP")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = []
        for path in COMMON_UPLOAD_PATHS:
            target = build_url(domain, path)
            futures.append(ex.submit(safe_request, session, "GET", target, timeout=DEFAULT_TIMEOUT))

        if show_progress:
            with Progress() as progress:
                task = progress.add_task("[cyan]Probing upload endpoints...", total=len(futures))
                for fut in as_completed(futures):
                    rr, _ = fut.result()
                    if rr is not None and rr.status_code in [200, 301, 302, 403, 405]:
                        if upload_table is not None:
                            upload_table.add_row(rr.url, str(rr.status_code))
                        found = True
                        endpoint_hits.append((rr.url, rr.status_code))
                    progress.advance(task)
        else:
            for fut in as_completed(futures):
                rr, _ = fut.result()
                if rr is not None and rr.status_code in [200, 301, 302, 403, 405]:
                    if upload_table is not None:
                        upload_table.add_row(rr.url, str(rr.status_code))
                    found = True
                    endpoint_hits.append((rr.url, rr.status_code))

    if found and upload_table is not None:
        console.print(upload_table)

    try:
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        file_forms = []

        for form in forms:
            file_inputs = form.find_all("input", attrs={"type": re.compile(r"^file$", re.I)})
            if file_inputs:
                action = (form.get("action") or "").strip()
                method = (form.get("method") or "GET").upper()
                enctype = (form.get("enctype") or "unknown").lower()
                action_url = urljoin(domain.rstrip("/") + "/", action) if action else domain
                file_forms.append((action_url, method, enctype))
                form_hits.append((action_url, method, enctype))

        if file_forms:
            if not return_details:
                form_table = Table(title="Forms With File Input")
                form_table.add_column("Action", style="yellow")
                form_table.add_column("Method")
                form_table.add_column("Enctype")

                for action_url, method, enctype in file_forms[:50]:
                    form_table.add_row(action_url, method, enctype)

                console.print(form_table)
            found = True
    except Exception:
        pass

    if found:
        if not return_details:
            console.print("[yellow]Upload surface indicators found (review manually)[/yellow]")
            max_score = 0
            for _, status_code in endpoint_hits:
                max_score = max(max_score, 45 if status_code == 200 else 35)
            for _, _, enctype in form_hits:
                base = 30 + (10 if "multipart/form-data" in (enctype or "") else 0)
                max_score = max(max_score, clamp_score(min(60, base)))
            console.print(f"[bold]Score:[/bold] {max_score}/100 ({risk_label(max_score)})")

        if return_details:
            findings = []
            max_score = 0
            for u, status_code in endpoint_hits:
                score = 45 if status_code == 200 else 35
                max_score = max(max_score, score)
                findings.append({
                    "module": "Upload Misconfig",
                    "url": u,
                    "score": score,
                    "risk": risk_label(score),
                    "detail": f"Endpoint probe HTTP {status_code}"
                })

            for action_url, method, enctype in form_hits:
                base = 30
                if "multipart/form-data" in (enctype or ""):
                    base += 10
                score = clamp_score(min(60, base))
                max_score = max(max_score, score)
                findings.append({
                    "module": "Upload Misconfig",
                    "url": action_url,
                    "score": score,
                    "risk": risk_label(score),
                    "detail": f"Form file input ({method}, {enctype})"
                })

            return {"score": max_score, "findings": findings}

        return True

    if not return_details:
        console.print("[green]No upload surface indicators detected[/green]")
    return {"score": 0, "findings": []} if return_details else False


def check_sqli_indicators(domain, *, session=None, show_progress=True, return_details=False):
    domain = normalize_domain(domain)
    if not domain:
        console.print("[red]Invalid domain[/red]")
        return {"score": 0, "findings": []} if return_details else False

    if not return_details:
        console.print("[cyan][*][/cyan] Scanning SQL injection indicators (passive)")

    suspicious_params = {
        "id",
        "ids",
        "cat",
        "category",
        "product",
        "item",
        "pid",
        "uid",
        "user",
        "page",
        "p",
        "q",
        "search",
        "s",
        "news",
        "article",
        "order",
        "sort"
    }

    session = session or get_http_session()

    parsed_base = urlparse(domain)
    base_host = parsed_base.netloc

    error_markers = [
        "sql syntax",
        "you have an error in your sql syntax",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "mysql",
        "mariadb",
        "postgresql",
        "pg::",
        "sqlite",
        "odbc",
        "sqlstate",
        "pdoexception",
        "warning: mysql",
        "fatal error",
        "syntax error"
    ]

    urls_with_params = {}
    forms_with_params = {}
    error_disclosures = set()

    queue = [domain]
    visited = set()

    def record_params(url, params):
        if not params:
            return
        key = url
        existing = urls_with_params.get(key)
        if existing is None:
            urls_with_params[key] = set(params)
        else:
            existing.update(params)

    def record_form(action_url, method, params):
        if not params:
            return
        key = f"{method} {action_url}"
        existing = forms_with_params.get(key)
        if existing is None:
            forms_with_params[key] = set(params)
        else:
            existing.update(params)

    def scan_page(url):
        r, err = safe_request(session, "GET", url, timeout=DEFAULT_TIMEOUT)
        if r is None:
            return set(), err

        if not is_probably_html_response(r):
            return set(), None

        text = r.text or ""
        text_l = text.lower()
        if any(m in text_l for m in error_markers) and (r.status_code >= 500 or urlparse(r.url).query):
            error_disclosures.add(r.url)

        links = extract_internal_links(text, r.url, base_host)

        try:
            soup = BeautifulSoup(text, "html.parser")

            for a in soup.find_all("a", href=True):
                href = (a.get("href") or "").strip()
                if not href:
                    continue
                abs_url = urljoin(r.url.rstrip("/") + "/", href)
                p = urlparse(abs_url)
                if p.netloc and p.netloc != base_host:
                    continue
                qs = parse_qs(p.query)
                if not qs:
                    continue
                hit_params = [k for k in qs.keys() if k.lower() in suspicious_params]
                if hit_params:
                    record_params(abs_url, [h.lower() for h in hit_params])

            for form in soup.find_all("form"):
                method = (form.get("method") or "GET").upper()
                action = (form.get("action") or "").strip() or r.url
                action_url = urljoin(r.url.rstrip("/") + "/", action)
                ap = urlparse(action_url)
                if ap.netloc and ap.netloc != base_host:
                    continue

                names = set()
                for inp in form.find_all(["input", "select", "textarea"]):
                    name = inp.get("name")
                    if name:
                        names.add(name)

                hit = [n for n in names if n.lower() in suspicious_params]
                if hit:
                    record_form(action_url, method, [h.lower() for h in hit])
        except Exception:
            pass

        return links, None

    if show_progress:
        with Progress() as progress:
            task = progress.add_task("[cyan]Crawling pages...", total=MAX_CRAWL_PAGES)
            while queue and len(visited) < MAX_CRAWL_PAGES:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                links, _ = scan_page(url)
                for link in links:
                    if link not in visited and link not in queue and (len(visited) + len(queue)) < MAX_CRAWL_PAGES:
                        queue.append(link)
                progress.advance(task)
    else:
        while queue and len(visited) < MAX_CRAWL_PAGES:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            links, _ = scan_page(url)
            for link in links:
                if link not in visited and link not in queue and (len(visited) + len(queue)) < MAX_CRAWL_PAGES:
                    queue.append(link)

    found_any = False

    if error_disclosures:
        if not return_details:
            table = Table(title="SQL Error Disclosure Indicators")
            table.add_column("URL", style="red")
            for u in sorted(list(error_disclosures))[:50]:
                table.add_row(u)
            console.print(table)
        found_any = True

    if urls_with_params:
        if not return_details:
            table = Table(title="Potential SQLi Parameters (from URLs)")
            table.add_column("URL", style="yellow")
            table.add_column("Parameter(s)", style="red")
            for u in sorted(urls_with_params.keys())[:50]:
                params = ", ".join(sorted(urls_with_params[u]))
                table.add_row(u, params)
            console.print(table)
        found_any = True

    if forms_with_params:
        if not return_details:
            table = Table(title="Potential SQLi Parameters (from Forms)")
            table.add_column("Form", style="yellow")
            table.add_column("Parameter(s)", style="red")
            for k in sorted(forms_with_params.keys())[:50]:
                params = ", ".join(sorted(forms_with_params[k]))
                table.add_row(k, params)
            console.print(table)
        found_any = True

    if found_any:
        if not return_details:
            console.print("[yellow]Found potential SQLi indicators (no exploitation attempted)[/yellow]")
            score = 85 if error_disclosures else (35 if urls_with_params else (30 if forms_with_params else 0))
            console.print(f"[bold]Score:[/bold] {score}/100 ({risk_label(score)})")

        if return_details:
            findings = []
            max_score = 0

            for u in sorted(error_disclosures):
                score = 85
                max_score = max(max_score, score)
                findings.append({
                    "module": "SQLi Indicators",
                    "url": u,
                    "score": score,
                    "risk": risk_label(score),
                    "detail": "Possible SQL error disclosure"
                })

            for u in sorted(urls_with_params.keys()):
                score = 35
                max_score = max(max_score, score)
                findings.append({
                    "module": "SQLi Indicators",
                    "url": u,
                    "score": score,
                    "risk": risk_label(score),
                    "detail": f"Params: {', '.join(sorted(urls_with_params[u]))}"
                })

            for k in sorted(forms_with_params.keys()):
                score = 30
                max_score = max(max_score, score)
                findings.append({
                    "module": "SQLi Indicators",
                    "url": k,
                    "score": score,
                    "risk": risk_label(score),
                    "detail": f"Params: {', '.join(sorted(forms_with_params[k]))}"
                })

            return {"score": max_score, "findings": findings}

        return True

    if not return_details:
        console.print("[green]No obvious SQLi indicators detected[/green]")
    return {"score": 0, "findings": []} if return_details else False

# =========================================================
# SECURITY AUDIT FEATURES
# =========================================================

# Defensive checks for authorized environments only
RISKY_UPLOAD_EXTENSIONS = {
    ".php",
    ".phtml",
    ".php5",
    ".phar",
    ".asp",
    ".aspx",
    ".jsp"
}

UPLOAD_DIRECTORIES = {
    "uploads",
    "upload",
    "files",
    "images",
    "tmp",
    "temp",
    "cache",
    "media"
}

DANGEROUS_PERMISSIONS = {
    0o777,
    0o775
}

# =========================================================
# CONFIG
# =========================================================

WEB_EXTENSIONS = {
    ".php",
    ".phtml",
    ".php5",
    ".asp",
    ".aspx",
    ".jsp",
    ".jspx",
    ".cgi",
    ".pl",
    ".py"
}

SUSPICIOUS_PATTERNS = {
    "base64_decode": r"base64_decode\\s*\\(",
    "eval": r"eval\\s*\\(",
    "shell_exec": r"shell_exec\\s*\\(",
    "system": r"system\\s*\\(",
    "exec": r"exec\\s*\\(",
    "passthru": r"passthru\\s*\\(",
    "gzinflate": r"gzinflate\\s*\\(",
    "assert": r"assert\\s*\\(",
    "preg_replace_e": r"preg_replace.*?/e",
    "cmd_param": r"cmd=",
    "wget": r"wget\\s+http",
    "curl": r"curl\\s+http",
    "python_reverse": r"socket\\.socket",
    "chmod777": r"chmod\\s*\\(\\s*777",
}

SUSPICIOUS_FILENAMES = {
    "shell.php",
    "cmd.php",
    "r57.php",
    "c99.php",
    "upload.php",
    "backdoor.php",
    "files.php",
    "404.php",
    "1.php",
    "test.php"
}

DEFAULT_LOGS = [
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access_log",
]

scan_results = []
lock = threading.Lock()

# =========================================================
# HELPERS
# =========================================================


def banner():
    art = r"""
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██████╗ ██╗   ██╗██╗     ███████╗███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔══██╗██║   ██║██║     ██╔════╝██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║██████╔╝██║   ██║██║     ███████╗█████╗  
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝███████╗███████║███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝
"""
    console.print(f"[bold red]{art}[/bold red]")
    console.print(
        Panel.fit(
            "Real-time Defensive Web Audit\n"
            "Authorized Use Only",
            border_style="red"
        )
    )


def sha256_file(path):
    h = hashlib.sha256()

    try:
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "ERROR"



def entropy(data):
    if not data:
        return 0

    counter = Counter(data)
    length = len(data)

    return -sum((count / length) * math.log2(count / length)
                for count in counter.values())



def is_web_file(path):
    return any(path.lower().endswith(ext) for ext in WEB_EXTENSIONS)


# =========================================================
# DETECTION ENGINE
# =========================================================


def analyze_file(path):
    findings = []

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Pattern matching
        for name, pattern in SUSPICIOUS_PATTERNS.items():
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(name)

        # Filename heuristics
        filename = os.path.basename(path).lower()

        if filename in SUSPICIOUS_FILENAMES:
            findings.append("suspicious_filename")

        # Entropy
        ent = entropy(content)

        if ent > 5.5:
            findings.append(f"high_entropy:{round(ent, 2)}")

        # Long base64 strings
        if re.search(r"[A-Za-z0-9+/]{200,}={0,2}", content):
            findings.append("possible_base64_payload")

        if findings:
            result = {
                "path": path,
                "findings": findings,
                "sha256": sha256_file(path),
                "size": os.path.getsize(path),
                "modified": datetime.fromtimestamp(
                    os.path.getmtime(path)
                ).isoformat()
            }

            with lock:
                scan_results.append(result)

    except Exception:
        pass



def worker(queue):
    while True:
        item = queue.get()

        if item is None:
            break

        analyze_file(item)
        queue.task_done()



def scan_directory(directory, threads=8):
    console.print(f"\n[cyan][*][/cyan] Scanning: {directory}")

    queue = Queue()
    workers = []

    for _ in range(threads):
        t = threading.Thread(target=worker, args=(queue,), daemon=True)
        t.start()
        workers.append(t)

    with Progress() as progress:
        task = progress.add_task("[red]Scanning...", total=None)

        for root, _, files in os.walk(directory):
            for file in files:
                path = os.path.join(root, file)

                if is_web_file(path):
                    queue.put(path)

        queue.join()
        progress.update(task, completed=100)

    for _ in workers:
        queue.put(None)

    for t in workers:
        t.join(timeout=1)

    console.print("[green][✓][/green] Scan complete")


# =========================================================
# REPORTING
# =========================================================


def display_results():
    if not scan_results:
        console.print("\n[green]No suspicious files found[/green]")
        return

    table = Table(title="Suspicious Files")

    table.add_column("#", style="cyan")
    table.add_column("Path", style="yellow")
    table.add_column("Findings", style="red")
    table.add_column("Size")

    for i, result in enumerate(scan_results, 1):
        table.add_row(
            str(i),
            result["path"],
            ", ".join(result["findings"]),
            str(result["size"])
        )

    console.print(table)



def export_report():
    filename = f"webshell_report_{int(time.time())}.json"

    with open(filename, "w") as f:
        json.dump(scan_results, f, indent=4)

    console.print(f"[green][✓][/green] Report saved: {filename}")


# =========================================================
# SECURITY MISCONFIGURATION AUDIT
# =========================================================


def audit_upload_surfaces(directory):
    findings = []

    console.print("[cyan][*][/cyan] Auditing upload surfaces...")

    for root, dirs, files in os.walk(directory):
        for d in dirs:
            lower = d.lower()

            if lower in UPLOAD_DIRECTORIES:
                full = os.path.join(root, d)

                try:
                    perms = oct(os.stat(full).st_mode & 0o777)
                except Exception:
                    perms = "unknown"

                findings.append({
                    "directory": full,
                    "permissions": perms,
                    "risk": "upload_surface"
                })

    if findings:
        table = Table(title="Potential Upload Surfaces")
        table.add_column("Directory", style="yellow")
        table.add_column("Permissions", style="red")
        table.add_column("Risk")

        for item in findings:
            table.add_row(
                item["directory"],
                item["permissions"],
                item["risk"]
            )

        console.print(table)
    else:
        console.print("[green]No risky upload directories detected[/green]")



def audit_permissions(directory):
    console.print("[cyan][*][/cyan] Auditing dangerous permissions...")

    table = Table(title="Dangerous Permissions")
    table.add_column("Path", style="yellow")
    table.add_column("Permission", style="red")

    found = False

    for root, dirs, files in os.walk(directory):
        for name in dirs + files:
            path = os.path.join(root, name)

            try:
                perm = os.stat(path).st_mode & 0o777

                if perm in DANGEROUS_PERMISSIONS:
                    table.add_row(path, oct(perm))
                    found = True
            except Exception:
                pass

    if found:
        console.print(table)
    else:
        console.print("[green]No dangerous permissions found[/green]")


# =========================================================
# LOG ANALYSIS
# =========================================================


def analyze_logs():
    suspicious = [
        r"cmd=",
        r"exec=",
        r"shell=",
        r"base64",
        r"multipart/form-data",
        r"wget",
        r"curl",
    ]

    findings = []

    for log in DEFAULT_LOGS:
        if not os.path.exists(log):
            continue

        console.print(f"[cyan][*][/cyan] Reading log: {log}")

        try:
            with open(log, "r", errors="ignore") as f:
                for line in f:
                    for pattern in suspicious:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append(line.strip())
                            break
        except Exception:
            pass

    if findings:
        table = Table(title="Suspicious Log Entries")
        table.add_column("Entry", style="red")

        for item in findings[:50]:
            table.add_row(item)

        console.print(table)
    else:
        console.print("[green]No suspicious log entries found[/green]")


# =========================================================
# QUARANTINE
# =========================================================


def quarantine_file():
    if not scan_results:
        console.print("[yellow]No scan results available[/yellow]")
        return

    path = Prompt.ask("Enter file path to quarantine")

    if not os.path.exists(path):
        console.print("[red]File not found[/red]")
        return

    quarantine_dir = "quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)

    dest = os.path.join(quarantine_dir, os.path.basename(path))

    try:
        shutil.move(path, dest)
        console.print(f"[green][✓][/green] Quarantined: {dest}")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


# =========================================================
# HASH INVENTORY
# =========================================================


def generate_inventory():
    directory = Prompt.ask("Directory to inventory")

    if not os.path.exists(directory):
        console.print("[red]Directory not found[/red]")
        return

    inventory = []

    for root, _, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)

            try:
                inventory.append({
                    "path": path,
                    "sha256": sha256_file(path),
                    "size": os.path.getsize(path)
                })
            except Exception:
                pass

    filename = f"inventory_{int(time.time())}.json"

    with open(filename, "w") as f:
        json.dump(inventory, f, indent=4)

    console.print(f"[green][✓][/green] Inventory saved: {filename}")


# =========================================================
# MENU
# =========================================================


def menu():
    console.print("\n[bold cyan]VulnPulse[/bold cyan]")

    domain = ""
    while not domain:
        domain = normalize_domain(Prompt.ask("Target Domain"))

    console.print(f"[cyan][*][/cyan] Target: {domain}")
    console.print("[cyan][*][/cyan] Scan awal: File Upload Misconfiguration")
    check_upload_misconfig(domain)

    while True:
        console.print("""
[1] Scan File Upload Misconfiguration
[2] Scan SQL Injection Indicators
[3] Scan Directory Listing Exposure
[4] Scan Backup File Exposure
[5] Scan Missing Security Headers
[6] Scan Admin Panel Discovery
[7] Scan Sensitive File Exposure
[8] Scan CMS Fingerprint
[9] Scan Public Git Exposure
[10] Scan Dangerous HTTP Methods
[11] Change Target Domain
[12] Run All Scans (Auto)
[13] Scan XSS Indicators (DOM/HTML)
[0] Exit
""")

        choice = Prompt.ask("Select")

        if choice == "1":
            check_upload_misconfig(domain)

        elif choice == "2":
            check_sqli_indicators(domain)

        elif choice == "3":
            check_directory_listing(domain)

        elif choice == "4":
            check_backup_files(domain)

        elif choice == "5":
            check_missing_security_headers(domain)

        elif choice == "6":
            check_admin_panels(domain)

        elif choice == "7":
            check_env_files(domain)

        elif choice == "8":
            fingerprint_cms(domain)

        elif choice == "9":
            check_git_exposure(domain)

        elif choice == "10":
            check_http_methods(domain)

        elif choice == "11":
            domain = ""
            while not domain:
                domain = normalize_domain(Prompt.ask("Target Domain"))
            console.print(f"[cyan][*][/cyan] Target: {domain}")
            console.print("[cyan][*][/cyan] Scan awal: File Upload Misconfiguration")
            check_upload_misconfig(domain)

        elif choice == "12":
            module_results = []
            all_findings = []

            def run(name, fn):
                try:
                    result = fn(domain) or {"score": 0, "findings": []}
                    score = clamp_score(result.get("score", 0))
                    findings = result.get("findings") or []
                    module_results.append({
                        "module": name,
                        "score": score,
                        "risk": risk_label(score),
                        "count": len(findings),
                        "top_url": (findings[0].get("url") if findings else "")
                    })
                    for f in findings:
                        all_findings.append(f)
                except Exception as e:
                    module_results.append({
                        "module": name,
                        "score": 0,
                        "risk": "ERROR",
                        "count": 0,
                        "top_url": ""
                    })
                    all_findings.append({
                        "module": name,
                        "url": domain,
                        "score": 0,
                        "risk": "ERROR",
                        "detail": str(e)
                    })

            with Progress() as progress:
                session = get_http_session()
                task = progress.add_task("[cyan]Running all scans...", total=11)
                for name, fn in [
                    ("Upload Misconfig", lambda d: check_upload_misconfig(d, session=session, show_progress=False, return_details=True)),
                    ("SQLi Indicators", lambda d: check_sqli_indicators(d, session=session, show_progress=False, return_details=True)),
                    ("Directory Listing", lambda d: check_directory_listing(d, session=session, show_progress=False, return_details=True)),
                    ("Backup Files", lambda d: check_backup_files(d, session=session, show_progress=False, return_details=True)),
                    ("Missing Headers", lambda d: check_missing_security_headers(d, session=session, return_details=True)),
                    ("Admin Panels", lambda d: check_admin_panels(d, session=session, show_progress=False, return_details=True)),
                    ("Sensitive Files", lambda d: check_env_files(d, session=session, show_progress=False, return_details=True)),
                    ("CMS Fingerprint", lambda d: fingerprint_cms(d, session=session, return_details=True)),
                    ("Git Exposure", lambda d: check_git_exposure(d, session=session, return_details=True)),
                    ("HTTP Methods", lambda d: check_http_methods(d, session=session, return_details=True)),
                    ("XSS Indicators", lambda d: check_xss_indicators(d, session=session, show_progress=False, return_details=True)),
                ]:
                    run(name, fn)
                    progress.advance(task)

            overall = clamp_score(max([m["score"] for m in module_results], default=0))
            overall_risk = risk_label(overall)

            console.print(
                Panel.fit(
                    f"Target: {domain}\n"
                    f"Overall Score: {overall}/100\n"
                    f"Overall Risk: {overall_risk}",
                    border_style="cyan"
                )
            )

            summary = Table(title="Scan Summary (Scored)")
            summary.add_column("Module", style="yellow")
            summary.add_column("Score")
            summary.add_column("Risk")
            summary.add_column("Findings")
            summary.add_column("Top URL", style="cyan")

            module_results.sort(key=lambda x: x["score"], reverse=True)
            for m in module_results:
                summary.add_row(
                    m["module"],
                    str(m["score"]),
                    m["risk"],
                    str(m["count"]),
                    (m["top_url"] or "-")
                )

            console.print(summary)

            if all_findings:
                all_findings.sort(key=lambda x: int(x.get("score", 0)), reverse=True)
                table = Table(title="Top Findings (URLs + Score)")
                table.add_column("Score")
                table.add_column("Risk")
                table.add_column("Module", style="yellow")
                table.add_column("URL", style="cyan")
                table.add_column("Detail", style="red")

                for f in all_findings[:30]:
                    table.add_row(
                        str(clamp_score(f.get("score", 0))),
                        str(f.get("risk", "")),
                        str(f.get("module", "")),
                        str(f.get("url", "")),
                        str(f.get("detail", ""))
                    )

                console.print(table)

        elif choice == "13":
            check_xss_indicators(domain)

        elif choice == "0":
            console.print("[bold red]Goodbye[/bold red]")
            break

        else:
            console.print("[red]Invalid choice[/red]")


# =========================================================
# CLI MODE
# =========================================================

import argparse


def cli_mode():
    parser = argparse.ArgumentParser(
        description="VulnPulse - Defensive Web Audit Toolkit"
    )

    parser.add_argument(
        "-d",
        "--directory",
        help="Target directory to scan"
    )

    parser.add_argument(
        "-l",
        "--logs",
        action="store_true",
        help="Analyze web server logs"
    )

    parser.add_argument(
        "-e",
        "--export",
        action="store_true",
        help="Export JSON report"
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Quiet mode"
    )

    args = parser.parse_args()

    if args.directory:
        if not os.path.exists(args.directory):
            console.print("[red]Directory not found[/red]")
            return True

        if not args.quiet:
            banner()

        scan_directory(args.directory)
        display_results()

        if args.export:
            export_report()

        return True

    if args.logs:
        if not args.quiet:
            banner()

        analyze_logs()
        return True

    return False


# =========================================================
# MAIN
# =========================================================


def main():
    os.system("cls" if os.name == "nt" else "clear")

    # CLI MODE
    if cli_mode():
        return

    # INTERACTIVE MODE
    banner()
    menu()


if __name__ == "__main__":
    main()
