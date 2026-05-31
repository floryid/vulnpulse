# VulnPulse

Real-time Defensive Web Audit Toolkit (passive scanning) + Webshell hygiene utilities.

## Highlights

- Domain audit (passive): upload surface indicators, SQLi indicators, directory listing, exposed backups, missing security headers, admin panels, sensitive files, public `.git`, dangerous HTTP methods, XSS indicators (DOM/HTML).
- Scored findings + modern summary (overall score, module score, top findings with full URLs).
- Web directory webshell scanning: suspicious patterns, entropy, hashes, quarantine, JSON report.

## Quick Start

### Requirements

- Python 3.10+ (recommended)
- Packages:
  - `rich`
  - `requests`
  - `beautifulsoup4`

Install:

```bash
pip install rich requests beautifulsoup4
```

### Run

```bash
python vuln.py
```

## Usage

When you run the app, enter your target domain once. VulnPulse will:

1. Run an initial scan (upload misconfiguration indicators)
2. Show the interactive menu so you can run other modules without re-entering the domain

### Main Menu (Domain Audit)

- **[1] Upload Misconfiguration**: discovers common upload endpoints + file-upload form indicators (passive).
- **[2] SQLi Indicators**: crawls internal pages and lists parameterized URLs/forms + possible SQL error disclosure indicators (no exploitation).
- **[3] Directory Listing**: checks common directories for “Index of”.
- **[4] Backup Exposure**: checks common backup file names (`backup.zip`, `website.zip`, etc.).
- **[5] Missing Security Headers**: checks recommended headers and scores missing items.
- **[6] Admin Panels**: probes common admin paths and reports reachable panels.
- **[7] Sensitive File Exposure**: checks common sensitive files (`.env`, `config.php.bak`, `.git/config`).
- **[8] CMS Fingerprint**: lightweight fingerprinting.
- **[9] Public Git Exposure**: checks `.git/`.
- **[10] Dangerous HTTP Methods**: checks `Allow` header from `OPTIONS`.
- **[12] Run All Scans (Auto)**: runs all modules, prints modern scored summary + full URLs.
- **[13] XSS Indicators (DOM/HTML)**: detects risk indicators (CSP weakness, DOM sinks, inline handlers) without payload injection.

## Scoring

VulnPulse assigns a **score per finding** (0–100) and a **module score**. In auto mode, it also prints:

- **Overall Score**: highest module score
- **Top Findings**: full URL + score + risk label

Risk labels:

- `CRITICAL` (90–100)
- `HIGH` (70–89)
- `MEDIUM` (40–69)
- `LOW` (1–39)
- `INFO` (0)

## Webshell Hygiene (Directory Scan)

Besides domain auditing, the codebase contains a local web directory scanner that can:

- scan for suspicious functions/patterns
- detect high-entropy content
- generate SHA-256 inventory
- quarantine suspicious files
- export JSON reports

## Safety & Scope

This tool is designed for **defensive auditing** and **authorized environments only**.

- No exploitation is performed.
- SQLi/XSS modules focus on passive indicators and error disclosure detection.

## Project Structure

- `vuln.py` — main entry point (interactive menu + scanners)

## Deploy to GitHub

Repository target: `https://github.com/floryid/vulnpulse`

From the project folder:

```bash
git init
git add .
git commit -m "Initial commit: VulnPulse"
git branch -M main
git remote add origin https://github.com/floryid/vulnpulse.git
git push -u origin main
```

If you already have a git repo, skip `git init` and only set the remote + push.

## Disclaimer

Use at your own risk. You are responsible for ensuring you have explicit authorization to test a target. The authors are not responsible for misuse or damages.
