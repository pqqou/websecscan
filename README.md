# WebSecScanner

A simple, modular web security scanner CLI tool for quick security and privacy checks of websites.

## Features
- **Vulnerability Checks**: Scans for common vulnerabilities like insecure HTTP methods, CORS, clickjacking, XSS, SQLi, directory traversal, outdated jQuery, missing security headers, and more.
- **Threat Checks**: Detects exposed admin panels, backup files, directory listing, open redirects, sensitive files, test pages, robots.txt, .env, .git/config, etc.
- **Privacy Checks**: Finds missing privacy policies, third-party trackers, Google Fonts, Facebook Pixel, embedded YouTube videos, social media links, analytics IDs, cookie banners, GDPR mentions, and more.
- **Subdomain Enumeration**: Optionally finds and scans subdomains.
- **API Security Checks**: Optionally scans for insecure API endpoints (stub, extendable).
- **Authenticated Scans**: Supports session cookies (for login-protected areas).
- **Severity Scoring**: All findings are grouped by severity.
- **Threat Intelligence**: Optionally checks exposed emails/IPs against threat intelligence sources (stub, extendable).
- **Custom Checks via Config**: Checks can be configured via YAML.
- **Export**: Export results as JSON or CSV.
- **Performance Metrics**: Optionally shows scan duration.

## Installation

### Requirements
- Python 3.8+

### CLI Tool Installation (Recommended)

1. Install [pipx](https://pypa.github.io/pipx/):
   ```pwsh
   python -m pip install --user pipx
   python -m pipx ensurepath
   # Restart your terminal if needed
   ```
2. Install WebSecScanner globally with pipx:
   ```pwsh
   pipx install .
   ```
3. Now the `websecscan` command is available everywhere:
   ```pwsh
   websecscan https://example.com
   ```

#### Alternative: Development in venv

1. Create and activate a virtual environment:
   ```pwsh
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -e .
   ```
2. Then use as above:
   ```pwsh
   websecscan https://example.com
   ```

> **Note:**
> If the command is not found, make sure you are either using pipx or have activated your virtual environment.

## Uninstallation

### If installed with pipx (recommended):
```pwsh
pipx uninstall websecscanner
```

### If installed in a virtual environment:
1. Deactivate and remove the virtual environment folder:
   ```pwsh
   deactivate
   Remove-Item -Recurse -Force .venv
   ```

> **Note:**
> This will remove the tool and all its dependencies from your system (if using pipx) or from your project folder (if using a venv).

## Usage

```pwsh
websecscan <url> [OPTIONS]
```

**Key Options:**
- `--headers`, `--cookies`, `--paths`, `--methods`, `--dirlist`, `--server`, `--open-redirect`, `--cors`, `--https-redirect`, `--clickjacking`, `--jquery`, `--robots`, `--env`, `--privacy` – Run individual checks
- `--user-agent <str>` – Set a custom User-Agent
- `-v`, `--verbose` – Verbose output
- `--export <path>` – Export results as JSON/CSV
- `--export-format json|csv` – Choose export format
- `--config <path>` – Configure checks via YAML
- `--subdomains` – Scan subdomains
- `--api` – API security checks
- `--session-cookie <cookie>` – Authenticated scans
- `--metrics` – Show scan duration

## Example

```pwsh
websecscan https://example.com --privacy --export results.json --metrics
```

## Dependencies
- requests
- pyyaml

(All dependencies are installed automatically.)

## Extensibility
- Checks and features are modularized in the `Features/` folder and can be easily extended.

---

**Note:**
Some features (API checks, threat intelligence) are provided as stubs and can be extended as needed.

---

MIT License
