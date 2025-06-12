#!/usr/bin/env python3
from Features import features_config, features_export, features_severity, features_subdomains, features_api, features_threatintel, features_auth, features_metrics, features_privacy, features_threat, features_vuln

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Simple Web Security Scanner")
    parser.add_argument("url", nargs="?", help="Target website URL (e.g., https://example.com)")
    parser.add_argument("--headers", action="store_true", help="Only perform header check")
    parser.add_argument("--cookies", action="store_true", help="Only perform cookie check")
    parser.add_argument("--paths", action="store_true", help="Only perform path check")
    parser.add_argument("--methods", action="store_true", help="Only perform HTTP methods check")
    parser.add_argument("--dirlist", action="store_true", help="Only check for directory listing")
    parser.add_argument("--server", action="store_true", help="Only check server/technology headers")
    parser.add_argument("--open-redirect", action="store_true", help="Check for open redirect vulnerabilities")
    parser.add_argument("--cors", action="store_true", help="Check for CORS misconfiguration")
    parser.add_argument("--https-redirect", action="store_true", help="Check HTTP to HTTPS redirection")
    parser.add_argument("--clickjacking", action="store_true", help="Check for clickjacking vulnerability")
    parser.add_argument("--jquery", action="store_true", help="Check for outdated jQuery versions")
    parser.add_argument("--robots", action="store_true", help="Check for exposed robots.txt")
    parser.add_argument("--env", action="store_true", help="Check for exposed .env file")
    parser.add_argument("--privacy", action="store_true", help="Check for privacy policy and privacy issues")
    parser.add_argument("--user-agent", type=str, default=None, help="Set a custom User-Agent")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument('--export', type=str, help='Export results to file (json/csv)')
    parser.add_argument('--export-format', type=str, choices=['json', 'csv'], default='json', help='Export format')
    parser.add_argument('--config', type=str, help='Path to config file (YAML)')
    parser.add_argument('--subdomains', action='store_true', help='Enumerate and scan subdomains')
    parser.add_argument('--api', action='store_true', help='Check for API security issues')
    parser.add_argument('--session-cookie', type=str, help='Session cookie for authenticated scans')
    parser.add_argument('--metrics', action='store_true', help='Show performance metrics')
    parser.add_argument('--uninstall', action='store_true', help='Uninstall WebSecScanner and remove all files (pipx or venv)')
    args = parser.parse_args()

    # Uninstall feature
    if args.uninstall:
        import os, sys, shutil
        print("[!] Uninstalling WebSecScanner...")
        # Detect pipx uninstall
        pipx_home = os.environ.get('PIPX_HOME')
        pipx_bin = shutil.which('pipx')
        if pipx_home or 'pipx' in sys.executable or pipx_bin:
            print("[+] Detected pipx installation. Please run the following command to uninstall:")
            print("    pipx uninstall websecscanner")
        else:
            # Try to remove venv if present
            venv_path = os.path.join(os.getcwd(), '.venv')
            if os.path.isdir(venv_path):
                print(f"[+] Removing virtual environment at {venv_path}")
                shutil.rmtree(venv_path)
                print("[+] Virtual environment removed.")
            else:
                print("[!] No virtual environment found. Please uninstall manually if needed.")
        print("[!] Uninstallation complete. Exiting.")
        sys.exit(0)

    if not args.url:
        parser.error("the following arguments are required: url")
    url = args.url

    config = features_config.load_config(args.config) if args.config else {}
    features_auth.setup_auth(args)
    start_time = features_metrics.start_metrics() if args.metrics else None

    threats = []
    vulnerabilities = []
    privacy_issues = []

    print("\n--- Vulnerability Checks ---")
    if args.headers or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        features_vuln.check_security_headers(url)
    if args.cookies or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        features_vuln.check_cookies(url)
    if args.methods or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if features_vuln.check_http_methods(url):
            vulnerabilities.append("Insecure HTTP methods allowed")
    if args.cors or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                             args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if features_vuln.check_cors(url, verbose=args.verbose):
            vulnerabilities.append("CORS misconfiguration")
    if args.https_redirect or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                       args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if features_vuln.check_https_redirect(url, verbose=args.verbose):
            vulnerabilities.append("HTTP is not redirected to HTTPS")
    if args.clickjacking or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                     args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if features_vuln.check_clickjacking(url, verbose=args.verbose):
            vulnerabilities.append("Clickjacking protection missing")
    if args.jquery or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                               args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if features_vuln.check_jquery_version(url, verbose=args.verbose):
            vulnerabilities.append("Outdated jQuery detected")
    if features_vuln.check_xss_reflection(url, verbose=args.verbose):
        vulnerabilities.append("Possible reflected XSS vulnerability")
    if features_vuln.check_sql_error(url, verbose=args.verbose):
        vulnerabilities.append("Possible SQL error message (potential SQL injection)")
    if features_vuln.check_directory_traversal(url, verbose=args.verbose):
        vulnerabilities.append("Possible directory traversal vulnerability")
    if features_vuln.check_sensitive_info_leak(url, verbose=args.verbose):
        vulnerabilities.append("Possible sensitive information leak")
    if features_vuln.check_csp_eval_unsafe_inline(url, verbose=args.verbose):
        vulnerabilities.append("CSP allows 'unsafe-eval' or 'unsafe-inline'")
    if features_vuln.check_exposed_stacktrace(url, verbose=args.verbose):
        vulnerabilities.append("Exposed stack trace detected")
    if features_vuln.check_exposed_debug(url, verbose=args.verbose):
        vulnerabilities.append("Debug mode/info exposed")

    print("\n--- Threat Checks ---")
    if args.paths or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                              args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        for t in features_threat.check_common_paths(url):
            threats.append(t)
    if args.dirlist or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if features_threat.check_directory_listing(url):
            threats.append("Directory listing enabled")
    if args.server or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                               args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        features_threat.check_server_header(url)
    if args.open_redirect or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                      args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if features_threat.check_open_redirect(url, verbose=args.verbose):
            threats.append("Possible open redirect")
    if args.robots or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                               args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if features_threat.check_robots_txt(url, verbose=args.verbose):
            threats.append("Sensitive entries in robots.txt")
    if args.env or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                            args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if features_threat.check_env_file(url, verbose=args.verbose):
            threats.append(".env file exposed")
    for f in features_threat.check_backup_files(url, verbose=args.verbose):
        threats.append(f"Exposed backup/config file: {f}")
    if features_threat.check_git_exposure(url, verbose=args.verbose):
        threats.append(".git/config exposed")
    if features_threat.check_exposed_phpinfo(url, verbose=args.verbose):
        threats.append("phpinfo() exposed")
    if features_threat.check_admin_panel_exposure(url, verbose=args.verbose):
        threats.append("Admin panel exposed")
    for f in features_threat.check_sensitive_file_disclosure(url, verbose=args.verbose):
        threats.append(f"Sensitive file exposed: {f}")
    for f in features_threat.check_test_pages(url, verbose=args.verbose):
        threats.append(f"Test/dev page exposed: {f}")
    for f in features_threat.check_exposed_readme_license(url, verbose=args.verbose):
        threats.append(f"Exposed file: {f}")

    print("\n--- Privacy Checks ---")
    if args.privacy or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env, args.privacy]):
        if features_privacy.check_privacy_policy(url, verbose=args.verbose):
            privacy_issues.append("No privacy policy page found")
        trackers = features_privacy.check_third_party_trackers(url, verbose=args.verbose)
        if trackers:
            privacy_issues.append("Third-party trackers detected: " + ", ".join(trackers))
        emails = features_privacy.check_exposed_emails(url, verbose=args.verbose)
        if emails:
            privacy_issues.append("Exposed email addresses: " + ", ".join(set(emails)))
        if features_privacy.check_cookie_consent(url, verbose=args.verbose):
            privacy_issues.append("No cookie consent banner detected")
        if features_privacy.check_gdpr_mentions(url, verbose=args.verbose):
            privacy_issues.append("No GDPR/DSGVO mention detected")
        social_links = features_privacy.check_social_media_links(url, verbose=args.verbose)
        if social_links:
            privacy_issues.append("Social media links found: " + ", ".join(set(social_links)))
        analytics_ids = features_privacy.check_analytics_id_exposure(url, verbose=args.verbose)
        if analytics_ids:
            privacy_issues.append("Analytics IDs exposed: " + ", ".join(set(analytics_ids)))
        if features_privacy.check_facebook_pixel(url, verbose=args.verbose):
            privacy_issues.append("Facebook Pixel detected")
        if features_privacy.check_google_fonts(url, verbose=args.verbose):
            privacy_issues.append("Google Fonts detected (potential privacy issue)")
        if features_privacy.check_youtube_embeds(url, verbose=args.verbose):
            privacy_issues.append("Embedded YouTube video detected")

    # Subdomain enumeration
    subdomains = []
    if args.subdomains:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        subdomains = features_subdomains.enumerate_subdomains(domain)
        print(f"[+] Found subdomains: {subdomains}")

    # API security checks
    api_findings = []
    if args.api:
        api_findings = features_api.check_api_security(url, verbose=args.verbose)

    # Collect findings with severity
    findings = {'vulnerabilities': [], 'threats': [], 'privacy_issues': [], 'api': []}
    for v in vulnerabilities:
        findings['vulnerabilities'].append({'desc': v, 'severity': features_severity.score_finding(v)})
    for t in threats:
        findings['threats'].append({'desc': t, 'severity': features_severity.score_finding(t)})
    for p in privacy_issues:
        findings['privacy_issues'].append({'desc': p, 'severity': features_severity.score_finding(p)})
    for a in api_findings:
        findings['api'].append({'desc': a, 'severity': features_severity.score_finding(a)})

    # Threat intelligence
    emails = [f['desc'] for f in findings['privacy_issues'] if 'Exposed email addresses' in f['desc']]
    ips = []  # TODO: Extract IPs from findings if needed
    ti_findings = features_threatintel.check_threat_intel(emails, ips)
    if ti_findings:
        findings['threats'].extend({'desc': f, 'severity': 'High'} for f in ti_findings)

    # Export
    if args.export:
        features_export.export_results(findings, args.export, args.export_format)

    # Metrics
    if args.metrics and start_time:
        features_metrics.end_metrics(start_time)

    print("\n=== Scan finished ===")
    print("Please review the grouped findings below:")

    # Print grouped findings with severity
    if findings['vulnerabilities']:
        print("\n=== Vulnerabilities ===")
        for v in findings['vulnerabilities']:
            print(f"  - [{v['severity']}] {v['desc']}")
    if findings['threats']:
        print("\n=== Threats ===")
        for t in findings['threats']:
            print(f"  - [{t['severity']}] {t['desc']}")
    if findings['privacy_issues']:
        print("\n=== Privacy Issues ===")
        for p in findings['privacy_issues']:
            print(f"  - [{p['severity']}] {p['desc']}")
    if findings['api']:
        print("\n=== API Issues ===")
        for a in findings['api']:
            print(f"  - [{a['severity']}] {a['desc']}")
    if not findings['threats'] and not findings['vulnerabilities'] and not findings['privacy_issues'] and not findings['api']:
        print("\nNo critical findings detected.")

if __name__ == "__main__":
    main()
