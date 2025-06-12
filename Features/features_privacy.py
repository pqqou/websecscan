#!/usr/bin/env python3
import argparse
import requests
import re

# If you need to import from other features, use 'from Features.<module> import ...'

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy"
]

COMMON_PATHS = [
    "/admin", "/.git", "/config.php", "/phpinfo", "/login", "/server-status"
]

# =========================
# Vulnerability Checks
# =========================

def check_security_headers(url):
    try:
        response = requests.get(url, timeout=5)
        print("\n[+] Security Header Check:")
        for header in SECURITY_HEADERS:
            if header in response.headers:
                print(f"  [✓] {header}: {response.headers[header]}")
            else:
                print(f"  [!] Missing: {header}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error checking headers: {e}")

def check_cookies(url):
    try:
        response = requests.get(url, timeout=5)
        print("\n[+] Cookie Security Check:")
        if not response.cookies:
            print("  [–] No cookies set.")
        for cookie in response.cookies:
            secure = '✓' if cookie.secure else '✗'
            httponly = '✓' if 'httponly' in cookie._rest else '✗'
            print(f"  Cookie: {cookie.name} | Secure: {secure} | HttpOnly: {httponly}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error checking cookies: {e}")

def check_http_methods(url):
    """Check which HTTP methods are allowed."""
    try:
        response = requests.options(url, timeout=5)
        allowed = response.headers.get('Allow', '')
        print("\n[+] Allowed HTTP Methods:")
        if allowed:
            print(f"  [i] {allowed}")
            if any(m in allowed for m in ['PUT', 'DELETE', 'TRACE']):
                print("  [!] Insecure methods allowed!")
        else:
            print("  [–] No Allow header found.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error checking HTTP methods: {e}")

def check_cors(url, verbose=False):
    """Check for CORS misconfiguration."""
    try:
        headers = {"Origin": "https://evil.com"}
        r = requests.get(url, headers=headers, timeout=5)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        print("\n[+] CORS Configuration Check:")
        if acao == "*" or acao == "https://evil.com":
            print(f"  [!] CORS misconfiguration: Access-Control-Allow-Origin: {acao}")
        elif acao:
            print(f"  [i] Access-Control-Allow-Origin: {acao}")
        else:
            print("  [–] No Access-Control-Allow-Origin header found.")
        if acac.lower() == "true":
            print("  [!] Access-Control-Allow-Credentials: true")
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"  [i] Error checking CORS: {e}")

def check_https_redirect(url, verbose=False):
    """Check if HTTP is redirected to HTTPS."""
    if url.startswith("https://"):
        http_url = "http://" + url[len("https://"):]
    elif url.startswith("http://"):
        http_url = url
    else:
        http_url = "http://" + url
    try:
        r = requests.get(http_url, allow_redirects=False, timeout=5)
        print("\n[+] HTTP to HTTPS Redirect Check:")
        location = r.headers.get("Location", "")
        if r.status_code in (301, 302) and location.startswith("https://"):
            print("  [✓] HTTP is redirected to HTTPS.")
        elif r.status_code == 200:
            print("  [!] HTTP is not redirected to HTTPS.")
        else:
            print(f"  [i] HTTP response code: {r.status_code}")
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"  [i] Error checking HTTP to HTTPS redirect: {e}")

def check_clickjacking(url, verbose=False):
    """Check if the site is vulnerable to clickjacking (missing X-Frame-Options)."""
    try:
        r = requests.get(url, timeout=5)
        xfo = r.headers.get("X-Frame-Options", "")
        csp = r.headers.get("Content-Security-Policy", "")
        print("\n[+] Clickjacking Protection Check:")
        if "DENY" in xfo.upper() or "SAMEORIGIN" in xfo.upper():
            print("  [✓] X-Frame-Options set: " + xfo)
        elif "frame-ancestors" in csp:
            print("  [✓] frame-ancestors directive in Content-Security-Policy.")
        else:
            print("  [!] No clickjacking protection detected!")
            return True
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"  [i] Error checking clickjacking: {e}")
    return False

def check_jquery_version(url, verbose=False):
    """Check for outdated jQuery versions in HTML."""
    import re
    try:
        r = requests.get(url, timeout=5)
        matches = re.findall(r'jquery[-\.]([0-9\.]+)\.js', r.text, re.IGNORECASE)
        print("\n[+] jQuery Version Check:")
        if matches:
            for version in matches:
                print(f"  [i] Found jQuery version: {version}")
                major = int(version.split('.')[0])
                minor = int(version.split('.')[1]) if len(version.split('.')) > 1 else 0
                if major == 1 and minor < 12:
                    print("  [!] Outdated jQuery version detected!")
                    return True
        else:
            print("  [–] No jQuery detected.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking jQuery version: {e}")
    return False

def check_xss_reflection(url, verbose=False):
    """Check for reflected XSS by injecting a simple payload."""
    payload = "<script>alert(1)</script>"
    test_url = url
    if "?" in url:
        test_url += "&xss=" + payload
    else:
        test_url += "?xss=" + payload
    try:
        r = requests.get(test_url, timeout=5)
        if payload in r.text:
            print("\n[!] Possible reflected XSS vulnerability detected!")
            return True
        elif verbose:
            print("\n[i] No reflected XSS detected.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking XSS: {e}")
    return False

def check_sql_error(url, verbose=False):
    """Check for SQL error messages by injecting a single quote."""
    test_url = url
    if "?" in url:
        test_url += "'"
    else:
        test_url += "?test='"
    try:
        r = requests.get(test_url, timeout=5)
        errors = ["sql syntax", "mysql", "syntax error", "unclosed quotation", "odbc", "pdo", "pg_query", "sqlite"]
        for err in errors:
            if err in r.text.lower():
                print("\n[!] Possible SQL error message detected!")
                return True
        if verbose:
            print("\n[i] No SQL error messages detected.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking SQL errors: {e}")
    return False

def check_directory_traversal(url, verbose=False):
    """Check for directory traversal vulnerability."""
    test_url = url
    if "?" in url:
        test_url += "&file=../../../../etc/passwd"
    else:
        test_url += "?file=../../../../etc/passwd"
    try:
        r = requests.get(test_url, timeout=5)
        if "root:x:" in r.text:
            print("\n[!] Possible directory traversal vulnerability detected!")
            return True
        elif verbose:
            print("\n[i] No directory traversal detected.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking directory traversal: {e}")
    return False

def check_sensitive_info_leak(url, verbose=False):
    """Check for sensitive info leak in page content."""
    try:
        r = requests.get(url, timeout=5)
        patterns = [r'AKIA[0-9A-Z]{16}', r'sk_live_[0-9a-zA-Z]{24,}', r'-----BEGIN PRIVATE KEY-----']
        for pat in patterns:
            if re.search(pat, r.text):
                print("\n[!] Possible sensitive information leak detected!")
                return True
        if verbose:
            print("\n[i] No sensitive information leak detected.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking sensitive info leak: {e}")
    return False

# =========================
# Threat Checks
# =========================

def check_common_paths(base_url):
    print("\n[+] Checking Common Sensitive Paths:")
    for path in COMMON_PATHS:
        test_url = base_url.rstrip("/") + path
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code == 200:
                print(f"  [!] Accessible: {test_url}")
        except requests.exceptions.RequestException:
            continue

def check_directory_listing(url):
    """Check if directory listing is enabled."""
    try:
        test_url = url.rstrip('/') + '/'
        response = requests.get(test_url, timeout=5)
        if "Index of /" in response.text and response.status_code == 200:
            print(f"\n[!] Directory listing enabled: {test_url}")
    except requests.exceptions.RequestException:
        pass

def check_server_header(url):
    """Check for server and technology revealing headers."""
    try:
        response = requests.get(url, timeout=5)
        print("\n[+] Server/Technology Headers:")
        for h in ['Server', 'X-Powered-By', 'X-AspNet-Version']:
            if h in response.headers:
                print(f"  [i] {h}: {response.headers[h]}")
    except requests.exceptions.RequestException:
        pass

def check_open_redirect(url, verbose=False):
    """Check for open redirect vulnerabilities on common endpoints."""
    test_paths = ["/redirect", "/redirect.php", "/login", "/out", "/exit"]
    payload = "https://evil.com"
    print("\n[+] Checking for open redirects:")
    for path in test_paths:
        test_url = url.rstrip("/") + path + "?next=" + payload
        try:
            r = requests.get(test_url, allow_redirects=False, timeout=5)
            location = r.headers.get("Location", "")
            if payload in location:
                print(f"  [!] Possible open redirect: {test_url} -> {location}")
            elif verbose:
                print(f"  [i] No redirect at: {test_url}")
        except requests.exceptions.RequestException as e:
            if verbose:
                print(f"  [i] Error testing {test_url}: {e}")

def check_robots_txt(url, verbose=False):
    """Check if robots.txt is exposed and contains sensitive paths."""
    from urllib.parse import urljoin
    robots_url = urljoin(url, "/robots.txt")
    try:
        r = requests.get(robots_url, timeout=5)
        print("\n[+] robots.txt Exposure Check:")
        if r.status_code == 200:
            print(f"  [i] robots.txt found at {robots_url}")
            sensitive = [line for line in r.text.splitlines() if "Disallow" in line and ("/admin" in line or "/login" in line or "/config" in line)]
            if sensitive:
                for entry in sensitive:
                    print(f"  [!] Sensitive entry: {entry}")
                return True
            else:
                print("  [i] No sensitive entries found.")
        else:
            print("  [–] robots.txt not found.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking robots.txt: {e}")
    return False

def check_env_file(url, verbose=False):
    """Check if .env file is exposed."""
    from urllib.parse import urljoin
    env_url = urljoin(url, "/.env")
    try:
        r = requests.get(env_url, timeout=5)
        print("\n[+] .env File Exposure Check:")
        if r.status_code == 200 and "APP_KEY" in r.text:
            print(f"  [!] .env file exposed at {env_url}")
            return True
        else:
            print("  [–] .env file not exposed.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking .env file: {e}")
    return False

def check_backup_files(url, verbose=False):
    """Check for exposed backup/config files."""
    from urllib.parse import urljoin
    backup_files = ["/backup.zip", "/db.sql", "/config.bak", "/website.tar.gz", "/.env.bak"]
    found = []
    for path in backup_files:
        test_url = urljoin(url, path)
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code == 200 and len(r.content) > 100:
                print(f"\n[!] Exposed backup/config file: {test_url}")
                found.append(test_url)
        except Exception:
            continue
    return found

def check_git_exposure(url, verbose=False):
    """Check if .git/config is exposed."""
    from urllib.parse import urljoin
    git_url = urljoin(url, "/.git/config")
    try:
        r = requests.get(git_url, timeout=5)
        if r.status_code == 200 and "[core]" in r.text:
            print(f"\n[!] .git/config exposed at {git_url}")
            return True
        elif verbose:
            print(f"\n[i] .git/config not exposed.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking .git/config: {e}")
    return False

def check_exposed_phpinfo(url, verbose=False):
    """Check if phpinfo() is exposed."""
    from urllib.parse import urljoin
    phpinfo_url = urljoin(url, "/phpinfo.php")
    try:
        r = requests.get(phpinfo_url, timeout=5)
        if r.status_code == 200 and "phpinfo()" in r.text:
            print(f"\n[!] phpinfo() exposed at {phpinfo_url}")
            return True
        elif verbose:
            print(f"\n[i] phpinfo() not exposed.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking phpinfo(): {e}")
    return False

def check_admin_panel_exposure(url, verbose=False):
    """Check if /admin panel is exposed."""
    from urllib.parse import urljoin
    admin_url = urljoin(url, "/admin")
    try:
        r = requests.get(admin_url, timeout=5)
        if r.status_code == 200 and ("admin" in r.text.lower() or "dashboard" in r.text.lower()):
            print(f"\n[!] Admin panel exposed at {admin_url}")
            return True
        elif verbose:
            print(f"\n[i] Admin panel not exposed.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking admin panel: {e}")
    return False

# =========================
# Privacy Checks
# =========================

def check_privacy_policy(url, verbose=False):
    """Check if a privacy policy page is present."""
    from urllib.parse import urljoin
    possible_paths = ["/privacy", "/privacy-policy", "/datenschutz", "/privacy.html", "/privacy-policy.html"]
    found = False
    for path in possible_paths:
        test_url = urljoin(url, path)
        try:
            r = requests.get(test_url, timeout=5)
            if r.status_code == 200 and ("privacy" in r.text.lower() or "datenschutz" in r.text.lower()):
                print(f"\n[+] Privacy Policy found at: {test_url}")
                found = True
                return False  # No privacy issue if found
        except Exception:
            continue
    print("\n[!] No privacy policy page found.")
    return True

def check_third_party_trackers(url, verbose=False):
    """Check for common third-party trackers in HTML."""
    try:
        r = requests.get(url, timeout=5)
        html = r.text.lower()
        trackers = {
            "Google Analytics": ["www.google-analytics.com/analytics.js", "gtag/js", "ga('create'"],
            "Google Tag Manager": ["www.googletagmanager.com/gtm.js"],
            "Facebook Pixel": ["connect.facebook.net/en_US/fbevents.js"],
            "Hotjar": ["static.hotjar.com/c/hotjar-"],
            "Matomo": ["matomo.js", "piwik.js"],
            "Cloudflare": ["cdn-cgi/"],
        }
        found = []
        for name, patterns in trackers.items():
            for pattern in patterns:
                if pattern in html:
                    found.append(name)
                    break
        print("\n[+] Third-party Trackers Check:")
        if found:
            for t in found:
                print(f"  [!] Found tracker: {t}")
            return found
        else:
            print("  [✓] No common third-party trackers detected.")
            return []
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking trackers: {e}")
        return []

def check_exposed_emails(url, verbose=False):
    """Check for exposed email addresses in HTML."""
    try:
        r = requests.get(url, timeout=5)
        emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", r.text)
        print("\n[+] Exposed Email Addresses Check:")
        filtered = [e for e in emails if not e.endswith(('.png', '.jpg', '.jpeg', '.gif'))]
        if filtered:
            for email in set(filtered):
                print(f"  [!] Exposed email: {email}")
            return filtered
        else:
            print("  [✓] No exposed email addresses found.")
            return []
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking emails: {e}")
        return []

def check_cookie_consent(url, verbose=False):
    """Check for presence of cookie consent banner."""
    try:
        r = requests.get(url, timeout=5)
        keywords = ["cookie consent", "accept cookies", "cookie banner", "cookie settings"]
        found = False
        for k in keywords:
            if k in r.text.lower():
                print("\n[+] Cookie consent banner detected.")
                found = True
                break
        if not found:
            print("\n[!] No cookie consent banner detected.")
            return True
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking cookie consent: {e}")
    return False

def check_gdpr_mentions(url, verbose=False):
    """Check for GDPR/DSGVO mentions in the privacy policy or main page."""
    try:
        r = requests.get(url, timeout=5)
        if "gdpr" in r.text.lower() or "dsgvo" in r.text.lower():
            print("\n[+] GDPR/DSGVO mention detected.")
            return False
        else:
            print("\n[!] No GDPR/DSGVO mention detected.")
            return True
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking GDPR/DSGVO: {e}")
    return False

def check_social_media_links(url, verbose=False):
    """Check for social media profile links."""
    try:
        r = requests.get(url, timeout=5)
        social_patterns = [
            "facebook.com/", "twitter.com/", "linkedin.com/", "instagram.com/", "youtube.com/"
        ]
        found = []
        for pat in social_patterns:
            if pat in r.text.lower():
                found.append(pat.split(".")[0])
        if found:
            print("\n[!] Social media links found: " + ", ".join(set(found)))
            return found
        else:
            print("\n[✓] No social media links found.")
            return []
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking social media links: {e}")
        return []

def check_analytics_id_exposure(url, verbose=False):
    """Check for exposed Google Analytics or Facebook Pixel IDs."""
    try:
        r = requests.get(url, timeout=5)
        ga_ids = re.findall(r'UA-\d{4,10}-\d{1,4}', r.text)
        fb_ids = re.findall(r'fbq\(.init.,\s*[\'"](\d+)[\'"]', r.text)
        found = []
        if ga_ids:
            found.extend(ga_ids)
        if fb_ids:
            found.extend(fb_ids)
        if found:
            print("\n[!] Analytics IDs exposed: " + ", ".join(set(found)))
            return found
        else:
            print("\n[✓] No analytics IDs exposed.")
            return []
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking analytics IDs: {e}")
        return []

def check_facebook_pixel(url, verbose=False):
    """Check for Facebook Pixel usage."""
    try:
        r = requests.get(url, timeout=5)
        if "connect.facebook.net/en_US/fbevents.js" in r.text:
            print("\n[!] Facebook Pixel detected.")
            return True
        else:
            if verbose:
                print("\n[i] No Facebook Pixel detected.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking Facebook Pixel: {e}")
    return False

def check_google_fonts(url, verbose=False):
    """Check for Google Fonts usage (potential privacy issue)."""
    try:
        r = requests.get(url, timeout=5)
        if "fonts.googleapis.com" in r.text or "fonts.gstatic.com" in r.text:
            print("\n[!] Google Fonts detected (potential privacy issue).")
            return True
        else:
            if verbose:
                print("\n[i] No Google Fonts detected.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking Google Fonts: {e}")
    return False

def check_youtube_embeds(url, verbose=False):
    """Check for embedded YouTube videos."""
    try:
        r = requests.get(url, timeout=5)
        if "youtube.com/embed/" in r.text or "youtube-nocookie.com/embed/" in r.text:
            print("\n[!] Embedded YouTube video detected.")
            return True
        else:
            if verbose:
                print("\n[i] No YouTube embeds detected.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking YouTube embeds: {e}")
    return False

# =========================
# Main
# =========================

def main():
    parser = argparse.ArgumentParser(description="Simple Web Security Scanner")
    parser.add_argument("url", help="Target website URL (e.g., https://example.com)")
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
    args = parser.parse_args()
    url = args.url

    print("\n=== Web Security Scanner (Basic) ===")
    print(f"Target: {url}")

    # Set global requests user-agent if specified
    if args.user_agent:
        requests.defaults.headers['User-Agent'] = args.user_agent

    threats = []
    vulnerabilities = []
    privacy_issues = []

    # =========================
    # Vulnerability Checks
    # =========================
    print("\n--- Vulnerability Checks ---")
    if args.headers or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        check_security_headers(url)
    if args.cookies or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        check_cookies(url)
    if args.methods or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        try:
            response = requests.options(url, timeout=5)
            allowed = response.headers.get('Allow', '')
            print("\n[+] Allowed HTTP Methods:")
            if allowed:
                print(f"  [i] {allowed}")
                if any(m in allowed for m in ['PUT', 'DELETE', 'TRACE']):
                    print("  [!] Insecure methods allowed!")
                    vulnerabilities.append(f"Insecure HTTP methods allowed: {allowed}")
            else:
                print("  [–] No Allow header found.")
        except requests.exceptions.RequestException as e:
            print(f"[!] Error checking HTTP methods: {e}")
    if args.cors or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                             args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        try:
            headers = {"Origin": "https://evil.com"}
            r = requests.get(url, headers=headers, timeout=5)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            print("\n[+] CORS Configuration Check:")
            if acao == "*" or acao == "https://evil.com":
                print(f"  [!] CORS misconfiguration: Access-Control-Allow-Origin: {acao}")
                vulnerabilities.append(f"CORS misconfiguration: Access-Control-Allow-Origin: {acao}")
            elif acao:
                print(f"  [i] Access-Control-Allow-Origin: {acao}")
            else:
                print("  [–] No Access-Control-Allow-Origin header found.")
            if acac.lower() == "true":
                print("  [!] Access-Control-Allow-Credentials: true")
                vulnerabilities.append("Access-Control-Allow-Credentials: true")
        except requests.exceptions.RequestException as e:
            if args.verbose:
                print(f"  [i] Error checking CORS: {e}")
    if args.https_redirect or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                       args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if url.startswith("https://"):
            http_url = "http://" + url[len("https://"):]
        elif url.startswith("http://"):
            http_url = url
        else:
            http_url = "http://" + url
        try:
            r = requests.get(http_url, allow_redirects=False, timeout=5)
            print("\n[+] HTTP to HTTPS Redirect Check:")
            location = r.headers.get("Location", "")
            if r.status_code in (301, 302) and location.startswith("https://"):
                print("  [✓] HTTP is redirected to HTTPS.")
            elif r.status_code == 200:
                print("  [!] HTTP is not redirected to HTTPS.")
                vulnerabilities.append("HTTP is not redirected to HTTPS")
            else:
                print(f"  [i] HTTP response code: {r.status_code}")
        except requests.exceptions.RequestException as e:
            if args.verbose:
                print(f"  [i] Error checking HTTP to HTTPS redirect: {e}")
    if args.clickjacking or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                     args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if check_clickjacking(url, verbose=args.verbose):
            vulnerabilities.append("Clickjacking protection missing")
    if args.jquery or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                               args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if check_jquery_version(url, verbose=args.verbose):
            vulnerabilities.append("Outdated jQuery detected")
    if check_xss_reflection(url, verbose=args.verbose):
        vulnerabilities.append("Possible reflected XSS vulnerability")
    if check_sql_error(url, verbose=args.verbose):
        vulnerabilities.append("Possible SQL error message (potential SQL injection)")
    if check_directory_traversal(url, verbose=args.verbose):
        vulnerabilities.append("Possible directory traversal vulnerability")
    if check_sensitive_info_leak(url, verbose=args.verbose):
        vulnerabilities.append("Possible sensitive information leak")

    # =========================
    # Threat Checks
    # =========================
    print("\n--- Threat Checks ---")
    if args.paths or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                              args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        print("\n[+] Checking Common Sensitive Paths:")
        for path in COMMON_PATHS:
            test_url = url.rstrip("/") + path
            try:
                r = requests.get(test_url, timeout=5)
                if r.status_code == 200:
                    print(f"  [!] Accessible: {test_url}")
                    threats.append(f"Sensitive path accessible: {test_url}")
            except requests.exceptions.RequestException:
                continue
    if args.dirlist or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        try:
            test_url = url.rstrip('/') + '/'
            response = requests.get(test_url, timeout=5)
            if "Index of /" in response.text and response.status_code == 200:
                print(f"\n[!] Directory listing enabled: {test_url}")
                threats.append(f"Directory listing enabled: {test_url}")
        except requests.exceptions.RequestException:
            pass
    if args.server or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                               args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        check_server_header(url)
    if args.open_redirect or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                      args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        test_paths = ["/redirect", "/redirect.php", "/login", "/out", "/exit"]
        payload = "https://evil.com"
        print("\n[+] Checking for open redirects:")
        for path in test_paths:
            test_url = url.rstrip("/") + path + "?next=" + payload
            try:
                r = requests.get(test_url, allow_redirects=False, timeout=5)
                location = r.headers.get("Location", "")
                if payload in location:
                    print(f"  [!] Possible open redirect: {test_url} -> {location}")
                    threats.append(f"Possible open redirect: {test_url} -> {location}")
                elif args.verbose:
                    print(f"  [i] No redirect at: {test_url}")
            except requests.exceptions.RequestException as e:
                if args.verbose:
                    print(f"  [i] Error testing {test_url}: {e}")
    if args.robots or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                               args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if check_robots_txt(url, verbose=args.verbose):
            threats.append("Sensitive entries in robots.txt")
    if args.env or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                            args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env]):
        if check_env_file(url, verbose=args.verbose):
            threats.append(".env file exposed")
    backup_files = check_backup_files(url, verbose=args.verbose)
    if backup_files:
        for f in backup_files:
            threats.append(f"Exposed backup/config file: {f}")
    if check_git_exposure(url, verbose=args.verbose):
        threats.append(".git/config exposed")
    if check_exposed_phpinfo(url, verbose=args.verbose):
        threats.append("phpinfo() exposed")
    if check_admin_panel_exposure(url, verbose=args.verbose):
        threats.append("Admin panel exposed")

    # =========================
    # Privacy Checks
    # =========================
    print("\n--- Privacy Checks ---")
    if args.privacy or not any([args.headers, args.cookies, args.paths, args.methods, args.dirlist, args.server,
                                args.open_redirect, args.cors, args.https_redirect, args.clickjacking, args.jquery, args.robots, args.env, args.privacy]):
        if check_privacy_policy(url, verbose=args.verbose):
            privacy_issues.append("No privacy policy page found")
        trackers = check_third_party_trackers(url, verbose=args.verbose)
        if trackers:
            privacy_issues.append("Third-party trackers detected: " + ", ".join(trackers))
        emails = check_exposed_emails(url, verbose=args.verbose)
        if emails:
            privacy_issues.append("Exposed email addresses: " + ", ".join(set(emails)))
        if check_cookie_consent(url, verbose=args.verbose):
            privacy_issues.append("No cookie consent banner detected")
        if check_gdpr_mentions(url, verbose=args.verbose):
            privacy_issues.append("No GDPR/DSGVO mention detected")
    social_links = check_social_media_links(url, verbose=args.verbose)
    if social_links:
        privacy_issues.append("Social media links found: " + ", ".join(set(social_links)))
    analytics_ids = check_analytics_id_exposure(url, verbose=args.verbose)
    if analytics_ids:
        privacy_issues.append("Analytics IDs exposed: " + ", ".join(set(analytics_ids)))

    print("\n=== Scan finished ===")
    print("Please review the grouped findings below:")

    if vulnerabilities:
        print("\n=== Vulnerabilities ===")
        for v in vulnerabilities:
            print(f"  - {v}")
    if threats:
        print("\n=== Threats ===")
        for t in threats:
            print(f"  - {t}")
    if privacy_issues:
        print("\n=== Privacy Issues ===")
        for p in privacy_issues:
            print(f"  - {p}")
    if not threats and not vulnerabilities and not privacy_issues:
        print("\nNo critical findings detected.")

if __name__ == "__main__":
    main()