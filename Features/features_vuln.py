#!/usr/bin/env python3
import argparse
import requests
import re
from Features.features_common import SECURITY_HEADERS
# If you need to import from other features, use 'from Features.<module> import ...'

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
    """Returns True if insecure methods are allowed, else False."""
    try:
        response = requests.options(url, timeout=5)
        allowed = response.headers.get('Allow', '')
        print("\n[+] Allowed HTTP Methods:")
        if allowed:
            print(f"  [i] {allowed}")
            if any(m in allowed for m in ['PUT', 'DELETE', 'TRACE']):
                print("  [!] Insecure methods allowed!")
                return True
        else:
            print("  [–] No Allow header found.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error checking HTTP methods: {e}")
    return False

def check_cors(url, verbose=False):
    """Returns True if CORS misconfiguration is found, else False."""
    try:
        headers = {"Origin": "https://evil.com"}
        r = requests.get(url, headers=headers, timeout=5)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        print("\n[+] CORS Configuration Check:")
        if acao == "*" or acao == "https://evil.com":
            print(f"  [!] CORS misconfiguration: Access-Control-Allow-Origin: {acao}")
            return True
        if acac.lower() == "true":
            print("  [!] Access-Control-Allow-Credentials: true")
            return True
        elif acao:
            print(f"  [i] Access-Control-Allow-Origin: {acao}")
        else:
            print("  [–] No Access-Control-Allow-Origin header found.")
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"  [i] Error checking CORS: {e}")
    return False

def check_https_redirect(url, verbose=False):
    """Returns True if HTTP is NOT redirected to HTTPS, else False."""
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
            return False
        elif r.status_code == 200:
            print("  [!] HTTP is not redirected to HTTPS.")
            return True
        else:
            print(f"  [i] HTTP response code: {r.status_code}")
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"  [i] Error checking HTTP to HTTPS redirect: {e}")
    return False

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

def check_csp_eval_unsafe_inline(url, verbose=False):
    """Check if CSP allows 'unsafe-eval' or 'unsafe-inline'."""
    try:
        r = requests.get(url, timeout=5)
        csp = r.headers.get("Content-Security-Policy", "")
        if "unsafe-eval" in csp or "unsafe-inline" in csp:
            print("\n[!] CSP allows 'unsafe-eval' or 'unsafe-inline'.")
            return True
        elif verbose:
            print("\n[i] CSP does not allow 'unsafe-eval' or 'unsafe-inline'.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking CSP: {e}")
    return False

def check_exposed_stacktrace(url, verbose=False):
    """Check for exposed stack traces in the response."""
    try:
        r = requests.get(url, timeout=5)
        stack_patterns = ["Traceback (most recent call last):", "at sun.", "at org.", "System.NullReferenceException"]
        for pat in stack_patterns:
            if pat in r.text:
                print("\n[!] Exposed stack trace detected!")
                return True
        if verbose:
            print("\n[i] No stack trace detected.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking stack trace: {e}")
    return False

def check_exposed_debug(url, verbose=False):
    """Check for debug mode or debug info in the response."""
    try:
        r = requests.get(url, timeout=5)
        if "debug=true" in r.text.lower() or "debug mode" in r.text.lower():
            print("\n[!] Debug mode or debug info exposed!")
            return True
        if verbose:
            print("\n[i] No debug info detected.")
    except Exception as e:
        if verbose:
            print(f"  [i] Error checking debug info: {e}")
    return False