# Severity scoring helper

# If you need to import from other features, use 'from Features.<module> import ...'

SEVERITY_MAP = {
    'Insecure HTTP methods allowed': 'High',
    'CORS misconfiguration': 'Medium',
    'HTTP is not redirected to HTTPS': 'Medium',
    'Clickjacking protection missing': 'Medium',
    'Outdated jQuery detected': 'Low',
    'Possible reflected XSS vulnerability': 'High',
    'Possible SQL error message (potential SQL injection)': 'High',
    'Possible directory traversal vulnerability': 'High',
    'Possible sensitive information leak': 'Medium',
    "CSP allows 'unsafe-eval' or 'unsafe-inline'": 'Medium',
    'Exposed stack trace detected': 'Low',
    'Debug mode/info exposed': 'Low',
    # ...add more as needed...
}

def score_finding(desc):
    for k, v in SEVERITY_MAP.items():
        if k in desc:
            return v
    return 'Info'
