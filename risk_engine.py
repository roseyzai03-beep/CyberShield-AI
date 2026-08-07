"""
risk_engine.py
Cybersecurity risk calculation logic.
Performs lightweight static analysis on uploaded files and
produces a risk score, risk level, and list of detected threats.
"""
import os
import re
import math
from collections import Counter

# Keyword / pattern signatures that raise suspicion
SUSPICIOUS_PATTERNS = {
    'eval(': 'Use of eval() — possible code injection',
    'exec(': 'Use of exec() — possible arbitrary code execution',
    'base64.b64decode': 'Base64 decoding — possible payload obfuscation',
    'powershell': 'PowerShell reference — possible script-based attack',
    'cmd.exe': 'Direct shell invocation detected',
    'DROP TABLE': 'Possible SQL injection payload',
    'UNION SELECT': 'Possible SQL injection payload',
    '<script>': 'Embedded script tag — possible XSS payload',
    'os.system': 'Direct OS command execution',
    'subprocess.Popen': 'Subprocess spawning detected',
    '0.0.0.0': 'Wildcard bind address — possible backdoor listener',
    'nc -e': 'Netcat reverse shell pattern',
    '/etc/passwd': 'Reference to sensitive system file',
    'malware': 'Explicit malware reference',
    'ransomware': 'Explicit ransomware reference',
    'keylogger': 'Keylogging reference',
}
HIGH_RISK_EXTENSIONS = {'exe', 'bat', 'ps1', 'vbs', 'scr'}
def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte string (0-8). High entropy can
    indicate encryption, compression, or obfuscated/packed payloads."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)
def analyze_file(filepath: str, filename: str) -> dict:
    threats = []
    score = 0
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    file_size = os.path.getsize(filepath)
    # 1. Extension-based risk
    if ext in HIGH_RISK_EXTENSIONS:
        threats.append(f'High-risk executable extension (.{ext})')
        score += 30
    # 2. Read file safely (as bytes, then attempt text decode)
    with open(filepath, 'rb') as f:
        raw = f.read()
    entropy = shannon_entropy(raw)
    if entropy > 7.5:
        threats.append(f'High entropy content ({entropy}/8) — possible packed/encrypted payload')
        score += 25
    elif entropy > 6.5:
        threats.append(f'Elevated entropy content ({entropy}/8)')
        score += 10
    try:
        text = raw.decode('utf-8', errors='ignore')
    except Exception:
        text = ''
    # 3. Signature / keyword scan
    for pattern, description in SUSPICIOUS_PATTERNS.items():
        if pattern.lower() in text.lower():
            threats.append(description)
            score += 12
    # 4. Suspicious IP / URL patterns
    ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    if len(ip_matches) > 3:
        threats.append(f'Multiple embedded IP addresses found ({len(ip_matches)})')
        score += 10
    url_matches = re.findall(r'https?://[^\s\'"]+', text)
    if len(url_matches) > 5:
        threats.append(f'Large number of embedded URLs found ({len(url_matches)})')
        score += 8
    # 5. File size heuristic
    if file_size > 15 * 1024 * 1024:
        threats.append('Unusually large file size')
        score += 5
    score = min(score, 100)
    risk_level = score_to_level(score)
    details = {
        'file_size_bytes': file_size,
        'entropy': entropy,
        'extension': ext,
        'ip_count': len(ip_matches),
        'url_count': len(url_matches),
    }
    if not threats:
        threats.append('No known suspicious signatures detected')
    return {
        'risk_score': score,
        'risk_level': risk_level,
        'threats': threats,
        'details': details,
    }

def score_to_level(score: int) -> str:
    if score >= 70:
        return 'Critical'
    elif score >= 45:
        return 'High'
    elif score >= 20:
        return 'Medium'
    else:
        return 'Low'
def get_risk_summary(scans: list) -> dict:
    """Aggregate stats for dashboard view."""
    if not scans:
        return {
            'total_scans': 0,
            'avg_score': 0,
            'level_counts': {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0},
        }
    total = len(scans)
    avg_score = round(sum(s['risk_score'] for s in scans) / total, 1)
    level_counts = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
    for s in scans:
        level_counts[s['risk_level']] = level_counts.get(s['risk_level'], 0) + 1
    return {
        'total_scans': total,
        'avg_score': avg_score,
        'level_counts': level_counts,
    }


# ---------------------------------------------------------------
# Text analysis (used by the /text-detection page and its JSON API)
# ---------------------------------------------------------------

# Plain "feared" words that indicate a threatening / malicious message.
FEARED_KEYWORDS = {
    'malware': 'Explicit malware reference',
    'ransomware': 'Explicit ransomware reference',
    'phishing': 'Phishing reference',
    'keylogger': 'Keylogging reference',
    'trojan': 'Trojan reference',
    'spyware': 'Spyware reference',
    'botnet': 'Botnet reference',
    'rootkit': 'Rootkit reference',
    'backdoor': 'Backdoor reference',
    'ddos': 'DDoS attack reference',
    'exploit': 'Exploit reference',
    'payload': 'Payload reference',
    'bomb': 'Threatening language detected',
    'attack': 'Threatening language detected',
    'hack': 'Hacking reference',
    'password': 'Credential reference',
    'otp': 'One-time-password (OTP) request — common phishing lure',
    'credit card': 'Credit card data reference',
    'bank account': 'Bank account data reference',
    'urgent': 'Urgency pressure — common social-engineering tactic',
    'click here': 'Suspicious call-to-action link',
    'verify your account': 'Account-verification phishing lure',
    'wire transfer': 'Money transfer request',
    'bitcoin': 'Cryptocurrency payment demand',
}


def analyze_text(text: str) -> dict:
    """Scan a raw block of text for suspicious code patterns, feared words,
    embedded IPs/URLs, and obfuscation hints. Mirrors analyze_file()."""
    threats = []
    matched_keywords = []
    score = 0
    lowered = text.lower()

    # 1. Code / command injection signatures
    for pattern, description in SUSPICIOUS_PATTERNS.items():
        if pattern.lower() in lowered:
            threats.append(description)
            matched_keywords.append(pattern)
            score += 12

    # 2. Feared / social-engineering keywords
    for keyword, description in FEARED_KEYWORDS.items():
        if keyword in lowered and keyword not in matched_keywords:
            if description not in threats:
                threats.append(description)
            matched_keywords.append(keyword)
            score += 8

    # 3. Embedded IPs and URLs
    ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    if ip_matches:
        threats.append(f'Embedded IP address(es) found ({len(ip_matches)})')
        score += 6 * min(len(ip_matches), 3)

    url_matches = re.findall(r'https?://[^\s\'"]+', text)
    if url_matches:
        threats.append(f'Embedded URL(s) found ({len(url_matches)})')
        score += 5 * min(len(url_matches), 3)

    # 4. Long base64-looking blobs (obfuscated payloads)
    if re.search(r'[A-Za-z0-9+/]{60,}={0,2}', text):
        threats.append('Long base64-like blob — possible obfuscated payload')
        score += 15

    score = min(score, 100)
    risk_level = score_to_level(score)

    if not threats:
        threats.append('No known suspicious signatures detected')

    details = {
        'char_count': len(text),
        'word_count': len(text.split()),
        'matched_keywords': matched_keywords,
        'ip_count': len(ip_matches),
        'url_count': len(url_matches),
    }

    return {
        'risk_score': score,
        'risk_level': risk_level,
        'threats': threats,
        'details': details,
    }
