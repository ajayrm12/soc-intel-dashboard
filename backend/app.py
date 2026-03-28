"""
SecOps Intelligence Dashboard - Backend (app.py)
Author: Senior Cybersecurity Engineer
Description: SOC-level threat analysis using VirusTotal, AbuseIPDB, ip-api, and python-whois
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import whois
import re
import time
import datetime
import base64
import os
from functools import lru_cache
from urllib.parse import urlparse

app = Flask(__name__, static_folder="static")

# Allow requests from any origin — needed for local HTML file access (file://)
CORS(app, resources={r"/api/*": {"origins": "*"}},
     supports_credentials=False)

# Belt-and-suspenders: add CORS headers to every API response
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
    return response

@app.route("/api/<path:path>", methods=["OPTIONS"])
def handle_options(path):
    """Handle CORS preflight for all API routes."""
    from flask import Response
    return Response("", 204, headers={
        "Access-Control-Allow-Origin":  "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST, GET, OPTIONS"
    })

# ─────────────────────────────────────────────
# API KEYS — Set these in Render Environment Variables
# ─────────────────────────────────────────────
VT_API_KEY      = os.environ.get("VT_API_KEY", "")
ABUSEIPDB_KEY   = os.environ.get("ABUSEIPDB_KEY", "")

# ─────────────────────────────────────────────
# Simple in-memory cache: {cache_key: (timestamp, result)}
# ─────────────────────────────────────────────
_cache = {}
CACHE_TTL = 300  # 5 minutes

def cache_get(key):
    if key in _cache:
        ts, val = _cache[key]
        if time.time() - ts < CACHE_TTL:
            return val
    return None

def cache_set(key, val):
    _cache[key] = (time.time(), val)


# ══════════════════════════════════════════════
# VIRUSTOTAL HELPERS
# ══════════════════════════════════════════════

def vt_headers():
    return {"x-apikey": VT_API_KEY, "Accept": "application/json"}


def vt_scan_url(url):
    """
    Step 1: Submit a URL to VirusTotal for scanning.
    Returns the analysis ID needed to fetch results.
    """
    endpoint = "https://www.virustotal.com/api/v3/urls"
    # VirusTotal requires URL to be base64-encoded (URL-safe, no padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    # First check if we already have a report
    check = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=vt_headers(), timeout=10
    )
    if check.status_code == 200:
        return {"status": "existing", "data": check.json()}

    # Otherwise submit for fresh scan
    resp = requests.post(
        endpoint,
        headers={**vt_headers(), "Content-Type": "application/x-www-form-urlencoded"},
        data=f"url={requests.utils.quote(url, safe='')}",
        timeout=10
    )
    if resp.status_code == 200:
        analysis_id = resp.json()["data"]["id"]
        return {"status": "submitted", "analysis_id": analysis_id}
    return {"status": "error", "message": resp.text}


def vt_get_analysis(analysis_id):
    """
    Step 2: Poll VirusTotal for analysis results using the ID from step 1.
    Waits up to 20 seconds for the scan to complete.
    """
    endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    for attempt in range(5):
        resp = requests.get(endpoint, headers=vt_headers(), timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            status = data["data"]["attributes"]["status"]
            if status == "completed":
                return data
            # Still queued/running — wait and retry
        time.sleep(4)
    return None


def vt_parse_stats(attributes):
    """Extract malicious/suspicious/harmless counts from VT attributes."""
    stats = attributes.get("last_analysis_stats", {})
    return {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total":      sum(stats.values())
    }


def analyze_url_vt(url):
    """
    Full VirusTotal URL analysis: submit → wait → fetch → parse.
    Returns structured result dict.
    """
    cache_key = f"vt_url:{url}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    result = vt_scan_url(url)

    if result["status"] == "error":
        return {"error": result["message"]}

    if result["status"] == "existing":
        attrs = result["data"]["data"]["attributes"]
        stats = vt_parse_stats(attrs)
        out = {"url": url, "stats": stats, "source": "cached_vt"}
        cache_set(cache_key, out)
        return out

    # Newly submitted — fetch analysis
    analysis = vt_get_analysis(result["analysis_id"])
    if not analysis:
        return {"url": url, "error": "Analysis timed out"}

    attrs = analysis["data"]["attributes"]
    stats = vt_parse_stats(attrs)
    out = {"url": url, "stats": stats, "source": "fresh_vt"}
    cache_set(cache_key, out)
    return out


def analyze_ip_vt(ip):
    """Analyze an IP address with VirusTotal."""
    cache_key = f"vt_ip:{ip}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    resp = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers=vt_headers(), timeout=10
    )
    if resp.status_code != 200:
        return {"error": f"VT IP lookup failed: {resp.status_code}"}

    attrs = resp.json()["data"]["attributes"]
    stats = vt_parse_stats(attrs)
    out = {
        "ip": ip,
        "stats": stats,
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country", "Unknown"),
        "as_owner": attrs.get("as_owner", "Unknown"),
        "network": attrs.get("network", "Unknown")
    }
    cache_set(cache_key, out)
    return out


def analyze_domain_vt(domain):
    """Analyze a domain with VirusTotal."""
    cache_key = f"vt_domain:{domain}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    resp = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers=vt_headers(), timeout=10
    )
    if resp.status_code != 200:
        return {"error": f"VT Domain lookup failed: {resp.status_code}"}

    attrs = resp.json()["data"]["attributes"]
    stats = vt_parse_stats(attrs)
    out = {
        "domain": domain,
        "stats": stats,
        "reputation": attrs.get("reputation", 0),
        "categories": attrs.get("categories", {}),
        "creation_date": attrs.get("creation_date", None),
        "registrar": attrs.get("registrar", "Unknown")
    }
    cache_set(cache_key, out)
    return out


# ══════════════════════════════════════════════
# ABUSEIPDB
# ══════════════════════════════════════════════

def check_abuseipdb(ip):
    """Query AbuseIPDB for abuse confidence score and report count."""
    cache_key = f"abuse:{ip}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    if not ABUSEIPDB_KEY:
        return {"error": "AbuseIPDB key not configured"}

    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        timeout=10
    )
    if resp.status_code != 200:
        return {"error": f"AbuseIPDB error: {resp.status_code}"}

    data = resp.json()["data"]
    out = {
        "ip": ip,
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "total_reports":    data.get("totalReports", 0),
        "country":          data.get("countryCode", "Unknown"),
        "isp":              data.get("isp", "Unknown"),
        "domain":           data.get("domain", "Unknown"),
        "is_tor":           data.get("isTor", False),
        "is_whitelisted":   data.get("isWhitelisted", False),
        "last_reported":    data.get("lastReportedAt", None)
    }
    cache_set(cache_key, out)
    return out


# ══════════════════════════════════════════════
# GEO-LOCATION
# ══════════════════════════════════════════════

def get_geolocation(ip):
    """Get geographic data for an IP address."""
    cache_key = f"geo:{ip}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    resp = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5)
    if resp.status_code != 200:
        return {"error": "Geo lookup failed"}

    data = resp.json()
    if data.get("status") != "success":
        return {"error": data.get("message", "Unknown error")}

    out = {
        "ip":          ip,
        "country":     data.get("country"),
        "countryCode": data.get("countryCode"),
        "region":      data.get("regionName"),
        "city":        data.get("city"),
        "zip":         data.get("zip"),
        "lat":         data.get("lat"),
        "lon":         data.get("lon"),
        "timezone":    data.get("timezone"),
        "isp":         data.get("isp"),
        "org":         data.get("org"),
        "as_number":   data.get("as"),
        "hosting":     data.get("hosting", False),
        "proxy":       data.get("proxy", False),
        "vpn":         data.get("vpn", False),
        "tor":         data.get("tor", False)
    }
    cache_set(cache_key, out)
    return out


# ══════════════════════════════════════════════
# DOMAIN AGE (WHOIS)
# ══════════════════════════════════════════════

def get_domain_age(domain):
    """Fetch domain registration date and calculate age in days."""
    cache_key = f"whois:{domain}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.datetime.now() - creation).days
            out = {
                "domain":       domain,
                "creation_date": str(creation),
                "age_days":     age_days,
                "registrar":    w.registrar or "Unknown",
                "expiration":   str(w.expiration_date) if w.expiration_date else "Unknown"
            }
            cache_set(cache_key, out)
            return out
    except Exception as e:
        pass
    return {"domain": domain, "creation_date": None, "age_days": None, "registrar": "Unknown"}


# ══════════════════════════════════════════════
# THREAT SCORE ENGINE (0–100)
# ══════════════════════════════════════════════

def calculate_threat_score(vt_stats=None, abuse_data=None, domain_age=None, url_indicators=None):
    """
    Compute a 0–100 threat score from multiple signals.

    Scoring breakdown:
    - VirusTotal malicious count:  up to 40 points
    - AbuseIPDB confidence score:  up to 30 points
    - Domain age (young = risky):  up to 15 points
    - URL risk indicators:         up to 15 points
    """
    score = 0
    breakdown = {}

    # --- VirusTotal (max 40) ---
    if vt_stats:
        mal = vt_stats.get("malicious", 0)
        sus = vt_stats.get("suspicious", 0)
        total = max(vt_stats.get("total", 1), 1)
        vt_score = min(40, int((mal * 2 + sus) / total * 40))
        # Absolute bonus for clearly malicious
        if mal >= 5:
            vt_score = max(vt_score, 30)
        if mal >= 15:
            vt_score = max(vt_score, 40)
        score += vt_score
        breakdown["virustotal"] = vt_score

    # --- AbuseIPDB (max 30) ---
    if abuse_data and "abuse_confidence" in abuse_data:
        conf = abuse_data["abuse_confidence"]
        abuse_score = int(conf * 0.30)
        score += abuse_score
        breakdown["abuseipdb"] = abuse_score

    # --- Domain Age (max 15) ---
    if domain_age and domain_age.get("age_days") is not None:
        age = domain_age["age_days"]
        if age < 30:
            age_score = 15
        elif age < 90:
            age_score = 10
        elif age < 180:
            age_score = 5
        elif age < 365:
            age_score = 2
        else:
            age_score = 0
        score += age_score
        breakdown["domain_age"] = age_score

    # --- URL Indicators (max 15) ---
    if url_indicators:
        ind_score = min(15, url_indicators.get("risk_points", 0))
        score += ind_score
        breakdown["url_indicators"] = ind_score

    score = min(100, score)

    if score >= 70:
        severity = "HIGH"
        color = "#ff3b3b"
    elif score >= 40:
        severity = "MEDIUM"
        color = "#ff9f0a"
    else:
        severity = "LOW"
        color = "#30d158"

    return {
        "score":     score,
        "severity":  severity,
        "color":     color,
        "breakdown": breakdown
    }


# ══════════════════════════════════════════════
# URL RISK INDICATORS
# ══════════════════════════════════════════════

SHORT_URL_DOMAINS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd",
    "buff.ly","adf.ly","short.link","rb.gy","cutt.ly","tiny.cc"
}

SUSPICIOUS_TLDS = {".tk",".ml",".ga",".cf",".gq",".pw",".top",".click",".download",".zip"}

def analyze_url_indicators(url):
    """Detect red flags in URL structure without external APIs."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().lstrip("www.")
        path = parsed.path
        query = parsed.query
    except:
        return {"risk_points": 0, "flags": []}

    flags = []
    risk = 0

    # Short URL service
    if any(domain == s or domain.endswith("." + s) for s in SHORT_URL_DOMAINS):
        flags.append("Short URL service — hides true destination")
        risk += 5

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f"Suspicious TLD: {tld}")
            risk += 4
            break

    # IP address as hostname
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        flags.append("Uses IP address instead of domain name")
        risk += 6

    # Excessive subdomains
    if domain.count(".") >= 4:
        flags.append(f"Excessive subdomains ({domain.count('.')} levels)")
        risk += 3

    # Long URL
    if len(url) > 200:
        flags.append(f"Unusually long URL ({len(url)} chars)")
        risk += 2

    # Hex/encoded characters
    if re.search(r"%[0-9a-fA-F]{2}", url):
        flags.append("URL contains encoded characters")
        risk += 2

    # Multiple redirects in query string
    if re.search(r"(redirect|url|goto|next|return)=http", query, re.I):
        flags.append("URL contains redirect parameter")
        risk += 4

    # Common phishing keywords in path/domain
    phish_keywords = ["login","signin","account","secure","verify","update","confirm","paypal","amazon","microsoft","apple","google","bank"]
    for kw in phish_keywords:
        if kw in domain or kw in path.lower():
            flags.append(f"Phishing keyword detected: '{kw}'")
            risk += 3
            break

    # HTTP (not HTTPS)
    if parsed.scheme == "http":
        flags.append("Unencrypted HTTP connection (not HTTPS)")
        risk += 2

    # Double extension in path (e.g. .pdf.exe)
    if re.search(r"\.(pdf|doc|xls|zip)\.(exe|php|js|bat|cmd)$", path, re.I):
        flags.append("Double file extension — possible disguised executable")
        risk += 6

    return {"risk_points": min(15, risk), "flags": flags}


# ══════════════════════════════════════════════
# EMAIL PHISHING ANALYZER
# ══════════════════════════════════════════════

def extract_urls(text):
    """Extract all URLs from raw email or text content."""
    pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
    urls = re.findall(pattern, text)
    # Normalize www. URLs
    normalized = []
    for u in urls:
        if u.startswith("www."):
            u = "http://" + u
        normalized.append(u.strip(".,;"))
    return list(set(normalized))


def parse_email_headers(text):
    """
    Simple header parsing: look for SPF/DKIM results and Received chain.
    Works on pasted raw email headers (e.g. from Gmail 'Show original').
    """
    results = {}

    # SPF
    spf_match = re.search(r"Received-SPF:\s*(\w+)", text, re.I)
    results["spf"] = spf_match.group(1).upper() if spf_match else "NOT FOUND"

    # DKIM
    dkim_match = re.search(r"dkim=(\w+)", text, re.I)
    results["dkim"] = dkim_match.group(1).upper() if dkim_match else "NOT FOUND"

    # DMARC
    dmarc_match = re.search(r"dmarc=(\w+)", text, re.I)
    results["dmarc"] = dmarc_match.group(1).upper() if dmarc_match else "NOT FOUND"

    # From address
    from_match = re.search(r"^From:.*?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", text, re.M | re.I)
    results["from_address"] = from_match.group(1) if from_match else "Not found"

    # Reply-To
    reply_match = re.search(r"Reply-To:.*?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", text, re.I)
    results["reply_to"] = reply_match.group(1) if reply_match else None

    # Reply-To mismatch (common phishing tactic)
    results["reply_to_mismatch"] = (
        results["reply_to"] is not None and
        results["from_address"] != "Not found" and
        results["reply_to"].split("@")[-1] != results["from_address"].split("@")[-1]
    )

    # Received hops
    received_hops = re.findall(r"^Received:.*?$", text, re.M | re.I)
    results["hop_count"] = len(received_hops)
    results["received_chain"] = [h.strip() for h in received_hops[:5]]  # limit to 5

    return results


def detect_phishing_indicators(email_text, header_results, urls):
    """Identify phishing signals in email content and structure."""
    indicators = []

    text_lower = email_text.lower()

    # Urgency language
    urgency_patterns = [
        "urgent", "immediately", "your account will be", "verify now",
        "action required", "click here now", "limited time", "expire",
        "suspended", "blocked", "unauthorized access"
    ]
    for p in urgency_patterns:
        if p in text_lower:
            indicators.append(f"Urgency language: '{p}'")
            break

    # Request for credentials
    cred_patterns = ["enter your password", "confirm your password", "update payment",
                     "enter credit card", "social security", "bank account number"]
    for p in cred_patterns:
        if p in text_lower:
            indicators.append(f"Credential request: '{p}'")
            break

    # SPF/DKIM failures
    if header_results.get("spf") in ("FAIL", "SOFTFAIL"):
        indicators.append(f"SPF check failed: {header_results['spf']}")
    if header_results.get("dkim") == "FAIL":
        indicators.append("DKIM signature failed")
    if header_results.get("dmarc") == "FAIL":
        indicators.append("DMARC policy failed")

    # Reply-To mismatch
    if header_results.get("reply_to_mismatch"):
        indicators.append(
            f"Reply-To domain differs from From domain — common phishing tactic"
        )

    # Short URLs
    for url in urls:
        domain = urlparse(url).netloc.lstrip("www.")
        if any(domain == s for s in SHORT_URL_DOMAINS):
            indicators.append(f"Short URL detected: {url}")
            break

    # Many URLs
    if len(urls) > 10:
        indicators.append(f"High URL count ({len(urls)}) — bulk phishing signature")

    return indicators


# ══════════════════════════════════════════════
# FLASK ROUTES
# ══════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/analyze/ip", methods=["POST"])
def api_analyze_ip():
    """Full IP analysis: VT + AbuseIPDB + GeoIP + Threat Score."""
    data = request.get_json()
    ip = (data or {}).get("ip", "").strip()

    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return jsonify({"error": "Invalid IP address"}), 400

    vt      = analyze_ip_vt(ip)
    abuse   = check_abuseipdb(ip)
    geo     = get_geolocation(ip)
    threat  = calculate_threat_score(
        vt_stats=vt.get("stats"),
        abuse_data=abuse if "abuse_confidence" in abuse else None
    )

    return jsonify({
        "ip":          ip,
        "virustotal":  vt,
        "abuseipdb":   abuse,
        "geolocation": geo,
        "threat":      threat
    })


@app.route("/api/analyze/domain", methods=["POST"])
def api_analyze_domain():
    """Full domain analysis: VT + WHOIS + Threat Score."""
    data   = request.get_json()
    domain = (data or {}).get("domain", "").strip().lower()
    domain = re.sub(r"^https?://(www\.)?", "", domain).split("/")[0]

    if not domain:
        return jsonify({"error": "Invalid domain"}), 400

    vt      = analyze_domain_vt(domain)
    age     = get_domain_age(domain)
    threat  = calculate_threat_score(
        vt_stats=vt.get("stats"),
        domain_age=age
    )

    return jsonify({
        "domain":      domain,
        "virustotal":  vt,
        "domain_age":  age,
        "threat":      threat
    })


@app.route("/api/analyze/url", methods=["POST"])
def api_analyze_url():
    """
    Full URL analysis:
    1. VirusTotal 2-step submit → fetch
    2. URL indicator analysis
    3. Threat Score
    """
    data = request.get_json()
    url  = (data or {}).get("url", "").strip()

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lstrip("www.")
    except:
        return jsonify({"error": "Invalid URL"}), 400

    indicators = analyze_url_indicators(url)
    vt         = analyze_url_vt(url)
    age        = get_domain_age(domain)
    threat     = calculate_threat_score(
        vt_stats=vt.get("stats"),
        domain_age=age,
        url_indicators=indicators
    )

    return jsonify({
        "url":          url,
        "domain":       domain,
        "virustotal":   vt,
        "domain_age":   age,
        "indicators":   indicators,
        "threat":       threat
    })


@app.route("/api/analyze/email", methods=["POST"])
def api_analyze_email():
    """
    Email phishing analysis:
    - Extract URLs and analyze each with VirusTotal
    - Parse email headers (SPF/DKIM/DMARC/Received chain)
    - Detect phishing indicators
    - Compute overall threat score
    """
    data  = request.get_json()
    email = (data or {}).get("email", "")

    if not email:
        return jsonify({"error": "No email content provided"}), 400

    # 1. Extract URLs
    urls = extract_urls(email)

    # 2. Parse headers
    headers = parse_email_headers(email)

    # 3. Analyze up to 5 URLs (rate limit protection)
    url_results = []
    worst_stats = None
    for url in urls[:5]:
        indicators = analyze_url_indicators(url)
        vt = analyze_url_vt(url)
        stats = vt.get("stats", {})
        if worst_stats is None or stats.get("malicious", 0) > worst_stats.get("malicious", 0):
            worst_stats = stats
        url_results.append({
            "url":        url,
            "vt":         vt,
            "indicators": indicators
        })

    # 4. Phishing indicators
    phishing_flags = detect_phishing_indicators(email, headers, urls)

    # 5. Threat score
    threat = calculate_threat_score(
        vt_stats=worst_stats,
        url_indicators={"risk_points": min(15, len(phishing_flags) * 3)}
    )

    return jsonify({
        "url_count":      len(urls),
        "urls_analyzed":  url_results,
        "headers":        headers,
        "phishing_flags": phishing_flags,
        "threat":         threat
    })


# ══════════════════════════════════════════════
# SOC PHISHING TICKET ANALYZER
# Mirrors real SOC analyst workflow:
# Sender domain → Domain IP → Domain Age →
# URL check → Header SPF/DKIM → IP reputation → Verdict
# ══════════════════════════════════════════════

def extract_sender_domain(email_text):
    """Pull sender domain from From: header."""
    match = re.search(r"From:.*?@([\w.\-]+)", email_text, re.I)
    if match:
        return match.group(1).lower().strip()
    return None

def extract_sender_ip_from_received(email_text):
    """
    Extract originating sender IP from the LAST Received: header
    (closest to the original sender, not internal hops).
    """
    received = re.findall(
        r"Received:.*?(?:\[(\d{1,3}(?:\.\d{1,3}){3})\]|from\s+\S+\s+\[(\d{1,3}(?:\.\d{1,3}){3})\])",
        email_text, re.I | re.S
    )
    # Flatten and get last valid IP (furthest hop = true origin)
    ips = [ip for pair in received for ip in pair if ip]
    # Filter private IPs
    public_ips = [ip for ip in ips if not (
        ip.startswith("10.") or ip.startswith("192.168.") or
        ip.startswith("172.") or ip == "127.0.0.1"
    )]
    return public_ips[-1] if public_ips else None

def check_urlvoid(domain):
    """
    URLVoid-style check: use VirusTotal domain report as proxy.
    Returns clean/suspicious based on VT stats.
    """
    vt = analyze_domain_vt(domain)
    stats = vt.get("stats", {})
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    if mal >= 3:
        return "Malicious", mal, stats
    elif mal > 0 or sus > 0:
        return "Suspicious", mal + sus, stats
    return "Clean", 0, stats

@app.route("/api/analyze/phishing-ticket", methods=["POST"])
def api_phishing_ticket():
    """
    Full SOC-style phishing email analysis.
    Accepts raw email text (paste or .eml upload).
    Returns structured SOC ticket with per-check results and final verdict.
    """
    data       = request.get_json()
    email_text = (data or {}).get("email", "")
    ticket_no  = (data or {}).get("ticket_no", "MANUAL-" + str(int(time.time()))[-6:])

    if not email_text:
        return jsonify({"error": "No email content provided"}), 400

    result = {
        "ticket_no":   ticket_no,
        "date":        datetime.datetime.utcnow().strftime("%d-%m-%Y"),
        "checks":      {},
        "verdict":     None,
        "threat_score": 0
    }

    checks  = result["checks"]
    risk_pts = 0

    # ── 1. Sender Domain Check ──
    sender_domain = extract_sender_domain(email_text)
    checks["sender_domain"] = {"domain": sender_domain or "Not found"}
    if sender_domain:
        sd_status, sd_count, sd_stats = check_urlvoid(sender_domain)
        checks["sender_domain"].update({
            "status": sd_status,
            "malicious_engines": sd_count,
            "vt_stats": sd_stats
        })
        if sd_status == "Malicious":   risk_pts += 35
        elif sd_status == "Suspicious": risk_pts += 15
    else:
        checks["sender_domain"]["status"] = "Not found"

    # ── 2. Domain Check (all domains in email body) ──
    urls = extract_urls(email_text)
    body_domains = list(set([
        urlparse(u).netloc.lstrip("www.").split(":")[0]
        for u in urls if urlparse(u).netloc
    ]))
    domain_results = []
    worst_domain_mal = 0
    for d in body_domains[:4]:
        status, count, stats = check_urlvoid(d)
        domain_results.append({"domain": d, "status": status, "malicious": count, "stats": stats})
        worst_domain_mal = max(worst_domain_mal, count)
        if status == "Malicious":   risk_pts += 20
        elif status == "Suspicious": risk_pts += 8

    overall_domain_status = "Clean"
    if any(r["status"] == "Malicious" for r in domain_results):
        overall_domain_status = "Malicious"
    elif any(r["status"] == "Suspicious" for r in domain_results):
        overall_domain_status = "Suspicious"

    checks["domain_check"] = {
        "domains_found": len(body_domains),
        "results": domain_results,
        "overall_status": overall_domain_status
    }

    # ── 3. Domain IP Check ──
    domain_ip_results = []
    if sender_domain:
        try:
            import socket
            ip = socket.gethostbyname(sender_domain)
            geo = get_geolocation(ip)
            abuse = check_abuseipdb(ip)
            vt_ip = analyze_ip_vt(ip)
            ip_mal = vt_ip.get("stats", {}).get("malicious", 0)
            abuse_conf = abuse.get("abuse_confidence", 0) if "abuse_confidence" in abuse else 0

            ip_status = "Clean"
            if ip_mal >= 3 or abuse_conf >= 50:
                ip_status = "Malicious"
                risk_pts += 25
            elif ip_mal > 0 or abuse_conf >= 20:
                ip_status = "Suspicious"
                risk_pts += 10

            domain_ip_results.append({
                "ip": ip,
                "status": ip_status,
                "country": geo.get("country", "Unknown"),
                "isp": geo.get("isp", "Unknown"),
                "vt_malicious": ip_mal,
                "abuse_confidence": abuse_conf,
                "is_tor": abuse.get("is_tor", False),
                "is_proxy": geo.get("proxy", False)
            })
        except Exception as e:
            domain_ip_results.append({"ip": "Resolution failed", "status": "Unknown"})

    checks["domain_ip"] = {
        "results": domain_ip_results,
        "overall_status": domain_ip_results[0]["status"] if domain_ip_results else "Unknown"
    }

    # ── 4. Domain Age ──
    age_data = get_domain_age(sender_domain) if sender_domain else {}
    age_days  = age_data.get("age_days")
    age_years = round(age_days / 365, 1) if age_days else None
    age_status = "Unknown"
    if age_days is not None:
        if age_days < 30:
            age_status = "Very New (High Risk)"
            risk_pts += 15
        elif age_days < 180:
            age_status = "New (Moderate Risk)"
            risk_pts += 8
        elif age_days < 365:
            age_status = "Less than 1 Year"
            risk_pts += 3
        else:
            age_status = f"{age_years} Years"

    checks["domain_age"] = {
        "domain": sender_domain,
        "age_days": age_days,
        "age_display": age_status,
        "creation_date": age_data.get("creation_date", "Unknown"),
        "registrar": age_data.get("registrar", "Unknown")
    }

    # ── 5. URL Check ──
    url_results = []
    worst_url_mal = 0
    for url in urls[:5]:
        ind = analyze_url_indicators(url)
        vt  = analyze_url_vt(url)
        mal = vt.get("stats", {}).get("malicious", 0)
        worst_url_mal = max(worst_url_mal, mal)
        status = "Malicious" if mal >= 3 else ("Suspicious" if mal > 0 or ind["risk_points"] >= 8 else "Clean")
        url_results.append({
            "url": url,
            "vt_malicious": mal,
            "vt_stats": vt.get("stats", {}),
            "risk_flags": ind["flags"],
            "risk_points": ind["risk_points"],
            "status": status
        })
        if status == "Malicious":   risk_pts += 20
        elif status == "Suspicious": risk_pts += 8

    url_overall = "Clean"
    if any(r["status"] == "Malicious" for r in url_results):
        url_overall = "Malicious"
    elif any(r["status"] == "Suspicious" for r in url_results):
        url_overall = "Suspicious"

    checks["url_check"] = {
        "urls_found": len(urls),
        "urls_analyzed": len(url_results),
        "results": url_results,
        "overall_status": url_overall
    }

    # ── 6. Attachment Check ──
    # Detect attachment references in pasted email
    attachment_patterns = re.findall(
        r'filename=["\']?([^"\';\s]+\.(exe|zip|rar|js|vbs|bat|cmd|ps1|docm|xlsm|pdf|iso|img|jar|hta|scr))["\']?',
        email_text, re.I
    )
    attachment_status = "Clean"
    attachment_names = []
    if attachment_patterns:
        attachment_names = [m[0] for m in attachment_patterns]
        dangerous_exts  = {"exe","js","vbs","bat","cmd","ps1","docm","xlsm","hta","scr","jar"}
        if any(m[1].lower() in dangerous_exts for m in attachment_patterns):
            attachment_status = "Malicious"
            risk_pts += 30
        else:
            attachment_status = "Suspicious"
            risk_pts += 10

    checks["attachment"] = {
        "found": len(attachment_names),
        "files": attachment_names,
        "status": attachment_status
    }

    # ── 7. Header Check (SPF / DKIM / DMARC) ──
    hdr = parse_email_headers(email_text)
    spf  = hdr.get("spf",  "NOT FOUND")
    dkim = hdr.get("dkim", "NOT FOUND")
    dmarc= hdr.get("dmarc","NOT FOUND")

    header_issues = []
    if spf  in ("FAIL","SOFTFAIL"): header_issues.append("SPF failed"); risk_pts += 10
    if dkim == "FAIL":              header_issues.append("DKIM failed"); risk_pts += 10
    if dmarc== "FAIL":              header_issues.append("DMARC failed"); risk_pts += 8
    if hdr.get("reply_to_mismatch"):
        header_issues.append("Reply-To domain mismatch"); risk_pts += 12

    spf_align  = "Yes" if spf  == "PASS" else ("No" if spf  in ("FAIL","SOFTFAIL") else "N/A")
    dkim_align = "Yes" if dkim == "PASS" else ("No" if dkim == "FAIL" else "N/A")

    checks["header"] = {
        "spf":              spf,
        "dkim":             dkim,
        "dmarc":            dmarc,
        "spf_alignment":    spf_align,
        "dkim_alignment":   dkim_align,
        "from_address":     hdr.get("from_address", "Not found"),
        "reply_to":         hdr.get("reply_to"),
        "reply_to_mismatch":hdr.get("reply_to_mismatch", False),
        "hop_count":        hdr.get("hop_count", 0),
        "issues":           header_issues,
        "overall_status":   "Issues Found" if header_issues else "Pass"
    }

    # ── 8. Header IP Check ──
    sender_ip = extract_sender_ip_from_received(email_text)
    header_ip_result = {"ip": None, "status": "N/A"}
    if sender_ip:
        geo   = get_geolocation(sender_ip)
        abuse = check_abuseipdb(sender_ip)
        vt_ip = analyze_ip_vt(sender_ip)
        ip_mal  = vt_ip.get("stats", {}).get("malicious", 0)
        abuse_c = abuse.get("abuse_confidence", 0) if "abuse_confidence" in abuse else 0
        ip_status = "Clean"
        if ip_mal >= 3 or abuse_c >= 50:
            ip_status = "Malicious"; risk_pts += 20
        elif ip_mal > 0 or abuse_c >= 20:
            ip_status = "Suspicious"; risk_pts += 8

        header_ip_result = {
            "ip":               sender_ip,
            "status":           ip_status,
            "country":          geo.get("country", "Unknown"),
            "isp":              geo.get("isp", "Unknown"),
            "vt_malicious":     ip_mal,
            "abuse_confidence": abuse_c,
            "is_tor":           geo.get("tor", False),
            "is_proxy":         geo.get("proxy", False)
        }
        if ip_status == "Malicious":   risk_pts += 15
        elif ip_status == "Suspicious": risk_pts += 5
    else:
        header_ip_result = {"ip": "Not found in headers", "status": "N/A"}

    checks["header_ip"] = header_ip_result

    # ── Final Verdict ──
    risk_pts = min(100, risk_pts)
    result["threat_score"] = risk_pts

    all_statuses = [
        checks["sender_domain"].get("status",""),
        checks["domain_check"]["overall_status"],
        checks["domain_ip"]["overall_status"],
        checks["url_check"]["overall_status"],
        checks["attachment"]["status"],
        checks["header"]["overall_status"],
        checks["header_ip"].get("status","")
    ]

    malicious_count  = sum(1 for s in all_statuses if s == "Malicious")
    suspicious_count = sum(1 for s in all_statuses if s in ("Suspicious","Issues Found"))

    if malicious_count >= 1 or risk_pts >= 50:
        result["verdict"] = "Malicious"
        result["verdict_reason"] = f"{malicious_count} malicious indicator(s) found. Threat score: {risk_pts}/100."
    elif suspicious_count >= 2 or risk_pts >= 25:
        result["verdict"] = "Suspicious"
        result["verdict_reason"] = f"{suspicious_count} suspicious indicator(s). Recommend further investigation."
    else:
        result["verdict"] = "Non Malicious"
        result["verdict_reason"] = "No significant threat indicators detected across all checks."

    return jsonify(result)


# ─────────────────────────────────────────────
# Health check for Render
# ─────────────────────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": time.time()})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
