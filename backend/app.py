from flask import Flask, request, jsonify, send_file, session, redirect, url_for
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
from docx import Document
from docx.shared import Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from concurrent.futures import ThreadPoolExecutor, as_completed
import validators
import io
import re
import csv
import sqlite3
import os
from urllib.parse import urljoin, urlparse
import uuid
import ssl
import socket
from datetime import datetime, timezone
from functools import wraps

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'vulnscan-secret-2024')
CORS(app)

ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'VulnScan@2024')
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vulnscan.db')

RATE_LIMITS = {
    'burst':      {'max': 5,  'window': 60,   'block': 1200},   # 5 scans / 60 sec
    'hourly':     {'max': 10, 'window': 3600,  'block': 1200},   # 10 scans / hour
    'domain':     {'max': 10, 'window': 3600,  'block': 1200},   # 10 scans same domain / hour
}
WARN_AT = 0.7   # warn when 70% of any limit is hit

PRIVATE_NETS = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|localhost)', re.I
)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT, timestamp TEXT,
        risk_score INTEGER, seo_score INTEGER,
        vuln_total INTEGER, vuln_critical INTEGER,
        vuln_high INTEGER, vuln_medium INTEGER, vuln_low INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS export_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT, timestamp TEXT, export_type TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS rate_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        domain TEXT NOT NULL,
        ts INTEGER NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS blocks (
        ip TEXT PRIMARY KEY,
        reason TEXT,
        rule TEXT,
        blocked_at INTEGER,
        unblock_at INTEGER
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_rate_ip_ts ON rate_events(ip, ts)')
    conn.commit()
    conn.close()

init_db()


def get_client_ip():
    """Get real client IP, respecting reverse proxy headers."""
    for header in ('X-Forwarded-For', 'X-Real-IP'):
        val = request.headers.get(header)
        if val:
            return val.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def check_rate_limit(ip, domain):
    """
    Returns (blocked, block_info, warnings).
    blocked: bool
    block_info: dict with reason/rule/unblock_at if blocked
    warnings: list of warning strings
    """
    now = int(datetime.now(timezone.utc).timestamp())
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Check existing block
    row = c.execute('SELECT reason, rule, unblock_at FROM blocks WHERE ip=?', (ip,)).fetchone()
    if row:
        reason, rule, unblock_at = row
        if now < unblock_at:
            conn.close()
            remaining = unblock_at - now
            mins = remaining // 60
            secs = remaining % 60
            return True, {
                'reason': reason,
                'rule': rule,
                'unblock_at': unblock_at,
                'remaining_seconds': remaining,
                'message': f'Access temporarily suspended for {mins}m {secs}s. {reason}'
            }, []
        else:
            # Block expired — remove it
            c.execute('DELETE FROM blocks WHERE ip=?', (ip,))
            conn.commit()

    # Count events in windows
    burst_since  = now - RATE_LIMITS['burst']['window']
    hourly_since = now - RATE_LIMITS['hourly']['window']

    burst_count  = c.execute('SELECT COUNT(*) FROM rate_events WHERE ip=? AND ts>=?',
                             (ip, burst_since)).fetchone()[0]
    hourly_count = c.execute('SELECT COUNT(*) FROM rate_events WHERE ip=? AND ts>=?',
                             (ip, hourly_since)).fetchone()[0]
    domain_count = c.execute('SELECT COUNT(*) FROM rate_events WHERE ip=? AND domain=? AND ts>=?',
                             (ip, domain, hourly_since)).fetchone()[0]

    counts = {
        'burst':  (burst_count,  RATE_LIMITS['burst']['max']),
        'hourly': (hourly_count, RATE_LIMITS['hourly']['max']),
        'domain': (domain_count, RATE_LIMITS['domain']['max']),
    }

    RULE_LABELS = {
        'burst':  'Too many scans in a short time (max 5 per 60 seconds)',
        'hourly': 'Hourly scan limit reached (max 10 per hour)',
        'domain': 'Same domain scanned too many times (max 10 per hour)',
    }

    # Check if any limit exceeded
    for rule, (count, limit) in counts.items():
        if count >= limit:
            unblock_at = now + RATE_LIMITS[rule]['block']
            label = RULE_LABELS[rule]
            c.execute('''INSERT OR REPLACE INTO blocks (ip, reason, rule, blocked_at, unblock_at)
                         VALUES (?,?,?,?,?)''', (ip, label, rule, now, unblock_at))
            conn.commit()
            conn.close()
            mins = RATE_LIMITS[rule]['block'] // 60
            return True, {
                'reason': label,
                'rule': rule,
                'unblock_at': unblock_at,
                'remaining_seconds': RATE_LIMITS[rule]['block'],
                'message': f'Temporarily blocked for {mins} minutes. Reason: {label}'
            }, []

    # Build warnings (approaching limits)
    warnings = []
    WARN_MSGS = {
        'burst':  lambda c, m: f'Slow down — {c} of {m} allowed scans used in the last 60 seconds.',
        'hourly': lambda c, m: f'Approaching hourly limit — {c}/{m} scans used this hour.',
        'domain': lambda c, m: f'Same domain scanned {c}/{m} times this hour.',
    }
    for rule, (count, limit) in counts.items():
        if count >= int(limit * WARN_AT):
            warnings.append(WARN_MSGS[rule](count, limit))

    conn.close()
    return False, None, warnings


def record_scan_event(ip, domain):
    now = int(datetime.now(timezone.utc).timestamp())
    conn = sqlite3.connect(DB_PATH)
    conn.execute('INSERT INTO rate_events (ip, domain, ts) VALUES (?,?,?)', (ip, domain, now))
    # Prune old events (older than 1 hour) to keep table small
    conn.execute('DELETE FROM rate_events WHERE ts < ?', (now - 3600,))
    conn.commit()
    conn.close()

def log_scan(data):
    try:
        v = data.get('vulnerabilities', {}).get('summary', {})
        conn = sqlite3.connect(DB_PATH)
        conn.execute('''INSERT INTO scan_history
            (url, timestamp, risk_score, seo_score, vuln_total, vuln_critical, vuln_high, vuln_medium, vuln_low)
            VALUES (?,?,?,?,?,?,?,?,?)''',
            (data.get('url'), datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
             v.get('risk_score', 0), data.get('seo', {}).get('score', 0),
             v.get('total', 0), v.get('critical', 0),
             v.get('high', 0), v.get('medium', 0), v.get('low', 0)))
        conn.commit()
        conn.close()
    except Exception:
        pass

def log_export(url, export_type):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute('INSERT INTO export_history (url, timestamp, export_type) VALUES (?,?,?)',
                     (url, datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), export_type))
        conn.commit()
        conn.close()
    except Exception:
        pass

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            return redirect('/admin/login')
        return f(*args, **kwargs)
    return decorated

# Store scraped data temporarily
scraped_data_store = {}


def is_valid_url(url):
    """Validate URL format"""
    return validators.url(url)


def check_security_headers(response):
    """Check for missing security headers"""
    headers = response.headers
    security_issues = []

    # Important security headers to check with damage descriptions
    security_headers = {
        'Strict-Transport-Security': {
            'message': 'Missing HSTS header - site vulnerable to downgrade attacks',
            'damage': 'Attackers can downgrade HTTPS to HTTP and intercept/modify all traffic. User data, passwords, and sensitive information can be stolen or manipulated in transit.'
        },
        'Content-Security-Policy': {
            'message': 'Missing CSP header - site vulnerable to XSS attacks',
            'damage': 'Attackers can inject malicious scripts to steal user sessions, credentials, redirect users to phishing sites, deface the website, or install malware on visitor devices.'
        },
        'X-Frame-Options': {
            'message': 'Missing X-Frame-Options header - site vulnerable to clickjacking',
            'damage': 'Attackers can embed your site in a malicious frame, tricking users into clicking hidden elements that perform unauthorized actions like transferring funds or changing account settings.'
        },
        'X-Content-Type-Options': {
            'message': 'Missing X-Content-Type-Options header - MIME sniffing possible',
            'damage': 'Browsers may interpret files as different types than intended, enabling XSS attacks where malicious scripts are executed from seemingly harmless files.'
        },
        'Referrer-Policy': {
            'message': 'Missing Referrer-Policy header - privacy information may leak',
            'damage': 'Sensitive URLs containing tokens, session IDs, or personal data can leak to third-party sites through referrer headers, exposing user privacy and security tokens.'
        },
        'Permissions-Policy': {
            'message': 'Missing Permissions-Policy header - browser features not restricted',
            'damage': 'Malicious scripts can abuse browser features like camera, microphone, geolocation without proper restrictions, enabling surveillance and privacy violations.'
        },
        'X-XSS-Protection': {
            'message': 'Missing X-XSS-Protection header',
            'damage': 'Browser XSS filter is disabled, making reflected XSS attacks more likely to succeed, potentially stealing user data and session cookies.'
        },
    }

    for header, data in security_headers.items():
        if header not in headers:
            security_issues.append({
                'type': 'Missing Security Header',
                'severity': 'Medium',
                'header': header,
                'description': data['message'],
                'damage': data['damage']
            })

    # Check for insecure cookies
    set_cookie = headers.get('Set-Cookie', '')
    if set_cookie:
        if 'Secure' not in set_cookie:
            security_issues.append({
                'type': 'Insecure Cookie',
                'severity': 'High',
                'header': 'Set-Cookie',
                'description': 'Cookie missing Secure flag - transmitted over HTTP',
                'damage': 'Session cookies can be intercepted over unencrypted connections, allowing attackers to hijack user accounts, impersonate users, and gain unauthorized access to sensitive data.'
            })
        if 'HttpOnly' not in set_cookie:
            security_issues.append({
                'type': 'Insecure Cookie',
                'severity': 'Medium',
                'header': 'Set-Cookie',
                'description': 'Cookie missing HttpOnly flag - accessible to JavaScript',
                'damage': 'JavaScript can access cookies, enabling XSS attacks to steal session tokens. Attackers can hijack authenticated sessions and perform actions as the victim user.'
            })
        if 'SameSite' not in set_cookie:
            security_issues.append({
                'type': 'Insecure Cookie',
                'severity': 'Low',
                'header': 'Set-Cookie',
                'description': 'Cookie missing SameSite attribute - vulnerable to CSRF',
                'damage': 'Browsers send cookies with cross-site requests, allowing attackers to forge requests on behalf of logged-in users, potentially performing unauthorized actions like changing passwords or making purchases.'
            })

    return security_issues


def check_server_info_leakage(headers):
    """Check for server information disclosure"""
    info_issues = []

    # Check for server version disclosure
    server = headers.get('Server', '')
    if server:
        # Check if version number is exposed
        if re.search(r'\d+\.\d+', server):
            info_issues.append({
                'type': 'Information Disclosure',
                'severity': 'Low',
                'header': 'Server',
                'description': f'Server version exposed: {server}',
                'damage': 'Attackers can identify known vulnerabilities in specific server versions, enabling targeted exploits that could lead to server compromise, data breaches, or service disruption.'
            })

    # Check for X-Powered-By header
    powered_by = headers.get('X-Powered-By', '')
    if powered_by:
        info_issues.append({
            'type': 'Information Disclosure',
            'severity': 'Low',
            'header': 'X-Powered-By',
            'description': f'Technology stack exposed: {powered_by}',
            'damage': 'Revealing backend technologies helps attackers craft specific exploits for known framework vulnerabilities, potentially leading to code execution or data access.'
        })

    return info_issues


def check_sensitive_files(base_url):
    """Check for exposed sensitive files"""
    sensitive_files = [
        {'path': '/.env', 'damage': 'Database credentials, API keys, and secret tokens may be exposed, allowing attackers to access databases, send emails as the company, or access third-party services.'},
        {'path': '/.git/config', 'damage': 'Full source code can be extracted including history, revealing hardcoded secrets, vulnerabilities, and proprietary business logic.'},
        {'path': '/.htaccess', 'damage': 'Server configuration exposed, revealing URL rewriting rules, authentication requirements, and directory protections that can help attackers map the application.'},
        {'path': '/.htpasswd', 'damage': 'Password hashes for protected areas exposed, allowing offline cracking attacks to gain access to restricted sections.'},
        {'path': '/config.php', 'damage': 'Database connection strings, API keys, and encryption keys exposed, enabling full database access and potential data theft.'},
        {'path': '/config.json', 'damage': 'Application configuration including secrets, endpoints, and feature flags exposed, facilitating targeted attacks.'},
        {'path': '/wp-config.php', 'damage': 'WordPress database credentials and authentication salts exposed, allowing attackers to take complete control of the WordPress site.'},
        {'path': '/admin/', 'damage': 'Administrative panel accessible, potentially allowing unauthorized access to user management, content control, and system settings.'},
        {'path': '/phpinfo.php', 'damage': 'Detailed server configuration exposed including environment variables, loaded modules, and file paths, aiding attackers in crafting exploits.'},
        {'path': '/.DS_Store', 'damage': 'Directory structure and file names revealed, exposing hidden files and backup files that should not be accessible.'},
        {'path': '/robots.txt', 'damage': 'While normally public, may reveal sensitive directories that administrators tried to hide from search engines.'},
        {'path': '/sitemap.xml', 'damage': 'While normally public, may expose admin URLs or private pages not intended for public access.'},
        {'path': '/.well-known/security.txt', 'damage': 'Security contact information exposed (standard practice, lower risk but still information disclosure).'}
    ]

    exposed_files = []

    # Detect SPA (Single Page Application) behavior: SPAs return 200 for all routes
    # by serving the index.html. We probe a random non-existent path as a baseline.
    spa_baseline_content = None
    spa_baseline_length = None
    try:
        canary_url = urljoin(base_url, '/definitely-not-a-real-path-xk392q')
        canary_resp = requests.get(canary_url, timeout=5, verify=False, allow_redirects=False)
        if canary_resp.status_code == 200:
            spa_baseline_content = canary_resp.text
            spa_baseline_length = len(canary_resp.content)
    except:
        pass

    def is_spa_false_positive(response):
        """Return True if the response looks like an SPA catch-all, not a real file."""
        if spa_baseline_content is None:
            return False
        content_type = response.headers.get('Content-Type', '')
        # If the response is HTML, compare with the SPA baseline
        if 'text/html' in content_type:
            resp_len = len(response.content)
            # If the length is within 5% of the baseline, treat as SPA catch-all
            if spa_baseline_length and abs(resp_len - spa_baseline_length) / max(spa_baseline_length, 1) < 0.05:
                return True
            # If the body text is identical to the baseline, it's definitely a catch-all
            if response.text == spa_baseline_content:
                return True
        return False

    def is_real_file_content(file_path, response):
        """Validate that the response content makes sense for the given file type."""
        content_type = response.headers.get('Content-Type', '')
        body = response.text[:2000]

        if file_path.endswith('.php'):
            # PHP files that are truly exposed should NOT return generic HTML
            # A real PHP file would contain PHP output or error traces, not an SPA shell
            if '<div id="root">' in body or '<div id="app">' in body:
                return False
            # phpinfo returns a very specific pattern
            if file_path == '/phpinfo.php' and 'PHP Version' not in body:
                return False
            # wp-config.php and config.php are raw PHP — a server misconfiguration
            # would either show PHP source or execute it. An HTML SPA page means
            # the route was caught by the frontend router.
            if 'text/html' in content_type and '<?php' not in body and 'PHP' not in body:
                return False

        if file_path == '/.env':
            # A real .env file should look like KEY=VALUE pairs, not HTML
            if '<html' in body.lower() or '<body' in body.lower():
                return False

        if file_path == '/.git/config':
            # git config files contain [core] sections
            if '[core]' not in body and '[remote' not in body:
                return False

        if file_path == '/.htaccess':
            # htaccess files contain Apache directives
            if '<html' in body.lower():
                return False

        if file_path == '/.htpasswd':
            # htpasswd files contain user:hash lines, not HTML
            if '<html' in body.lower():
                return False

        return True

    for file_info in sensitive_files:
        file_path = file_info['path']
        try:
            test_url = urljoin(base_url, file_path)
            response = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
            if response.status_code == 200:
                # Skip if this looks like an SPA catch-all response
                if is_spa_false_positive(response):
                    continue
                # Skip if content doesn't match what the file type should contain
                if not is_real_file_content(file_path, response):
                    continue
                exposed_files.append({
                    'type': 'Exposed Sensitive File',
                    'severity': 'High' if file_path in ['/.env', '/.git/config', '/config.php', '/wp-config.php'] else 'Medium',
                    'path': file_path,
                    'url': test_url,
                    'description': f'Potentially sensitive file accessible: {file_path}',
                    'damage': file_info['damage']
                })
        except:
            continue

    return exposed_files


def check_ssl_vulnerabilities(url):
    """Check SSL/TLS configuration"""
    ssl_issues = []

    parsed_url = urlparse(url)

    if parsed_url.scheme != 'https':
        ssl_issues.append({
            'type': 'Insecure Protocol',
            'severity': 'High',
            'description': 'Website not using HTTPS - data transmitted in plaintext',
            'damage': 'All data including passwords, credit cards, and personal information is transmitted unencrypted. Attackers on the same network can intercept, read, and modify all traffic using man-in-the-middle attacks.'
        })
        return ssl_issues

    # Try to check SSL certificate
    try:
        hostname = parsed_url.netloc
        if ':' in hostname:
            hostname = hostname.split(':')[0]

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Check certificate expiration
                if cert and 'notAfter' in cert:
                    expiry = cert['notAfter']
                    # Parse the date
                    expiry_date = datetime.strptime(expiry, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days

                    if days_until_expiry < 0:
                        ssl_issues.append({
                            'type': 'Expired SSL Certificate',
                            'severity': 'Critical',
                            'description': f'SSL certificate expired {abs(days_until_expiry)} days ago',
                            'damage': 'Browsers show security warnings, causing users to distrust the site. Attackers can intercept traffic using fake certificates. Users may abandon the site, leading to lost revenue and reputation damage.'
                        })
                    elif days_until_expiry < 30:
                        ssl_issues.append({
                            'type': 'SSL Certificate Expiring',
                            'severity': 'Medium',
                            'description': f'SSL certificate expires in {days_until_expiry} days',
                            'damage': 'If not renewed, the site will show security warnings and become inaccessible to many users, potentially causing service disruption and loss of business.'
                        })

                # Check SSL version
                version = ssock.version()
                if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    ssl_issues.append({
                        'type': 'Weak SSL/TLS',
                        'severity': 'High',
                        'description': f'Using weak protocol: {version}',
                        'damage': 'Legacy protocols have known vulnerabilities like POODLE and BEAST attacks. Attackers can downgrade connections and decrypt sensitive data including passwords and financial information.'
                    })

    except Exception as e:
        ssl_issues.append({
            'type': 'SSL/TLS Error',
            'severity': 'Medium',
            'description': f'Could not verify SSL certificate: {str(e)}',
            'damage': 'SSL verification issues may indicate certificate chain problems, causing browser warnings and preventing users from accessing the site securely.'
        })

    return ssl_issues


def check_https_redirect(url):
    """Return True if http:// redirects to https://, False if not, None on error."""
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        return None
    http_url = 'http://' + url[len('https://'):]
    try:
        resp = requests.get(http_url, timeout=5, verify=False, allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0'})
        return urlparse(resp.url).scheme == 'https'
    except Exception:
        return None


def analyze_seo(url, soup):
    """Analyze SEO factors. Expects the original (unmodified) soup."""
    base_parsed = urlparse(url)
    seo = {}

    # Title
    title_tag = soup.find('title')
    title = title_tag.get_text(strip=True) if title_tag else ''
    seo['title'] = title
    seo['title_length'] = len(title)
    seo['title_ok'] = 10 <= len(title) <= 60

    # Meta description
    meta_desc = soup.find('meta', attrs={'name': re.compile(r'^description$', re.I)})
    desc = meta_desc.get('content', '').strip() if meta_desc else ''
    seo['description'] = desc
    seo['description_length'] = len(desc)
    seo['description_ok'] = 50 <= len(desc) <= 160

    # H1
    h1s = soup.find_all('h1')
    seo['h1_count'] = len(h1s)
    seo['h1_ok'] = len(h1s) == 1
    seo['h1_texts'] = [h.get_text(strip=True) for h in h1s[:5]]

    # Images missing alt
    all_imgs = soup.find_all('img')
    seo['images_total'] = len(all_imgs)
    seo['images_missing_alt'] = sum(1 for img in all_imgs if not img.get('alt', '').strip())

    # Canonical
    canonical = soup.find('link', rel=lambda r: bool(r) and 'canonical' in r)
    seo['canonical'] = canonical.get('href', '') if canonical else ''

    # OG tags
    og = {}
    for prop in ['og:title', 'og:description', 'og:image', 'og:type', 'og:url']:
        tag = soup.find('meta', property=prop)
        og[prop.replace('og:', '')] = tag.get('content', '').strip() if tag else ''
    seo['og'] = og

    # Twitter tags
    tw = {}
    for name in ['twitter:card', 'twitter:title', 'twitter:description']:
        tag = soup.find('meta', attrs={'name': name})
        tw[name.replace('twitter:', '')] = tag.get('content', '').strip() if tag else ''
    seo['twitter'] = tw

    # Broken same-host links (max 20, parallel HEAD requests)
    candidate_links = []
    seen = set()
    for a in soup.find_all('a', href=True):
        if len(candidate_links) >= 20:
            break
        href = a.get('href', '').strip()
        if not href or href.startswith(('#', 'mailto:', 'tel:', 'javascript:')):
            continue
        full = urljoin(url, href)
        fp = urlparse(full)
        if fp.netloc != base_parsed.netloc or not full.startswith('http') or full in seen:
            continue
        seen.add(full)
        candidate_links.append(full)

    def _check_link(link_url):
        try:
            r = requests.head(link_url, timeout=3, verify=False, allow_redirects=True,
                              headers={'User-Agent': 'Mozilla/5.0'})
            return {'url': link_url, 'status': r.status_code} if r.status_code >= 400 else None
        except Exception:
            return {'url': link_url, 'status': 'timeout'}

    broken = []
    if candidate_links:
        with ThreadPoolExecutor(max_workers=8) as executor:
            for result in as_completed({executor.submit(_check_link, l): l for l in candidate_links}):
                outcome = result.result()
                if outcome:
                    broken.append(outcome)

    seo['broken_links'] = broken
    seo['links_checked'] = len(candidate_links)

    # ── On-Page SEO Analysis ──────────────────────────────────────────────────

    # URL structure
    url_path = base_parsed.path or '/'
    url_full = url
    seo['onpage'] = op = {}

    op['url_length'] = len(url_full)
    op['url_ok']     = len(url_full) <= 100
    op['url_has_underscores'] = '_' in url_path
    op['url_has_params']      = bool(base_parsed.query)
    op['url_is_https']        = base_parsed.scheme == 'https'
    op['url_path']            = url_path

    # Heading hierarchy (H1–H6)
    heading_counts = {}
    all_headings_ordered = []
    for level in range(1, 7):
        tags = soup.find_all(f'h{level}')
        heading_counts[f'h{level}'] = len(tags)
        for t in tags:
            all_headings_ordered.append({'level': level, 'text': t.get_text(strip=True)[:120]})
    op['heading_counts']   = heading_counts
    op['heading_hierarchy_ok'] = (
        heading_counts.get('h1', 0) == 1 and
        heading_counts.get('h2', 0) >= 1 and
        heading_counts.get('h1', 0) <= heading_counts.get('h2', 0) + 1
    )

    # Internal vs external links
    internal_links, external_links = [], []
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            continue
        full = urljoin(url, href)
        fp = urlparse(full)
        if fp.netloc == base_parsed.netloc:
            internal_links.append(full)
        elif fp.netloc:
            external_links.append(full)
    op['internal_links_count'] = len(internal_links)
    op['external_links_count'] = len(external_links)
    op['internal_links_ok']    = len(internal_links) >= 3

    # Images: lazy loading
    lazy_count = sum(1 for img in all_imgs if img.get('loading') == 'lazy' or img.get('data-src'))
    op['images_total']       = len(all_imgs)
    op['images_missing_alt'] = seo['images_missing_alt']
    op['images_lazy_count']  = lazy_count
    op['images_alt_ok']      = seo['images_missing_alt'] == 0

    # Content metrics
    body_text = soup.get_text(separator=' ', strip=True)
    words = [w for w in re.split(r'\s+', body_text) if w]
    word_count = len(words)
    sentences  = [s.strip() for s in re.split(r'[.!?]+', body_text) if len(s.strip()) > 10]
    avg_sentence_len = round(sum(len(s.split()) for s in sentences) / max(len(sentences), 1), 1)
    html_len  = len(str(soup))
    text_len  = len(body_text)
    text_ratio = round((text_len / max(html_len, 1)) * 100, 1)

    op['word_count']        = word_count
    op['word_count_ok']     = word_count >= 300
    op['avg_sentence_len']  = avg_sentence_len
    op['text_html_ratio']   = text_ratio
    op['text_ratio_ok']     = text_ratio >= 10
    op['paragraph_count']   = len(soup.find_all('p'))

    # Keyword extraction — top 10 meaningful words
    stopwords = {
        'the','a','an','and','or','but','in','on','at','to','for','of','with',
        'is','are','was','were','be','been','being','have','has','had','do',
        'does','did','will','would','could','should','may','might','shall',
        'this','that','these','those','it','its','by','from','as','into',
        'through','during','before','after','above','below','between','out',
        'up','down','about','than','so','if','not','no','nor','yet','both',
        'either','each','few','more','most','other','some','such','any','all',
    }
    freq = {}
    for w in words:
        w_clean = re.sub(r'[^a-z]', '', w.lower())
        if len(w_clean) >= 4 and w_clean not in stopwords:
            freq[w_clean] = freq.get(w_clean, 0) + 1
    top_keywords = sorted(freq.items(), key=lambda x: -x[1])[:10]
    op['top_keywords'] = [{'word': w, 'count': c} for w, c in top_keywords]

    # Keyword placement checks (using top keyword if available)
    if top_keywords:
        kw = top_keywords[0][0]
        op['keyword_in_title']       = kw in (seo.get('title') or '').lower()
        op['keyword_in_description'] = kw in (seo.get('description') or '').lower()
        op['keyword_in_h1']          = any(kw in h.get_text(strip=True).lower() for h in soup.find_all('h1'))
        op['keyword_in_url']         = kw in url_full.lower()
        op['primary_keyword']        = kw
    else:
        op['keyword_in_title'] = op['keyword_in_description'] = False
        op['keyword_in_h1'] = op['keyword_in_url'] = False
        op['primary_keyword'] = None

    # On-page score (out of 100)
    op_score = 100
    deductions = [
        (not op['url_ok'],               5,  'URL too long'),
        (op['url_has_underscores'],       5,  'URL uses underscores'),
        (not op['heading_hierarchy_ok'],  10, 'Poor heading hierarchy'),
        (not op['internal_links_ok'],     10, 'Too few internal links'),
        (not op['images_alt_ok'],         10, 'Images missing alt text'),
        (not op['word_count_ok'],         15, 'Low word count (<300)'),
        (not op['text_ratio_ok'],         5,  'Low text-to-HTML ratio'),
        (not op['keyword_in_title'],      10, 'Primary keyword not in title'),
        (not op['keyword_in_h1'],         10, 'Primary keyword not in H1'),
        (not op['keyword_in_description'],5,  'Primary keyword not in meta description'),
    ]
    op['issues'] = [msg for cond, _, msg in deductions if cond]
    for cond, pts, _ in deductions:
        if cond:
            op_score -= pts
    op['score'] = max(0, op_score)

    # ── Overall SEO score ─────────────────────────────────────────────────────
    score = 100
    if not seo['title_ok']:            score -= 15
    if not seo['description_ok']:     score -= 15
    if not seo['h1_ok']:              score -= 10
    if seo['images_missing_alt'] > 0: score -= min(10, seo['images_missing_alt'] * 2)
    if not seo['canonical']:          score -= 10
    if not seo['og']['title']:        score -= 5
    if not seo['og']['description']:  score -= 5
    if not seo['twitter']['card']:    score -= 5
    if broken:                        score -= min(25, len(broken) * 5)
    seo['score'] = max(0, score)

    return seo


def scan_vulnerabilities(url, response, soup):
    """Comprehensive vulnerability scan"""
    vulnerabilities = []

    # Check security headers
    vulnerabilities.extend(check_security_headers(response))

    # Check for information leakage
    vulnerabilities.extend(check_server_info_leakage(response.headers))

    # Check SSL/TLS
    vulnerabilities.extend(check_ssl_vulnerabilities(url))

    # Check for exposed sensitive files
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    vulnerabilities.extend(check_sensitive_files(base_url))

    # Check for forms without CSRF protection
    forms = soup.find_all('form')
    for form in forms:
        method = form.get('method', 'get').lower()
        if method == 'post':
            # Check for CSRF token
            has_csrf = False
            for input_tag in form.find_all('input'):
                name = input_tag.get('name', '').lower()
                if 'csrf' in name or 'token' in name:
                    has_csrf = True
                    break

            if not has_csrf:
                vulnerabilities.append({
                    'type': 'CSRF Vulnerability',
                    'severity': 'High',
                    'description': 'POST form found without CSRF token protection',
                    'damage': 'Attackers can craft malicious websites that submit requests to your site using victims\' authenticated sessions. This allows unauthorized actions like changing passwords, transferring funds, deleting accounts, or modifying data without user consent.'
                })

    # Check for mixed content (HTTP resources on HTTPS page)
    if urlparse(url).scheme == 'https':
        http_resources = []
        for tag in soup.find_all(['img', 'script', 'link', 'iframe']):
            src = tag.get('src', '') or tag.get('href', '')
            if src.startswith('http://'):
                http_resources.append(src)

        if http_resources:
            vulnerabilities.append({
                'type': 'Mixed Content',
                'severity': 'Medium',
                'description': f'Page loads {len(http_resources)} HTTP resource(s) on HTTPS page',
                'damage': 'HTTP resources on HTTPS pages can be intercepted and modified by attackers, potentially injecting malicious scripts that steal cookies, session tokens, or user data, breaking the security of the entire page.'
            })

    # Check for suspicious patterns in content
    text_content = soup.get_text().lower()

    # Check for potential SQL errors
    sql_errors = ['sql error', 'mysql error', 'sqlsyntaxerrorexception', 'warning: mysql']
    for error in sql_errors:
        if error in text_content:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'Medium',
                'description': f'Possible SQL error message exposed in page content',
                'damage': 'SQL error messages reveal database structure, table names, and query logic. Attackers can use this information to craft targeted SQL injection attacks that extract, modify, or delete database contents including user data and passwords.'
            })
            break

    # Check for exposed email addresses
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', str(soup))
    if emails:
        vulnerabilities.append({
            'type': 'Information Disclosure',
            'severity': 'Low',
            'description': f'Email address(es) exposed in page: {len(emails)} found',
            'damage': 'Exposed email addresses are harvested by spammers and phishers. Staff receive targeted phishing emails designed to steal credentials or deploy malware, increasing the risk of account compromise and network infiltration.'
        })

    # HTTP → HTTPS redirect check
    if urlparse(url).scheme == 'https':
        redirects = check_https_redirect(url)
        if redirects is False:
            vulnerabilities.append({
                'type': 'Missing HTTPS Redirect',
                'severity': 'High',
                'description': 'HTTP version of the site does not redirect to HTTPS',
                'damage': 'Users who visit the HTTP URL are not automatically forced to the secure version, leaving their traffic exposed to interception and man-in-the-middle attacks.'
            })

    # Calculate risk score
    severity_weights = {
        'Critical': 10,
        'High': 7,
        'Medium': 4,
        'Low': 1
    }

    total_score = sum(severity_weights.get(v['severity'], 0) for v in vulnerabilities)

    return {
        'vulnerabilities': vulnerabilities,
        'summary': {
            'total': len(vulnerabilities),
            'critical': len([v for v in vulnerabilities if v['severity'] == 'Critical']),
            'high': len([v for v in vulnerabilities if v['severity'] == 'High']),
            'medium': len([v for v in vulnerabilities if v['severity'] == 'Medium']),
            'low': len([v for v in vulnerabilities if v['severity'] == 'Low']),
            'risk_score': min(total_score, 100)
        }
    }


def detect_tech_info(url, response, soup):
    """Detect technology stack, hosting, domain, and website intelligence."""
    NA = 'Not publicly disclosed'
    info = {
        'frontend': [], 'backend': [], 'cms': None, 'cdn': None,
        'analytics': [], 'libraries': [], 'social_links': [],
        'ip': NA, 'country': NA, 'isp': NA, 'org': NA, 'city': NA,
        'domain_registrar': NA, 'domain_created': NA, 'domain_expires': NA,
        'domain_owner': NA, 'domain_nameservers': [],
        'wayback_first': NA, 'wayback_total': NA,
        'ssl_issuer': NA, 'ssl_expires': NA, 'ssl_valid': None,
        'http_version': NA, 'response_time_ms': NA, 'page_size_kb': NA,
        'spf': NA, 'dmarc': NA,
        'purpose': NA, 'mobile_ready': False, 'cookie_banner': False,
        'email_security_score': NA,
    }

    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    headers_resp = response.headers

    # --- Response performance ---
    info['response_time_ms'] = round(response.elapsed.total_seconds() * 1000)
    info['page_size_kb'] = round(len(response.content) / 1024, 1)

    # --- HTTP version ---
    try:
        ver = response.raw.version
        info['http_version'] = 'HTTP/2' if ver == 20 else 'HTTP/1.1' if ver == 11 else f'HTTP/{ver}'
    except Exception:
        pass

    # --- Tech stack from headers ---
    server = headers_resp.get('Server', '')
    powered = headers_resp.get('X-Powered-By', '')
    via = headers_resp.get('Via', '')
    cf_ray = headers_resp.get('CF-Ray', '')
    x_cache = headers_resp.get('X-Cache', '')

    if server:
        s_low = server.lower()
        if 'nginx' in s_low:    info['backend'].append('Nginx')
        if 'apache' in s_low:   info['backend'].append('Apache')
        if 'iis' in s_low:      info['backend'].append('IIS (Microsoft)')
        if 'cloudflare' in s_low: info['cdn'] = 'Cloudflare'
        if 'lighttpd' in s_low: info['backend'].append('Lighttpd')
        if 'gunicorn' in s_low: info['backend'].append('Gunicorn (Python)')
        if 'caddy' in s_low:    info['backend'].append('Caddy')

    if powered:
        p_low = powered.lower()
        if 'php' in p_low:      info['backend'].append(f'PHP ({powered})')
        if 'node' in p_low or 'express' in p_low: info['backend'].append('Node.js / Express')
        if 'asp.net' in p_low:  info['backend'].append('ASP.NET')
        if 'django' in p_low:   info['backend'].append('Django (Python)')
        if 'rails' in p_low:    info['backend'].append('Ruby on Rails')

    if cf_ray or 'cloudflare' in server.lower():
        info['cdn'] = 'Cloudflare'
    if headers_resp.get('X-Amz-Cf-Id') or headers_resp.get('X-Amz-Request-Id'):
        info['cdn'] = 'AWS CloudFront'
    if 'fastly' in via.lower() or 'fastly' in x_cache.lower():
        info['cdn'] = 'Fastly'
    if 'akamai' in via.lower():
        info['cdn'] = 'Akamai'

    # --- Frontend / CMS from HTML ---
    html_str = str(soup)

    # CMS
    generator = soup.find('meta', attrs={'name': 'generator'})
    if generator:
        gen_val = generator.get('content', '')
        info['cms'] = gen_val if gen_val else None

    cms_patterns = [
        ('WordPress', ['/wp-content/', '/wp-includes/']),
        ('Shopify', ['cdn.shopify.com', 'shopify.com/s/']),
        ('Wix', ['static.wixstatic.com', 'wix.com']),
        ('Squarespace', ['squarespace.com', 'sqspcdn.com']),
        ('Webflow', ['webflow.com', 'wf-']),
        ('Drupal', ['/sites/default/files', 'drupal']),
        ('Joomla', ['/components/com_']),
        ('Ghost', ['ghost.org', 'ghost-theme']),
    ]
    if not info['cms']:
        for cms_name, patterns in cms_patterns:
            if any(p in html_str for p in patterns):
                info['cms'] = cms_name
                break

    # Frontend framework
    fw_patterns = [
        ('React', ['data-reactroot', '_reactFiber', '__REACT_', 'react-dom']),
        ('Next.js', ['__NEXT_DATA__', '_next/static', 'next/dist']),
        ('Gatsby', ['gatsby-', '__gatsby']),
        ('Vue.js', ['__vue__', 'data-v-', 'vue.min.js', 'vue.js']),
        ('Nuxt.js', ['__NUXT__', '_nuxt/']),
        ('Angular', ['ng-version', 'angular.min.js', 'ng-app']),
        ('Svelte', ['__svelte', 'svelte/']),
        ('Ember.js', ['ember.min.js', 'EmberENV']),
    ]
    for fw_name, patterns in fw_patterns:
        if any(p in html_str for p in patterns):
            info['frontend'].append(fw_name)

    # JS libraries
    lib_patterns = [
        ('jQuery', ['jquery.min.js', 'jquery.js', 'jquery-']),
        ('Bootstrap', ['bootstrap.min.js', 'bootstrap.min.css', 'bootstrap/']),
        ('Tailwind CSS', ['tailwind', 'tailwindcss']),
        ('Lodash', ['lodash.min.js', 'lodash.js']),
        ('D3.js', ['d3.min.js', 'd3.js']),
        ('Three.js', ['three.min.js', 'three.js']),
        ('GSAP', ['gsap.min.js', 'TweenMax']),
    ]
    for lib_name, patterns in lib_patterns:
        if any(p in html_str for p in patterns):
            info['libraries'].append(lib_name)

    # Analytics & marketing
    analytics_patterns = [
        ('Google Analytics', ['google-analytics.com/analytics', 'gtag(', 'UA-', 'G-']),
        ('Google Tag Manager', ['googletagmanager.com', 'GTM-']),
        ('Facebook Pixel', ['connect.facebook.net', 'fbq(']),
        ('Hotjar', ['hotjar.com', 'hjid']),
        ('Mixpanel', ['mixpanel.com', 'mixpanel.init']),
        ('Segment', ['segment.com/analytics', 'analytics.js']),
        ('Heap', ['heapanalytics.com', 'heap.track']),
        ('Intercom', ['intercomcdn.com', 'Intercom(']),
    ]
    for tool_name, patterns in analytics_patterns:
        if any(p in html_str for p in patterns):
            info['analytics'].append(tool_name)

    # Social media links
    social_domains = {
        'facebook.com': 'Facebook', 'twitter.com': 'Twitter', 'x.com': 'X (Twitter)',
        'instagram.com': 'Instagram', 'linkedin.com': 'LinkedIn', 'youtube.com': 'YouTube',
        'tiktok.com': 'TikTok', 'github.com': 'GitHub', 'pinterest.com': 'Pinterest',
    }
    seen_socials = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        for domain, name in social_domains.items():
            if domain in href and name not in seen_socials:
                seen_socials.add(name)
                info['social_links'].append({'platform': name, 'url': href})

    # Mobile ready
    viewport = soup.find('meta', attrs={'name': 'viewport'})
    info['mobile_ready'] = bool(viewport)

    # Cookie banner
    cookie_patterns = ['cookie-consent', 'cookieconsent', 'gdpr', 'cookie-banner', 'cookie-notice']
    info['cookie_banner'] = any(p in html_str.lower() for p in cookie_patterns)

    # Purpose from meta description / OG
    meta_desc = soup.find('meta', attrs={'name': re.compile(r'^description$', re.I)})
    og_desc = soup.find('meta', property='og:description')
    info['purpose'] = (meta_desc and meta_desc.get('content', '').strip()) or \
                      (og_desc and og_desc.get('content', '').strip()) or NA

    # --- Parallel external calls ---
    def get_ip_geo():
        try:
            ip = socket.gethostbyname(hostname)
            geo = requests.get(f'http://ip-api.com/json/{ip}', timeout=5).json()
            return {
                'ip': ip,
                'country': geo.get('country', NA),
                'isp': geo.get('isp', NA),
                'org': geo.get('org', NA),
                'city': geo.get('city', NA),
            }
        except Exception:
            return {}

    def get_whois():
        try:
            import whois as whois_lib
            w = whois_lib.whois(hostname)
            created = w.creation_date
            expires = w.expiration_date
            if isinstance(created, list): created = created[0]
            if isinstance(expires, list): expires = expires[0]
            ns = w.name_servers or []
            ns = [str(n).lower() for n in (ns[:3] if isinstance(ns, list) else [ns])]
            return {
                'domain_registrar': w.registrar or NA,
                'domain_owner': (w.org or w.name or NA),
                'domain_created': str(created.date()) if created else NA,
                'domain_expires': str(expires.date()) if expires else NA,
                'domain_nameservers': ns,
            }
        except Exception:
            return {}

    def get_wayback():
        try:
            cdx = requests.get(
                f'http://web.archive.org/cdx/search/cdx?url={hostname}&output=json&limit=1&fl=timestamp&from=19900101&to=20261231',
                timeout=6
            ).json()
            if len(cdx) > 1:
                first_ts = cdx[1][0]
                first_date = f"{first_ts[:4]}-{first_ts[4:6]}-{first_ts[6:8]}"
            else:
                first_date = NA
            return {'wayback_first': first_date}
        except Exception:
            return {}

    def get_ssl_info():
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                cert = s.getpeercert()
            issuer = dict(x[0] for x in cert.get('issuer', []))
            not_after = cert.get('notAfter', '')
            return {
                'ssl_issuer': issuer.get('organizationName', issuer.get('O', NA)),
                'ssl_expires': not_after,
                'ssl_valid': True,
            }
        except Exception:
            return {'ssl_valid': False}

    def get_dns_email_security():
        try:
            import dns.resolver
            result = {}
            # SPF
            try:
                txts = dns.resolver.resolve(hostname, 'TXT', lifetime=5)
                for r in txts:
                    txt = r.to_text().strip('"')
                    if txt.startswith('v=spf1'):
                        result['spf'] = txt[:80]
                        break
                else:
                    result['spf'] = 'Not configured'
            except Exception:
                result['spf'] = 'Not configured'
            # DMARC
            try:
                dmarc_txts = dns.resolver.resolve(f'_dmarc.{hostname}', 'TXT', lifetime=5)
                for r in dmarc_txts:
                    txt = r.to_text().strip('"')
                    if txt.startswith('v=DMARC1'):
                        result['dmarc'] = txt[:80]
                        break
                else:
                    result['dmarc'] = 'Not configured'
            except Exception:
                result['dmarc'] = 'Not configured'
            # Score
            configured = sum(1 for k in ['spf', 'dmarc'] if result.get(k, '') not in ('Not configured', NA))
            result['email_security_score'] = f'{configured}/2 records configured'
            return result
        except ImportError:
            return {}

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {
            ex.submit(get_ip_geo): 'geo',
            ex.submit(get_whois): 'whois',
            ex.submit(get_wayback): 'wayback',
            ex.submit(get_ssl_info): 'ssl',
            ex.submit(get_dns_email_security): 'dns',
        }
        for future in as_completed(futures):
            try:
                result = future.result()
                info.update(result)
            except Exception:
                pass

    return info


def scrape_website(url):
    """Scrape all data from a website"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=30, verify=False)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'html.parser')

        # Perform vulnerability scan, SEO analysis, and tech detection on unmodified soup
        vulnerability_scan = scan_vulnerabilities(url, response, soup)
        seo_data = analyze_seo(url, soup)
        tech_info = detect_tech_info(url, response, soup)

        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer", "header"]):
            script.decompose()

        data = {
            'url': url,
            'title': '',
            'headings': [],
            'paragraphs': [],
            'links': [],
            'images': [],
            'tables': [],
            'lists': {'ul': [], 'ol': []},
            'meta_tags': {},
            'all_text': '',
            'vulnerabilities': vulnerability_scan,
            'seo': seo_data,
            'tech': tech_info,
        }

        # Extract title
        if soup.title:
            data['title'] = soup.title.string.strip() if soup.title.string else ''

        # Extract meta tags
        for meta in soup.find_all('meta'):
            name = meta.get('name', meta.get('property', ''))
            content = meta.get('content', '')
            if name and content:
                data['meta_tags'][name] = content

        # Extract headings
        for i in range(1, 7):
            for h in soup.find_all(f'h{i}'):
                text = h.get_text(strip=True)
                if text:
                    data['headings'].append({'level': i, 'text': text})

        # Extract paragraphs
        for p in soup.find_all('p'):
            text = p.get_text(strip=True)
            if text and len(text) > 10:  # Filter out short/empty paragraphs
                data['paragraphs'].append(text)

        # Extract links
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for a in soup.find_all('a', href=True):
            href = a['href']
            text = a.get_text(strip=True)
            if href:
                full_url = urljoin(base_url, href)
                data['links'].append({
                    'text': text[:100] if text else 'No text',
                    'url': full_url
                })

        # Extract images
        for img in soup.find_all('img'):
            src = img.get('src', '')
            alt = img.get('alt', '')
            if src:
                full_url = urljoin(base_url, src)
                data['images'].append({'src': full_url, 'alt': alt})

        # Extract tables
        for table in soup.find_all('table'):
            table_data = []
            for row in table.find_all('tr'):
                row_data = [cell.get_text(strip=True) for cell in row.find_all(['td', 'th'])]
                if row_data:
                    table_data.append(row_data)
            if table_data:
                data['tables'].append(table_data)

        # Extract lists
        for ul in soup.find_all('ul'):
            items = [li.get_text(strip=True) for li in ul.find_all('li') if li.get_text(strip=True)]
            if items:
                data['lists']['ul'].append(items)

        for ol in soup.find_all('ol'):
            items = [li.get_text(strip=True) for li in ol.find_all('li') if li.get_text(strip=True)]
            if items:
                data['lists']['ol'].append(items)

        # Extract all text content
        all_text = soup.get_text(separator='\n', strip=True)
        # Clean up excessive whitespace
        all_text = re.sub(r'\n+', '\n', all_text)
        all_text = re.sub(r'\s+', ' ', all_text)
        data['all_text'] = all_text[:50000]  # Limit to 50k characters

        return data

    except requests.RequestException as e:
        raise Exception(f"Failed to fetch website: {str(e)}")
    except Exception as e:
        raise Exception(f"Error scraping website: {str(e)}")


@app.route('/api/scrape', methods=['POST'])
def scrape():
    """API endpoint to scrape a website"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        # Auto-prepend https:// if no protocol given
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if not is_valid_url(url):
            return jsonify({'error': 'Invalid URL format. Please provide a valid URL (e.g., https://example.com)'}), 400

        # Block private/internal IP scanning
        parsed_host = urlparse(url).hostname or ''
        try:
            resolved_ip = socket.gethostbyname(parsed_host)
            if PRIVATE_NETS.match(resolved_ip) or PRIVATE_NETS.match(parsed_host):
                return jsonify({'error': 'Scanning private or internal network addresses is not permitted.'}), 403
        except Exception:
            pass

        # Rate limiting
        client_ip = get_client_ip()
        domain = parsed_host.lower()
        blocked, block_info, warnings = check_rate_limit(client_ip, domain)

        if blocked:
            return jsonify({
                'error': 'blocked',
                'block': block_info,
            }), 429

        # Record this scan attempt before running (counts against limit)
        record_scan_event(client_ip, domain)

        # Scrape the website
        scraped_data = scrape_website(url)

        # Store with unique ID
        session_id = str(uuid.uuid4())
        scraped_data_store[session_id] = scraped_data
        log_scan(scraped_data)

        return jsonify({
            'success': True,
            'session_id': session_id,
            'data': scraped_data,
            'warnings': warnings,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/csv/<session_id>', methods=['GET'])
def export_csv(session_id):
    """Export scraped data as CSV with section filtering."""
    if session_id not in scraped_data_store:
        return jsonify({'error': 'Session not found'}), 404

    sections_param = request.args.get('sections', '')
    sections = set(sections_param.split(',')) if sections_param else {
        'overview', 'vulnerabilities', 'tech', 'seo', 'headings', 'paragraphs',
        'links', 'images', 'tables', 'lists', 'fulltext'
    }
    data = scraped_data_store[session_id]

    def esc(s):
        return str(s).replace('"', '""').replace('\n', ' ').replace('\r', '')

    try:
        output = io.StringIO()

        if 'overview' in sections:
            output.write(f'Title,"{esc(data["title"])}"\n')
            output.write(f'URL,{data["url"]}\n\n')

        if 'tech' in sections and 'tech' in data:
            t = data['tech']
            output.write('Tech Intelligence\nField,Value\n')
            rows = [
                ('Frontend Framework', ', '.join(t.get('frontend', [])) or 'Not detected'),
                ('Backend / Server',   ', '.join(t.get('backend', []))  or 'Not detected'),
                ('CMS',               t.get('cms') or 'Not detected'),
                ('CDN',               t.get('cdn') or 'Not detected'),
                ('JS Libraries',      ', '.join(t.get('libraries', [])) or 'Not detected'),
                ('Analytics Tools',   ', '.join(t.get('analytics', [])) or 'Not detected'),
                ('IP Address',        t.get('ip', '')),
                ('Country',           t.get('country', '')),
                ('City',              t.get('city', '')),
                ('ISP / Hosting',     t.get('isp', '')),
                ('Organization',      t.get('org', '')),
                ('Domain Registrar',  t.get('domain_registrar', '')),
                ('Domain Owner',      t.get('domain_owner', '')),
                ('Domain Created',    t.get('domain_created', '')),
                ('Domain Expires',    t.get('domain_expires', '')),
                ('Name Servers',      ', '.join(t.get('domain_nameservers', []))),
                ('SSL Issuer',        t.get('ssl_issuer', '')),
                ('SSL Expires',       t.get('ssl_expires', '')),
                ('SSL Valid',         str(t.get('ssl_valid', ''))),
                ('SPF Record',        t.get('spf', '')),
                ('DMARC Record',      t.get('dmarc', '')),
                ('Email Security',    t.get('email_security_score', '')),
                ('First Archived',    t.get('wayback_first', '')),
                ('HTTP Version',      t.get('http_version', '')),
                ('Response Time',     f"{t.get('response_time_ms', '')} ms"),
                ('Page Size',         f"{t.get('page_size_kb', '')} KB"),
                ('Mobile Ready',      str(t.get('mobile_ready', ''))),
                ('Cookie Consent',    str(t.get('cookie_banner', ''))),
                ('Website Purpose',   t.get('purpose', '')),
                ('Social Profiles',   ', '.join(s['platform'] for s in t.get('social_links', []))),
            ]
            for field, val in rows:
                output.write(f'"{esc(field)}","{esc(val)}"\n')
            output.write('\n')

        if 'vulnerabilities' in sections:
            vulns = data.get('vulnerabilities', {}).get('vulnerabilities', [])
            if vulns:
                output.write('Vulnerabilities\nSeverity,Type,Description\n')
                for v in vulns:
                    output.write(f'"{esc(v["severity"])}","{esc(v["type"])}","{esc(v["description"])}"\n')
                output.write('\n')

        if 'seo' in sections and 'seo' in data:
            seo = data['seo']
            output.write('SEO Analysis\n')
            output.write(f'Score,{seo.get("score", "N/A")}\n')
            output.write(f'Title OK,{seo.get("title_ok", False)}\n')
            output.write(f'Description OK,{seo.get("description_ok", False)}\n')
            output.write(f'H1 Count,{seo.get("h1_count", 0)}\n')
            output.write(f'Images Missing Alt,{seo.get("images_missing_alt", 0)}\n')
            output.write(f'Canonical,"{esc(seo.get("canonical", ""))}"\n')
            if seo.get('broken_links'):
                output.write('Broken Links\nURL,Status\n')
                for bl in seo['broken_links']:
                    output.write(f'"{esc(bl["url"])}",{bl["status"]}\n')
            output.write('\n')

        if 'headings' in sections and data.get('headings'):
            output.write('Headings\nLevel,Text\n')
            for h in data['headings']:
                output.write(f'H{h["level"]},"{esc(h["text"])}"\n')
            output.write('\n')

        if 'paragraphs' in sections and data.get('paragraphs'):
            output.write('Paragraphs\nContent\n')
            for p in data['paragraphs']:
                output.write(f'"{esc(p)}"\n')
            output.write('\n')

        if 'links' in sections and data.get('links'):
            output.write('Links\nText,URL\n')
            for link in data['links'][:100]:
                output.write(f'"{esc(link["text"])}",{link["url"]}\n')
            output.write('\n')

        if 'images' in sections and data.get('images'):
            output.write('Images\nURL,Alt\n')
            for img in data['images']:
                output.write(f'"{esc(img["src"])}","{esc(img.get("alt", ""))}"\n')
            output.write('\n')

        if 'tables' in sections and data.get('tables'):
            output.write('Tables\n')
            for i, table in enumerate(data['tables'][:10], 1):
                output.write(f'Table {i}\n')
                for row in table:
                    output.write(','.join(f'"{esc(cell)}"' for cell in row) + '\n')
                output.write('\n')

        if 'lists' in sections:
            for kind, style in [('ul', 'Unordered'), ('ol', 'Ordered')]:
                items = data.get('lists', {}).get(kind, [])
                if items:
                    output.write(f'{style} Lists\n')
                    for lst in items[:10]:
                        for item in lst[:20]:
                            output.write(f'"{esc(item)}"\n')
                    output.write('\n')

        if 'fulltext' in sections and data.get('all_text'):
            output.write(f'Full Text\n"{esc(data["all_text"][:10000])}"\n\n')

        output.seek(0)
        mem = io.BytesIO()
        mem.write(output.getvalue().encode('utf-8'))
        mem.seek(0)

        log_export(data.get('url'), 'csv')
        return send_file(
            mem,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f"vulnscan_{urlparse(data['url']).netloc}.csv"
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/doc/<session_id>', methods=['GET'])
def export_doc(session_id):
    """Export scraped data as DOCX with section filtering and improved template."""
    if session_id not in scraped_data_store:
        return jsonify({'error': 'Session not found'}), 404

    sections_param = request.args.get('sections', '')
    sections = set(sections_param.split(',')) if sections_param else {
        'overview', 'vulnerabilities', 'tech', 'seo', 'headings', 'paragraphs',
        'links', 'images', 'tables', 'lists', 'fulltext'
    }
    data = scraped_data_store[session_id]

    try:
        doc = Document()
        generated_at = datetime.now().strftime('%B %d, %Y')
        generated_ts = datetime.now().strftime('%Y-%m-%d %H:%M')

        # ── Cover page ──────────────────────────────────────────────────────
        doc.add_paragraph()
        cover = doc.add_heading('VulnScan Security Report', 0)
        cover.alignment = WD_ALIGN_PARAGRAPH.CENTER

        for text in [data.get('title') or data['url'], data['url'], f'Generated: {generated_at}']:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.add_run(text)

        doc.add_paragraph()

        # Summary scores table
        risk_score = data.get('vulnerabilities', {}).get('summary', {}).get('risk_score', 0)
        seo_score = data.get('seo', {}).get('score', 'N/A')
        tbl = doc.add_table(rows=2, cols=2)
        tbl.style = 'Table Grid'
        for cell, txt in zip(tbl.rows[0].cells, ['Security Risk Score', 'SEO Score']):
            cell.paragraphs[0].add_run(txt).bold = True
        tbl.rows[1].cells[0].text = f'{risk_score} / 100'
        tbl.rows[1].cells[1].text = f'{seo_score} / 100' if isinstance(seo_score, int) else str(seo_score)

        doc.add_page_break()

        # ── Footer ──────────────────────────────────────────────────────────
        footer_para = doc.sections[0].footer.paragraphs[0]
        footer_para.text = f'VulnScan Report  •  {data["url"]}  •  {generated_ts}'
        footer_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

        # ── Sections ────────────────────────────────────────────────────────
        if 'overview' in sections:
            doc.add_heading('Overview', level=1)
            p = doc.add_paragraph()
            p.add_run('Source URL: ').bold = True
            p.add_run(data['url'])
            ov_tbl = doc.add_table(rows=1, cols=2)
            ov_tbl.style = 'Table Grid'
            for c, t in zip(ov_tbl.rows[0].cells, ['Item', 'Value']):
                c.paragraphs[0].add_run(t).bold = True
            for label, val in [
                ('Title', data.get('title', 'N/A')),
                ('Headings', len(data.get('headings', []))),
                ('Paragraphs', len(data.get('paragraphs', []))),
                ('Links', len(data.get('links', []))),
                ('Images', len(data.get('images', []))),
                ('Tables', len(data.get('tables', []))),
            ]:
                r = ov_tbl.add_row()
                r.cells[0].text = label
                r.cells[1].text = str(val)
            doc.add_paragraph()

        if 'vulnerabilities' in sections:
            doc.add_heading('Vulnerabilities', level=1)
            vs = data.get('vulnerabilities', {}).get('summary', {})
            sp = doc.add_paragraph()
            sp.add_run(
                f"Total: {vs.get('total',0)}  |  Critical: {vs.get('critical',0)}  |  "
                f"High: {vs.get('high',0)}  |  Medium: {vs.get('medium',0)}  |  Low: {vs.get('low',0)}"
            )
            for v in data.get('vulnerabilities', {}).get('vulnerabilities', []):
                bp = doc.add_paragraph(style='List Bullet')
                bp.add_run(f"[{v['severity']}] {v['type']}: ").bold = True
                bp.add_run(v['description'])
            doc.add_paragraph()

        if 'tech' in sections and 'tech' in data:
            t = data['tech']
            doc.add_heading('Website Intelligence', level=1)
            tech_rows = [
                ('Frontend Framework', ', '.join(t.get('frontend', [])) or 'Not detected'),
                ('Backend / Server',   ', '.join(t.get('backend', []))  or 'Not detected'),
                ('CMS',               t.get('cms') or 'Not detected'),
                ('CDN Provider',      t.get('cdn') or 'Not detected'),
                ('JS Libraries',      ', '.join(t.get('libraries', [])) or 'Not detected'),
                ('Analytics Tools',   ', '.join(t.get('analytics', [])) or 'Not detected'),
                ('IP Address',        t.get('ip', '')),
                ('Country',           t.get('country', '')),
                ('ISP / Hosting',     t.get('isp', '')),
                ('Domain Registrar',  t.get('domain_registrar', '')),
                ('Domain Owner',      t.get('domain_owner', '')),
                ('Domain Created',    t.get('domain_created', '')),
                ('Domain Expires',    t.get('domain_expires', '')),
                ('SSL Issuer',        t.get('ssl_issuer', '')),
                ('SSL Valid',         'Yes' if t.get('ssl_valid') else 'No'),
                ('SPF Record',        t.get('spf', '')),
                ('DMARC Record',      t.get('dmarc', '')),
                ('First Archived',    t.get('wayback_first', '')),
                ('HTTP Version',      t.get('http_version', '')),
                ('Response Time',     f"{t.get('response_time_ms', '')} ms"),
                ('Mobile Ready',      'Yes' if t.get('mobile_ready') else 'No'),
                ('Website Purpose',   t.get('purpose', '')),
            ]
            tt = doc.add_table(rows=1, cols=2)
            tt.style = 'Table Grid'
            for c, h in zip(tt.rows[0].cells, ['Field', 'Value']):
                c.paragraphs[0].add_run(h).bold = True
            for field, val in tech_rows:
                r = tt.add_row()
                r.cells[0].text = field
                r.cells[1].text = str(val) if val else 'Not publicly disclosed'
            doc.add_paragraph()

        if 'seo' in sections and 'seo' in data:
            seo = data['seo']
            doc.add_heading('SEO Analysis', level=1)
            sp = doc.add_paragraph()
            sp.add_run(f"SEO Score: {seo.get('score', 'N/A')} / 100").bold = True
            checks = [
                ('Title', seo.get('title_ok'), seo.get('title', 'Missing')[:80]),
                ('Meta Description', seo.get('description_ok'), f"{seo.get('description_length', 0)} chars" if seo.get('description') else 'Missing'),
                ('Single H1', seo.get('h1_ok'), f"{seo.get('h1_count', 0)} found"),
                ('Image Alt Tags', seo.get('images_missing_alt', 1) == 0, f"{seo.get('images_missing_alt', 0)} missing of {seo.get('images_total', 0)}"),
                ('Canonical URL', bool(seo.get('canonical')), seo.get('canonical', 'Not set')[:60]),
                ('OG Tags', bool(seo.get('og', {}).get('title')), 'Present' if seo.get('og', {}).get('title') else 'Missing'),
                ('Twitter Card', bool(seo.get('twitter', {}).get('card')), seo.get('twitter', {}).get('card', 'Not set')),
            ]
            for label, ok, detail in checks:
                bp = doc.add_paragraph(style='List Bullet')
                bp.add_run(f"{'✓' if ok else '✗'} {label}: ").bold = True
                bp.add_run(detail)
            if seo.get('broken_links'):
                doc.add_paragraph().add_run(f"Broken links ({len(seo['broken_links'])} found):").bold = True
                for bl in seo['broken_links']:
                    doc.add_paragraph(f"{bl['url']} → {bl['status']}", style='List Bullet')
            doc.add_paragraph()

        if 'headings' in sections and data.get('headings'):
            doc.add_heading('Headings', level=1)
            for h in data['headings']:
                p = doc.add_paragraph()
                p.add_run(f"H{h['level']}: ").bold = True
                p.add_run(h['text'])
            doc.add_paragraph()

        if 'paragraphs' in sections and data.get('paragraphs'):
            doc.add_heading('Paragraphs', level=1)
            for para in data['paragraphs'][:50]:
                doc.add_paragraph(para)
            doc.add_paragraph()

        if 'links' in sections and data.get('links'):
            doc.add_heading('Links', level=1)
            for link in data['links'][:50]:
                p = doc.add_paragraph(style='List Bullet')
                p.add_run(f"{link['text']}: ").bold = True
                p.add_run(link['url'])
            doc.add_paragraph()

        if 'images' in sections and data.get('images'):
            doc.add_heading('Images', level=1)
            for img in data['images'][:30]:
                p = doc.add_paragraph(style='List Bullet')
                p.add_run(f"Source: {img['src']}")
                if img.get('alt'):
                    p.add_run(f"  |  Alt: {img['alt']}")
            doc.add_paragraph()

        if 'tables' in sections and data.get('tables'):
            doc.add_heading('Tables', level=1)
            for i, table_data in enumerate(data['tables'][:5], 1):
                if table_data:
                    doc.add_paragraph(f'Table {i}', style='Heading 3')
                    dt = doc.add_table(rows=len(table_data), cols=max(len(r) for r in table_data))
                    dt.style = 'Table Grid'
                    for ri, row_data in enumerate(table_data):
                        for ci, cell_text in enumerate(row_data):
                            if ci < len(dt.rows[ri].cells):
                                dt.rows[ri].cells[ci].text = str(cell_text)
                    doc.add_paragraph()

        if 'lists' in sections:
            for lst_key, heading, style in [('ul', 'Unordered Lists', 'List Bullet'), ('ol', 'Ordered Lists', 'List Number')]:
                items = data.get('lists', {}).get(lst_key, [])
                if items:
                    doc.add_heading(heading, level=1)
                    for lst in items[:10]:
                        for item in lst[:20]:
                            doc.add_paragraph(item, style=style)
                        doc.add_paragraph()

        if 'fulltext' in sections and data.get('all_text'):
            doc.add_page_break()
            doc.add_heading('Full Text Content', level=1)
            doc.add_paragraph(data['all_text'])

        mem = io.BytesIO()
        doc.save(mem)
        mem.seek(0)

        log_export(data.get('url'), 'doc')
        return send_file(
            mem,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            as_attachment=True,
            download_name=f"vulnscan_{urlparse(data['url']).netloc}.docx"
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/proxy-image', methods=['GET'])
def proxy_image():
    """Proxy endpoint to bypass CORS restrictions for images"""
    try:
        image_url = request.args.get('url', '').strip()
        
        if not image_url:
            print("❌ No image URL provided")
            return send_file(
                io.BytesIO(b''),
                mimetype='image/png'
            ), 200  # Return empty PNG instead of error
        
        # Validate URL is http/https
        if not image_url.startswith(('http://', 'https://')):
            print(f"❌ Invalid URL scheme: {image_url}")
            return send_file(
                io.BytesIO(b''),
                mimetype='image/png'
            ), 200
        
        print(f"🔄 Fetching image: {image_url[:80]}...")
        
        # Prepare headers to look like a browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Accept': 'image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Sec-Fetch-Dest': 'image',
            'Sec-Fetch-Mode': 'no-cors',
            'Sec-Fetch-Site': 'cross-site',
            'DNT': '1',
            'Referer': 'https://www.google.com/',
            'Cache-Control': 'no-cache',
        }
        
        # Fetch the image with proper settings
        response = requests.get(
            image_url, 
            timeout=20,  # Increased timeout
            verify=False,
            allow_redirects=True,
            headers=headers,
            stream=True
        )
        
        # Log status
        print(f"📊 Status: {response.status_code}")
        
        # Even if status is not 200, try to return the content
        if response.status_code not in (200, 201, 202, 203, 204, 206):
            print(f"⚠️ Unexpected status {response.status_code}, attempting to return content anyway")
        
        # Get content type - be very lenient
        content_type = response.headers.get('Content-Type', '').lower()
        
        # If content-type is missing or not image, infer from URL
        if not content_type or 'image' not in content_type:
            if image_url.lower().endswith('.png'):
                content_type = 'image/png'
            elif image_url.lower().endswith(('.jpg', '.jpeg')):
                content_type = 'image/jpeg'
            elif image_url.lower().endswith('.gif'):
                content_type = 'image/gif'
            elif image_url.lower().endswith('.webp'):
                content_type = 'image/webp'
            elif image_url.lower().endswith('.svg'):
                content_type = 'image/svg+xml'
            else:
                # Default to jpeg if we can't determine
                content_type = 'image/jpeg'
        
        # Ensure proper mime type
        if 'image' not in content_type:
            content_type = 'image/jpeg'
        
        # Read image content
        image_data = response.content
        
        # Check if we got actual image data
        if len(image_data) < 100:
            print(f"⚠️ Very small response ({len(image_data)} bytes) - might not be an image")
        else:
            print(f"✅ Image fetched successfully ({len(image_data)} bytes)")
        
        # Return the image with cache headers
        response_obj = send_file(
            io.BytesIO(image_data),
            mimetype=content_type,
            as_attachment=False,
            max_age=86400  # Cache for 24 hours
        )
        
        # Add CORS headers
        response_obj.headers['Access-Control-Allow-Origin'] = '*'
        response_obj.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        response_obj.headers['Cache-Control'] = 'public, max-age=86400'
        
        return response_obj
    
    except requests.exceptions.Timeout:
        print(f"❌ Timeout loading image: {image_url}")
        return send_file(
            io.BytesIO(b''),
            mimetype='image/png'
        ), 200
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Connection error: {str(e)}")
        return send_file(
            io.BytesIO(b''),
            mimetype='image/png'
        ), 200
    except requests.exceptions.RequestException as e:
        print(f"❌ Request error: {str(e)}")
        return send_file(
            io.BytesIO(b''),
            mimetype='image/png'
        ), 200
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return send_file(
            io.BytesIO(b''),
            mimetype='image/png'
        ), 200


@app.route('/api/clear/<session_id>', methods=['DELETE'])
def clear_session(session_id):
    """Clear stored session data"""
    if session_id in scraped_data_store:
        del scraped_data_store[session_id]
    return jsonify({'success': True})


# ── Admin Panel ────────────────────────────────────────────────────────────────

ADMIN_HTML = '''<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>VulnScan Admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
.topbar{background:#1e293b;padding:14px 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #334155}
.topbar h1{font-size:18px;color:#38bdf8}
.logout{color:#94a3b8;text-decoration:none;font-size:13px}
.logout:hover{color:#f87171}
.container{padding:24px;max-width:1200px;margin:0 auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:28px}
.card{background:#1e293b;border-radius:10px;padding:18px;border:1px solid #334155}
.card .label{font-size:12px;color:#64748b;margin-bottom:6px}
.card .value{font-size:28px;font-weight:700;color:#38bdf8}
.card .sub{font-size:12px;color:#94a3b8;margin-top:4px}
.section{background:#1e293b;border-radius:10px;border:1px solid #334155;margin-bottom:24px;overflow:hidden}
.section-title{padding:14px 18px;font-size:14px;font-weight:600;border-bottom:1px solid #334155;color:#94a3b8;display:flex;justify-content:space-between}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#0f172a;padding:10px 14px;text-align:left;color:#64748b;font-weight:500}
td{padding:10px 14px;border-top:1px solid #1e293b}
tr:hover td{background:#1e3a5f22}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge.high{background:#7f1d1d;color:#fca5a5}
.badge.med{background:#78350f;color:#fcd34d}
.badge.low{background:#14532d;color:#86efac}
.badge.csv{background:#1e3a5f;color:#7dd3fc}
.badge.doc{background:#312e81;color:#a5b4fc}

/* Login */
.login-wrap{display:flex;align-items:center;justify-content:center;height:100vh}
.login-box{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:36px;width:320px}
.login-box h2{color:#38bdf8;margin-bottom:24px;text-align:center}
input[type=password]{width:100%;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:10px 14px;color:#e2e8f0;font-size:14px;margin-bottom:14px}
input[type=password]:focus{outline:none;border-color:#38bdf8}
.btn{width:100%;background:#0ea5e9;color:#fff;border:none;border-radius:6px;padding:10px;font-size:14px;font-weight:600;cursor:pointer}
.btn:hover{background:#0284c7}
.err{color:#f87171;font-size:13px;margin-top:10px;text-align:center}
</style>
</head>
<body>
<div id="app"></div>
<script>
const S=document.getElementById('app');
const path=location.pathname;

async function api(url,opts={}){
  const r=await fetch(url,{credentials:'include',...opts});
  return r.json();
}

function renderLogin(){
  S.innerHTML=`<div class="login-wrap"><div class="login-box">
    <h2>🔍 VulnScan Admin</h2>
    <input type="password" id="pw" placeholder="Password" onkeydown="if(event.key==='Enter')login()">
    <button class="btn" onclick="login()">Login</button>
    <div class="err" id="err"></div>
  </div></div>`;
}

async function login(){
  const pw=document.getElementById('pw').value;
  const r=await api('/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  if(r.ok) renderDashboard();
  else document.getElementById('err').textContent='Wrong password';
}

async function renderDashboard(){
  const [stats,scans,exports]=await Promise.all([
    api('/admin/api/stats'),
    api('/admin/api/scans'),
    api('/admin/api/exports')
  ]);

  const riskColor=s=>s>=70?'high':s>=40?'med':'low';

  S.innerHTML=`
  <div class="topbar"><h1>🔍 VulnScan Admin</h1><a class="logout" href="/admin/logout">Logout</a></div>
  <div class="container">
    <div class="cards">
      <div class="card"><div class="label">Total Scans</div><div class="value">${stats.total_scans}</div></div>
      <div class="card"><div class="label">Today</div><div class="value">${stats.today_scans}</div><div class="sub">scans</div></div>
      <div class="card"><div class="label">This Month</div><div class="value">${stats.month_scans}</div><div class="sub">scans</div></div>
      <div class="card"><div class="label">Avg Risk Score</div><div class="value">${stats.avg_risk}</div><div class="sub">/ 100</div></div>
      <div class="card"><div class="label">Avg SEO Score</div><div class="value">${stats.avg_seo}</div><div class="sub">/ 100</div></div>
      <div class="card"><div class="label">Total Exports</div><div class="value">${stats.total_exports}</div></div>
    </div>

    <div class="section">
      <div class="section-title"><span>Scan History</span><span>${scans.length} records</span></div>
      <table>
        <tr><th>URL</th><th>Date</th><th>Risk</th><th>SEO</th><th>Vulns</th><th>Critical</th><th>High</th></tr>
        ${scans.map(s=>`<tr>
          <td>${s.url}</td>
          <td>${s.timestamp}</td>
          <td><span class="badge ${riskColor(s.risk_score)}">${s.risk_score}</span></td>
          <td>${s.seo_score}</td>
          <td>${s.vuln_total}</td>
          <td>${s.vuln_critical}</td>
          <td>${s.vuln_high}</td>
        </tr>`).join('')}
      </table>
    </div>

    <div class="section">
      <div class="section-title"><span>Export History</span><span>${exports.length} records</span></div>
      <table>
        <tr><th>URL</th><th>Date</th><th>Type</th></tr>
        ${exports.map(e=>`<tr>
          <td>${e.url}</td>
          <td>${e.timestamp}</td>
          <td><span class="badge ${e.export_type}">${e.export_type.toUpperCase()}</span></td>
        </tr>`).join('')}
      </table>
    </div>
  </div>`;
}

async function init(){
  const r=await api('/admin/api/check');
  if(r.ok) renderDashboard();
  else renderLogin();
}
init();
</script>
</body>
</html>'''


@app.route('/admin')
@app.route('/admin/')
@admin_required
def admin_index():
    return ADMIN_HTML


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return ADMIN_HTML
    data = request.get_json()
    if data and data.get('password') == ADMIN_PASSWORD:
        session['admin'] = True
        return jsonify({'ok': True})
    return jsonify({'ok': False}), 401


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect('/admin/login')


@app.route('/admin/api/check')
def admin_check():
    return jsonify({'ok': bool(session.get('admin'))})


@app.route('/admin/api/stats')
@admin_required
def admin_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    month = datetime.now(timezone.utc).strftime('%Y-%m')
    stats = {
        'total_scans':   c.execute('SELECT COUNT(*) FROM scan_history').fetchone()[0],
        'today_scans':   c.execute("SELECT COUNT(*) FROM scan_history WHERE timestamp LIKE ?", (today+'%',)).fetchone()[0],
        'month_scans':   c.execute("SELECT COUNT(*) FROM scan_history WHERE timestamp LIKE ?", (month+'%',)).fetchone()[0],
        'avg_risk':      round(c.execute('SELECT AVG(risk_score) FROM scan_history').fetchone()[0] or 0),
        'avg_seo':       round(c.execute('SELECT AVG(seo_score) FROM scan_history').fetchone()[0] or 0),
        'total_exports': c.execute('SELECT COUNT(*) FROM export_history').fetchone()[0],
    }
    conn.close()
    return jsonify(stats)


@app.route('/admin/api/scans')
@admin_required
def admin_scans():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute('SELECT url,timestamp,risk_score,seo_score,vuln_total,vuln_critical,vuln_high,vuln_medium,vuln_low FROM scan_history ORDER BY id DESC LIMIT 100').fetchall()
    conn.close()
    keys = ['url','timestamp','risk_score','seo_score','vuln_total','vuln_critical','vuln_high','vuln_medium','vuln_low']
    return jsonify([dict(zip(keys, r)) for r in rows])


@app.route('/admin/api/exports')
@admin_required
def admin_exports():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute('SELECT url,timestamp,export_type FROM export_history ORDER BY id DESC LIMIT 100').fetchall()
    conn.close()
    return jsonify([{'url': r[0], 'timestamp': r[1], 'export_type': r[2]} for r in rows])


@app.route('/admin/api/blocks')
@admin_required
def admin_blocks():
    now = int(datetime.now(timezone.utc).timestamp())
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        'SELECT ip, reason, rule, blocked_at, unblock_at FROM blocks ORDER BY blocked_at DESC'
    ).fetchall()
    conn.close()
    result = []
    for ip, reason, rule, blocked_at, unblock_at in rows:
        active = now < unblock_at
        remaining = max(0, unblock_at - now)
        result.append({
            'ip': ip, 'reason': reason, 'rule': rule,
            'blocked_at': datetime.fromtimestamp(blocked_at, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            'unblock_at': datetime.fromtimestamp(unblock_at, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            'active': active,
            'remaining_seconds': remaining,
        })
    return jsonify(result)


@app.route('/admin/api/blocks/unblock', methods=['POST'])
@admin_required
def admin_unblock():
    ip = request.get_json().get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'IP required'}), 400
    conn = sqlite3.connect(DB_PATH)
    conn.execute('DELETE FROM blocks WHERE ip=?', (ip,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'{ip} unblocked'})


@app.route('/admin/api/rate-stats')
@admin_required
def admin_rate_stats():
    now = int(datetime.now(timezone.utc).timestamp())
    conn = sqlite3.connect(DB_PATH)
    total_blocks = conn.execute('SELECT COUNT(*) FROM blocks').fetchone()[0]
    active_blocks = conn.execute('SELECT COUNT(*) FROM blocks WHERE unblock_at > ?', (now,)).fetchone()[0]
    scans_last_hour = conn.execute(
        'SELECT COUNT(*) FROM rate_events WHERE ts >= ?', (now - 3600,)
    ).fetchone()[0]
    top_ips = conn.execute(
        'SELECT ip, COUNT(*) as c FROM rate_events WHERE ts >= ? GROUP BY ip ORDER BY c DESC LIMIT 10',
        (now - 3600,)
    ).fetchall()
    conn.close()
    return jsonify({
        'total_blocks_ever': total_blocks,
        'active_blocks': active_blocks,
        'scans_last_hour': scans_last_hour,
        'top_ips_last_hour': [{'ip': r[0], 'scans': r[1]} for r in top_ips],
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)