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
    conn.commit()
    conn.close()

init_db()

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

    for file_info in sensitive_files:
        file_path = file_info['path']
        try:
            test_url = urljoin(base_url, file_path)
            response = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
            if response.status_code == 200:
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

    # SEO score
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


def scrape_website(url):
    """Scrape all data from a website"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=30, verify=False)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'html.parser')

        # Perform vulnerability scan and SEO analysis on unmodified soup
        vulnerability_scan = scan_vulnerabilities(url, response, soup)
        seo_data = analyze_seo(url, soup)

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
            'seo': seo_data
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

        # Scrape the website
        scraped_data = scrape_website(url)

        # Store with unique ID
        session_id = str(uuid.uuid4())
        scraped_data_store[session_id] = scraped_data
        log_scan(scraped_data)

        return jsonify({
            'success': True,
            'session_id': session_id,
            'data': scraped_data
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
        'overview', 'vulnerabilities', 'seo', 'headings', 'paragraphs',
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
        'overview', 'vulnerabilities', 'seo', 'headings', 'paragraphs',
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


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)