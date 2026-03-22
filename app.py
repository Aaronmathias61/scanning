import os 
import socket
import ssl
import requests
import threading
from queue import Queue
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import A4
import whois
from datetime import datetime
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS 
import psycopg2
import json
from reportlab.platypus import Table, TableStyle
from reportlab.lib import colors
from flask import session, redirect, url_for

app = Flask(__name__)
CORS(app)
# CONFIGURATION

REPORT_FILE = "Vulnerability_Report.pdf"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

COMMON_DIRECTORIES = [
    "admin", "login", "dashboard", "uploads", "backup",
    "config", "test", "dev", "old", ".git", ".env",
    "phpmyadmin", "wp-admin", "wp-content", "api"
]

# ADVANCED AD + YOUTUBE DETECTION

KNOWN_AD_DOMAINS = [
    # Google Ads
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "adservice.google.com",
    "pagead2.googlesyndication.com",
    # YouTube / Google Video Ads
    "youtube.com",
    "youtu.be",
    "googlevideo.com",
    "ytimg.com",
    # Other Ad Networks
    "taboola.com",
    "outbrain.com",
    "amazon-adsystem.com",
    "adroll.com",
    "ads.yahoo.com",
    "facebook.com/tr",
    "ads-twitter.com"
]

DB_CONFIG = {
    "host": "localhost",
    "database": "postgres",   # ✅ change this
    "user": "postgres",
    "password": "root",
    "port": "5432"
}


app.secret_key = "MALWARE"

# Resolve Target


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except:
        return None

# FAST PORT SCAN (1–1024)

def port_scan(ip):
    open_ports = []
    queue = Queue()
    lock = threading.Lock()
    def scan():
        while not queue.empty():
            port = queue.get()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                if s.connect_ex((ip, port)) == 0:
                    with lock:
                        open_ports.append(port)
                s.close()
            except:
                pass
            queue.task_done()
    for port in range(1, 1025):
        queue.put(port)
    for _ in range(200):
        t = threading.Thread(target=scan)
        t.daemon = True
        t.start()
    queue.join()
    return sorted(open_ports)

# Website Alive Check

def check_website_alive(domain):
    try:
        r = requests.get("http://" + domain, timeout=5)
        return f"Alive (Status Code: {r.status_code})"
    except:
        return "Down / Not Reachable"

# Domain Creation Date

def get_domain_creation_date(domain):
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            return str(creation.date())
        return "Not Available"
    except:
        return "WHOIS Lookup Failed"

# SSL Certificate Check

def ssl_check(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert.get("notAfter", "Not Available")
    except:
        return "SSL Not Available"

# OS Detection (Basic)

def detect_os(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, 80))
        ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        s.close()
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        else:
            return "Network Device"
    except:
        return "Unknown"

# Security Header Check

def header_scan(domain):
    missing = []
    try:
        r = requests.get("http://" + domain, timeout=5)
        for header in SECURITY_HEADERS:
            if header not in r.headers:
                missing.append(header)
    except:
        missing.append("Header scan failed")
    return missing

# Hidden Directory Scan

def hidden_directory_scan(domain):
    found = []
    base = "http://" + domain

    for directory in COMMON_DIRECTORIES:
        url = f"{base}/{directory}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code in [200, 301, 302, 403]:
                found.append(f"{url} (Status: {r.status_code})")
        except:
            pass

    return found

# Service Detection

def detect_services(open_ports):
    services = []
    for port in open_ports:
        if port in [80, 443]:
            services.append("web server")
        elif port == 21:
            services.append("ftp")
        elif port == 22:
            services.append("ssh")
        elif port == 3306:
            services.append("mysql")
    return list(set(services))

# CVE Lookup

def cve_lookup(service):
    cves = []
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}&resultsPerPage=2"
        r = requests.get(url, timeout=5)
        data = r.json()

        for item in data.get("vulnerabilities", []):
            cves.append(item["cve"]["id"])
    except:
        cves.append("CVE lookup failed")

    if not cves:
        cves.append("No CVEs Found")

    return cves

# Cookie Security Scan

def cookie_scan(domain):
    cookie_issues = []
    try:
        r = requests.get("http://" + domain, timeout=5)
        cookies = r.cookies
        if not cookies:
            return ["No cookies set"]
        for cookie in cookies:
            issues = []
            if not cookie.secure:
                issues.append("Not Secure")
            # HttpOnly is not directly accessible via requests cookies
            # So we check raw headers instead
            raw_headers = r.headers.get("Set-Cookie", "")
            if "httponly" not in raw_headers.lower():
                issues.append("HttpOnly not set")
            if "samesite" not in raw_headers.lower():
                issues.append("SameSite not set")
            if issues:
                cookie_issues.append(f"{cookie.name}: {', '.join(issues)}")
        if not cookie_issues:
            cookie_issues.append("All cookies appear secure")
    except:
        cookie_issues.append("Cookie scan failed")
    return cookie_issues


# ADVANCED AD + YOUTUBE DETECTION

def detect_ads(domain):
    findings = []
    try:
        url = "http://" + domain
        r = requests.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        # 1️⃣ Detect iframes (common for ads + YouTube embeds)
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "")
            if src:
                for ad_domain in KNOWN_AD_DOMAINS:
                    if ad_domain in src:
                        findings.append(f"Iframe detected ({ad_domain}): {src}")
        # 2️⃣ Detect script sources (ad loaders)
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                for ad_domain in KNOWN_AD_DOMAINS:
                    if ad_domain in src:
                        findings.append(f"Ad script detected ({ad_domain}): {src}")
        # 3️⃣ Detect YouTube embed explicitly
        for iframe in soup.find_all("iframe"):
            src = iframe.get("src", "")
            if "youtube.com/embed" in src:
                findings.append(f"YouTube video embed detected: {src}")
        # 4️⃣ Detect video tags
        for video in soup.find_all("video"):
            findings.append("HTML5 <video> tag detected")
        # 5️⃣ Detect tracking pixels
        for img in soup.find_all("img"):
            src = img.get("src", "")
            if any(ad_domain in src for ad_domain in KNOWN_AD_DOMAINS):
                findings.append(f"Tracking pixel detected: {src}")
        # 6️⃣ Detect ad-related container names
        for tag in soup.find_all(True):
            classes = " ".join(tag.get("class", []))
            tag_id = tag.get("id", "")
            combined = (classes + " " + tag_id).lower()
            if any(keyword in combined for keyword in ["ad", "ads", "banner", "sponsor", "promo"]):
                findings.append(f"Possible ad container: {combined}")
    except Exception as e:
        findings.append("Ad detection failed")
    if not findings:
        findings.append("No ad networks detected (static scan)")
    return list(set(findings))

# PDF REPORT (FIXED SECTION)

def save_scan(data):
    conn = get_db_connection()
    cur = conn.cursor()

    query = """
    INSERT INTO scan_history (
        target, ip, website_status, detected_os, ssl_expiry,
        domain_creation, open_ports, missing_headers,
        hidden_dirs, cookie_issues, ad_results, cves
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    cur.execute(query, (
        data["target"],
        data["ip"],
        data["website_status"],
        data["detected_os"],
        data["ssl_expiry"],
        data["domain_creation"],
        json.dumps(data["open_ports"]),
        json.dumps(data["missing_headers"]),
        json.dumps(data["hidden_dirs"]),
        json.dumps(data["cookie_issues"]),
        json.dumps(data["ad_results"]),
        json.dumps(data["cves"])
    ))

    conn.commit()
    cur.close()
    conn.close()


def generate_pdf(target, ip, open_ports, missing_headers,
                 ssl_expiry, cves, detected_os,
                 website_status, creation_date,
                 hidden_dirs, cookie_issues, ad_results):

    doc = SimpleDocTemplate(REPORT_FILE, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    # Title Section
    title_table = Table(
        [[Paragraph("<font size=18><b>Advanced Website Vulnerability Report</b></font>", styles["Normal"])]],
        colWidths=[450])

    title_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('PADTOP', (0, 0), (-1, -1), 12),
        ('PADBOTTOM', (0, 0), (-1, -1), 12),
    ]))

    elements.append(title_table)
    elements.append(Spacer(1, 0.5 * inch))

    # Target Info Box
    info_data = [["Target:", target], ["IP Address:", ip]]

    info_table = Table(info_data, colWidths=[120, 330])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(info_table)
    elements.append(Spacer(1, 0.4 * inch))

    # SUMMARY (2 Columns)
    summary_data = [
        ["Website Status", website_status],
        ["Domain Creation", creation_date],
        ["Detected OS", detected_os],
        ["SSL Expiry", ssl_expiry]
    ]

    summary_table = Table(summary_data, colWidths=[180, 270])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 0.4 * inch))

    # SPLIT SECTION 1
    # Open Ports | Missing Headers
    ports_text = "\n".join([str(p) for p in open_ports]) if open_ports else "None Found"
    headers_text = "\n".join(missing_headers) if missing_headers else "None"

    split1 = Table([
        [
            Paragraph(f"<b>Open Ports</b><br/>{ports_text}", styles["Normal"]),
            Paragraph(f"<b>Missing Security Headers</b><br/>{headers_text}", styles["Normal"])
        ]
    ], colWidths=[225, 225])

    split1.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), colors.beige),
        ('BACKGROUND', (1, 0), (1, 0), colors.lavender),
        ('BOX', (0, 0), (-1, -1), 1, colors.grey),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(split1)
    elements.append(Spacer(1, 0.4 * inch))

    # SPLIT SECTION 2
    # Hidden Directories | Cookies
    hidden_text = "\n".join(hidden_dirs) if hidden_dirs else "None Found"
    cookie_text = "\n".join(cookie_issues)

    split2 = Table([
        [
            Paragraph(f"<b>Hidden Directories</b><br/>{hidden_text}", styles["Normal"]),
            Paragraph(f"<b>Cookie Issues</b><br/>{cookie_text}", styles["Normal"])
        ]
    ], colWidths=[225, 225])

    split2.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), colors.honeydew),
        ('BACKGROUND', (1, 0), (1, 0), colors.mistyrose),
        ('BOX', (0, 0), (-1, -1), 1, colors.grey),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(split2)
    elements.append(Spacer(1, 0.4 * inch))

    # CVE Section (Highlighted)
    cve_text = "\n".join(cves)

    cve_table = Table(
        [[Paragraph(f"<b>Related CVEs</b><br/>{cve_text}", styles["Normal"])]],
        colWidths=[450]
    )

    cve_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.salmon),
        ('BOX', (0, 0), (-1, -1), 1, colors.red),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(cve_table)
    elements.append(Spacer(1, 0.4 * inch))

    # Advertising Section
    ad_text = "\n".join(ad_results)

    ad_table = Table(
        [[Paragraph(f"<b>Advertising & Media Detection</b><br/>{ad_text}", styles["Normal"])]],
        colWidths=[450]
    )

    ad_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
        ('BOX', (0, 0), (-1, -1), 1, colors.black),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(ad_table)

    # Build PDF
    doc.build(elements)

    print("\n🎨 Colorful PDF Report Generated Successfully:", REPORT_FILE)

REPORT_FILE = os.path.join(os.path.dirname(__file__), "Vulnerability_Report.pdf")

@app.route("/")
def home():
    if "user" not in session:
        return redirect("/login")
    return render_template("index.html")

@app.route("/run-scan", methods=["POST"])
def run_scan():
    try:
        if "user" not in session:
            return jsonify({"error": "Unauthorized"}), 401

        data = request.json
        target = data.get("target")

        if not target:
            return jsonify({"error": "No target provided"}), 400

        clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]

        ip = resolve_target(clean_target)
        if not ip:
            return jsonify({"error": "Invalid domain"}), 400

        # SCAN
        open_ports = port_scan(ip)
        website_status = check_website_alive(clean_target)
        creation_date = get_domain_creation_date(clean_target)
        ssl_expiry = ssl_check(clean_target)
        detected_os = detect_os(ip)
        missing_headers = header_scan(clean_target)
        hidden_dirs = hidden_directory_scan(clean_target)
        cookie_issues = cookie_scan(clean_target)
        ad_results = detect_ads(clean_target)

        services = detect_services(open_ports)
        all_cves = []
        for service in services:
            all_cves.extend(cve_lookup(service))

        response_data = {
            "target": clean_target,
            "ip": ip,
            "open_ports": open_ports,
            "missing_headers": missing_headers,
            "ssl_expiry": ssl_expiry,
            "detected_os": detected_os,
            "website_status": website_status,
            "domain_creation": creation_date,
            "hidden_dirs": hidden_dirs,
            "cookie_issues": cookie_issues,
            "ad_results": ad_results,
            "cves": all_cves
        }

        # SAVE + PDF
        save_scan(response_data)
        generate_pdf(
            target=clean_target,
            ip=ip,
            open_ports=open_ports,
            missing_headers=missing_headers,
            ssl_expiry=ssl_expiry,
            cves=all_cves,
            detected_os=detected_os,
            website_status=website_status,
            creation_date=creation_date,
            hidden_dirs=hidden_dirs,
            cookie_issues=cookie_issues,
            ad_results=ad_results
        )

        return jsonify(response_data)

    except Exception as e:
        print("🔥 ERROR:", e)
        return jsonify({"error": str(e)}), 500

@app.route("/download-report")
def download_report():
    try:
        if not os.path.exists(REPORT_FILE):
            # PDF doesn't exist → create a blank placeholder
            from reportlab.platypus import SimpleDocTemplate, Paragraph
            from reportlab.lib.styles import getSampleStyleSheet
            doc = SimpleDocTemplate(REPORT_FILE)
            styles = getSampleStyleSheet()
            elements = [Paragraph("This is a placeholder PDF. Run a scan to get real results.", styles["Normal"])]
            doc.build(elements)

        return send_file(REPORT_FILE, as_attachment=True)
    except Exception as e:
        print("ERROR sending PDF:", e)
        return f"Internal server error: {e}", 500


@app.route("/history-page")
def history_page():
    if "user" not in session:
        return redirect("/login")
    return render_template("history.html")

@app.route("/history", methods=["GET"])
def get_history():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM scan_history WHERE username = %s ORDER BY created_at DESC",
        (session["user"],)
    )

    rows = cur.fetchall()

    result = []
    for row in rows:
        result.append({
            "id": row[0],
            "username": row[1],   # shifted index
            "target": row[2],
            "ip": row[3],
            "website_status": row[4],
            "detected_os": row[5],
            "ssl_expiry": row[6],
            "domain_creation": row[7],
            "open_ports": row[8],
            "missing_headers": row[9],
            "hidden_dirs": row[10],
            "cookie_issues": row[11],
            "ad_results": row[12],
            "cves": row[13],
            "created_at": row[14]
        })

    cur.close()
    conn.close()

    return jsonify(result)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                "SELECT * FROM users WHERE username = %s AND password = %s",
                (username, password)
            )
            user = cur.fetchone()

            if user:
                session["user"] = username
                return redirect("/")
            else:
                return render_template("login.html", error="Invalid credentials")

        except Exception as e:
            print("LOGIN ERROR:", e)
            return render_template("login.html", error="Something went wrong")

        finally:
            cur.close()
            conn.close()

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, password)
        )
        conn.commit()
        return jsonify({"success": True, "message": "User registered successfully"})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "message": "User already exists"})
    finally:
        cur.close()
        conn.close()
        

if __name__ == "__main__":
    app.run(debug=True)