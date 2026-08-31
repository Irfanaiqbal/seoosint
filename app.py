#!/usr/bin/env python3
import subprocess, threading, queue, time, re, socket, ssl, datetime, os, hashlib, hmac
from flask import Flask, request, Response, render_template, jsonify, redirect, url_for, session
import requests
import whois
from collections import deque
import uuid
import json
import sqlite3

app = Flask(__name__)
app.secret_key = os.environ.get('ADMIN_SECRET_KEY', 'change-this-secret-key-in-production-please')

# ============================================================
#  DATABASE — request logging (completely hidden from public)
# ============================================================
DB_PATH = os.environ.get('LOG_DB', 'shadowtrace_logs.db')

def db_init():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS scans (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts        TEXT    NOT NULL,
        ip        TEXT    NOT NULL,
        mode      TEXT    NOT NULL,
        target    TEXT    NOT NULL,
        ua        TEXT,
        country   TEXT,
        result_ct INTEGER DEFAULT 0
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS rate_blocks (
        id  INTEGER PRIMARY KEY AUTOINCREMENT,
        ts  TEXT NOT NULL,
        ip  TEXT NOT NULL,
        msg TEXT
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS notices (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        heading    TEXT    NOT NULL,
        content    TEXT    NOT NULL,
        link_url   TEXT,
        color_key  TEXT    DEFAULT 'cyan',
        active     INTEGER DEFAULT 1,
        created_at TEXT    NOT NULL
    )''')
    con.commit()
    con.close()

# ============================================================
#  NOTICE BOARD — admin-controlled banners on public page
# ============================================================
NOTICE_COLORS = {
    'cyan':   {'label': 'Cyan',   'hex': '#00e5ff', 'bg': 'rgba(0,229,255,.10)',  'glow': 'rgba(0,229,255,.25)'},
    'purple': {'label': 'Purple', 'hex': '#9b5de5', 'bg': 'rgba(155,93,229,.10)', 'glow': 'rgba(155,93,229,.25)'},
    'green':  {'label': 'Green',  'hex': '#00f5a0', 'bg': 'rgba(0,245,160,.10)',  'glow': 'rgba(0,245,160,.22)'},
    'pink':   {'label': 'Pink',   'hex': '#ff4d8f', 'bg': 'rgba(255,77,143,.10)', 'glow': 'rgba(255,77,143,.24)'},
    'yellow': {'label': 'Yellow', 'hex': '#ffd166', 'bg': 'rgba(255,209,102,.10)','glow': 'rgba(255,209,102,.22)'},
    'orange': {'label': 'Orange', 'hex': '#ff9a3c', 'bg': 'rgba(255,154,60,.10)', 'glow': 'rgba(255,154,60,.22)'},
    'blue':   {'label': 'Blue',   'hex': '#4488ff', 'bg': 'rgba(68,136,255,.10)', 'glow': 'rgba(68,136,255,.24)'},
    'red':    {'label': 'Red',    'hex': '#ff4455', 'bg': 'rgba(255,68,85,.10)',  'glow': 'rgba(255,68,85,.24)'},
}

def _notice_color(key):
    return NOTICE_COLORS.get(key, NOTICE_COLORS['cyan'])

def get_active_notices():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        'SELECT id,heading,content,link_url,color_key FROM notices WHERE active=1 ORDER BY id DESC'
    ).fetchall()
    con.close()
    out = []
    for r in rows:
        c = _notice_color(r[4])
        out.append({'id': r[0], 'heading': r[1], 'content': r[2], 'link_url': r[3],
                    'hex': c['hex'], 'bg': c['bg'], 'glow': c['glow']})
    return out

def get_all_notices():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        'SELECT id,heading,content,link_url,color_key,active,created_at FROM notices ORDER BY id DESC'
    ).fetchall()
    con.close()
    out = []
    for r in rows:
        c = _notice_color(r[4])
        out.append({'id': r[0], 'heading': r[1], 'content': r[2], 'link_url': r[3] or '',
                    'color_key': r[4], 'hex': c['hex'], 'active': r[5], 'created_at': r[6]})
    return out

def db_log_scan(ip, mode, target, ua, result_ct=0):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute(
            'INSERT INTO scans (ts,ip,mode,target,ua,result_ct) VALUES (?,?,?,?,?,?)',
            (datetime.datetime.utcnow().isoformat(), ip, mode, target, ua, result_ct)
        )
        con.commit()
        con.close()
    except Exception:
        pass

def db_log_block(ip, msg):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute('INSERT INTO rate_blocks (ts,ip,msg) VALUES (?,?,?)',
                    (datetime.datetime.utcnow().isoformat(), ip, msg))
        con.commit()
        con.close()
    except Exception:
        pass

db_init()

# ============================================================
#  ADMIN CREDENTIALS — change these or use env vars
# ============================================================
ADMIN_USERNAME = os.environ.get('ADMIN_USER', 'haleema5')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASS', 'haleema@321')
# Hidden admin panel URL segment — not linked anywhere on the site
ADMIN_PREFIX    = os.environ.get('ADMIN_PREFIX', 'x7k9m-panel')

# ============================================================
#  RATE LIMITING
# ============================================================
MAX_CONCURRENT_REQUESTS = 8   # matches gunicorn thread count — keep in sync w/ gunicorn.conf.py
MAX_REQUESTS_PER_IP     = 10
IP_REQUEST_WINDOW       = 60
active_requests = 0
request_queue   = deque()
request_lock    = threading.Lock()
ip_request_log  = {}
ip_lock         = threading.Lock()

def get_real_ip():
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'

def check_ip_rate_limit(ip):
    now = time.time()
    with ip_lock:
        timestamps = ip_request_log.get(ip, [])
        timestamps = [t for t in timestamps if now - t < IP_REQUEST_WINDOW]
        if len(timestamps) >= MAX_REQUESTS_PER_IP:
            return False
        timestamps.append(now)
        ip_request_log[ip] = timestamps
    return True

# ============================================================
#  INPUT VALIDATION
# ============================================================
def validate_target(mode, target):
    target = target.strip()
    if not target or len(target) > 256:
        return False, 'Invalid target length'
    if mode == 'email':
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target):
            return False, 'Invalid email format'
    elif mode == 'domain':
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
            return False, 'Invalid domain format'
    elif mode == 'phone':
        if not re.match(r'^\+?[\d\s\-\(\)]{7,20}$', target):
            return False, 'Invalid phone format'
    elif mode == 'username':
        if not re.match(r'^[a-zA-Z0-9._\-]{1,50}$', target):
            return False, 'Invalid username (alphanumeric, dots, dashes only)'
    return True, target

# ============================================================
#  USERNAME PLATFORMS
# ============================================================
USERNAME_PLATFORMS = {
    "GitHub":         "https://github.com/{u}",
    "GitLab":         "https://gitlab.com/{u}",
    "Bitbucket":      "https://bitbucket.org/{u}",
    "SourceForge":    "https://sourceforge.net/u/{u}",
    "Gitea":          "https://gitea.com/{u}",
    "CodePen":        "https://codepen.io/{u}",
    "Replit":         "https://replit.com/@{u}",
    "Kaggle":         "https://www.kaggle.com/{u}",
    "HackerRank":     "https://www.hackerrank.com/{u}",
    "LeetCode":       "https://leetcode.com/{u}",
    "Twitter / X":    "https://twitter.com/{u}",
    "Instagram":      "https://www.instagram.com/{u}/",
    "Facebook":       "https://www.facebook.com/{u}",
    "Reddit":         "https://www.reddit.com/user/{u}/",
    "TikTok":         "https://www.tiktok.com/@{u}",
    "Threads":        "https://www.threads.net/@{u}",
    "Pinterest":      "https://www.pinterest.com/{u}/",
    "Tumblr":         "https://{u}.tumblr.com",
    "Snapchat":       "https://www.snapchat.com/add/{u}",
    "Telegram":       "https://t.me/{u}",
    "Discord":        "https://discord.com/users/{u}",
    "Matrix":         "https://matrix.to/#/@{u}:matrix.org",
    "YouTube":        "https://www.youtube.com/@{u}",
    "Twitch":         "https://www.twitch.tv/{u}",
    "Vimeo":          "https://vimeo.com/{u}",
    "SoundCloud":     "https://soundcloud.com/{u}",
    "Mixcloud":       "https://www.mixcloud.com/{u}",
    "Bandcamp":       "https://bandcamp.com/{u}",
    "DeviantArt":     "https://www.deviantart.com/{u}",
    "Behance":        "https://www.behance.net/{u}",
    "Dribbble":       "https://dribbble.com/{u}",
    "Medium":         "https://medium.com/@{u}",
    "Substack":       "https://{u}.substack.com",
    "Stack Overflow": "https://stackoverflow.com/users/{u}",
    "Quora":          "https://www.quora.com/profile/{u}",
    "Steam":          "https://steamcommunity.com/id/{u}",
    "Epic Games":     "https://www.epicgames.com/id/{u}",
    "Roblox":         "https://www.roblox.com/user.aspx?username={u}",
    "Fiverr":         "https://www.fiverr.com/{u}",
    "Upwork":         "https://www.upwork.com/freelancers/{u}",
    "LinkedIn":       "https://www.linkedin.com/in/{u}",
    "Pastebin":       "https://pastebin.com/u/{u}",
    "Keybase":        "https://keybase.io/{u}",
    "About.me":       "https://about.me/{u}",
    "ProductHunt":    "https://www.producthunt.com/@{u}",
}

jobs = {}

# ============================================================
#  HELPERS
# ============================================================
def make_card(title, body, body_plain=None, icon='fa-info-circle', tag='', url=''):
    return json.dumps({
        'title': title,
        'body': body,
        'body_plain': body_plain or body,
        'icon': icon,
        'tag': tag,
        'url': url
    })

# ============================================================
#  PUBLIC FRONTEND HTML
# ============================================================

# ============================================================
#  ADMIN PANEL HTML — completely unlisted / hidden
# ============================================================

# ============================================================
#  ROUTES — PUBLIC
# ============================================================
@app.after_request
def sec_headers(r):
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['X-Frame-Options'] = 'DENY'
    r.headers['X-XSS-Protection'] = '1; mode=block'
    r.headers['Referrer-Policy'] = 'no-referrer'
    return r

@app.route('/')
def index():
    return render_template('index.html', notices=get_active_notices())

# ============================================================
#  BLOG — SEO content pages
# ============================================================
BLOG_POSTS = {
    'what-is-osint': {
        'title': 'What Is OSINT? A Practical Guide to Open Source Intelligence | SHADOWTRACE',
        'description': 'Learn what OSINT (Open Source Intelligence) is, where the data comes from, and how tools like SHADOWTRACE automate passive reconnaissance.',
        'tag': 'Guide',
        'excerpt': 'What OSINT actually is, where the data comes from, and how it is used in security research and personal audits.',
    },
    'email-osint-guide': {
        'title': "Email OSINT: How to Check What's Exposed About an Email Address | SHADOWTRACE",
        'description': 'A practical guide to email OSINT — what a scan can reveal, why it matters for your security, and how to do it responsibly.',
        'tag': 'Guide',
        'excerpt': 'What an email OSINT scan can reveal, why it matters for phishing prevention, and how to check your own exposure.',
    },
    'reduce-digital-footprint': {
        'title': '7 Ways to Reduce Your Digital Footprint in 2026 | SHADOWTRACE',
        'description': 'Seven practical steps to shrink your public digital footprint, from auditing your exposure to enabling two-factor authentication.',
        'tag': 'Checklist',
        'excerpt': 'A practical checklist for shrinking your public digital footprint, starting with a free self-audit.',
    },
}

@app.route('/blogs')
def blog_index():
    posts = [{'slug': slug, **data} for slug, data in BLOG_POSTS.items()]
    return render_template('blog/index.html',
        title='SHADOWTRACE Blog — OSINT Guides & Digital Footprint Tips',
        description='Practical guides on OSINT, digital footprint hygiene, and how to use SHADOWTRACE.',
        canonical='https://shadowtrace.qzz.io/blogs',
        jsonld=None, posts=posts)

@app.route('/blogs/<slug>')
def blog_post(slug):
    post = BLOG_POSTS.get(slug)
    if not post:
        return redirect('/blogs')
    jsonld = json.dumps({
        "@context": "https://schema.org",
        "@type": "Article",
        "headline": post['title'],
        "description": post['description'],
        "url": f"https://shadowtrace.qzz.io/blogs/{slug}",
        "publisher": {"@type": "Organization", "name": "SHADOWTRACE"}
    })
    return render_template(f'blog/{slug}.html',
        title=post['title'], description=post['description'],
        canonical=f'https://shadowtrace.qzz.io/blogs/{slug}', jsonld=jsonld)

@app.route('/robots.txt')
def robots_txt():
    body = (
        "User-agent: *\n"
        "Allow: /\n"
        f"Disallow: /{ADMIN_PREFIX}\n"
        "Sitemap: https://shadowtrace.qzz.io/sitemap.xml\n"
    )
    return Response(body, mimetype='text/plain')

@app.route('/sitemap.xml')
def sitemap_xml():
    urls = ['/', '/blogs'] + [f'/blogs/{slug}' for slug in BLOG_POSTS]
    items = ''.join(
        f'<url><loc>https://shadowtrace.qzz.io{u}</loc></url>' for u in urls
    )
    xml = f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{items}</urlset>'
    return Response(xml, mimetype='application/xml')

@app.route('/start', methods=['POST'])
def start():
    global active_requests
    ip = get_real_ip()
    ua = request.headers.get('User-Agent', '')

    if not check_ip_rate_limit(ip):
        db_log_block(ip, 'Rate limit exceeded')
        return jsonify({'status': 'error', 'message': 'Rate limit exceeded — try again in a minute'})

    data   = request.get_json(force=True)
    mode_v = data.get('mode', '')
    target = data.get('target', '').strip()

    ok, result = validate_target(mode_v, target)
    if not ok:
        return jsonify({'status': 'error', 'message': result})
    target = result

    job_id = str(uuid.uuid4())
    q = queue.Queue()
    jobs[job_id] = q

    with request_lock:
        if active_requests >= MAX_CONCURRENT_REQUESTS:
            pos = len(request_queue) + 1
            request_queue.append(job_id)
            return jsonify({'status': 'queued', 'job_id': job_id, 'queue_position': pos})
        active_requests += 1

    # Capture result count for logging
    result_counter = [0]

    def runner():
        global active_requests
        try:
            if mode_v == 'email':
                EMAIL_SCAN_TIMEOUT = 100  # hard cap so we never outlive gunicorn's worker timeout
                try:
                    p = subprocess.Popen(
                        ['user-scanner', '-e', target],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                        bufsize=1
                    )
                    start_t = time.time()
                    killed_for_timeout = False
                    for line in p.stdout:
                        line = line.strip()
                        if not line:
                            continue
                        # user-scanner with --only-found only prints hits, e.g.
                        # "[✔] Huggingface (target@mail.com): Registered"
                        # still guard against any stray skipped/error lines just in case
                        low = line.lower()
                        if 'skip' in low or 'not found' in low or 'available' in low or 'error' in low:
                            pass
                        elif ']' in line:
                            svc = line.split(']', 1)[1].strip()
                            svc = svc.split('(')[0].strip()
                            if svc:
                                q.put(make_card(svc, 'Email registered on this platform',
                                               icon='fa-check-circle', tag='email'))
                                result_counter[0] += 1
                        if time.time() - start_t > EMAIL_SCAN_TIMEOUT:
                            killed_for_timeout = True
                            p.kill()
                            break
                    p.wait(timeout=5) if not killed_for_timeout else None
                    if killed_for_timeout:
                        q.put(make_card('Scan truncated',
                                       'Scan took too long on this server and was stopped early — showing partial results',
                                       icon='fa-clock', tag='email'))
                except FileNotFoundError:
                    q.put(make_card('user-scanner not installed',
                                   'Install with: pip install user-scanner',
                                   icon='fa-exclamation-triangle', tag='email'))
                except Exception:
                    pass

            elif mode_v == 'username':
                for name, url_tpl in USERNAME_PLATFORMS.items():
                    try:
                        u = url_tpl.format(u=target)
                        r = requests.get(u, timeout=5, allow_redirects=True,
                                         headers={'User-Agent': 'Mozilla/5.0'})
                        if r.status_code == 200 and len(r.content) > 500:
                            q.put(make_card(name,
                                           f'<a href="{u}" target="_blank">{u}</a>',
                                           body_plain=u,
                                           icon='fa-external-link-alt',
                                           tag='username', url=u))
                            result_counter[0] += 1
                    except Exception:
                        pass

            elif mode_v == 'domain':
                # WHOIS
                try:
                    info = whois.whois(target)
                    if info.registrar:
                        q.put(make_card('Registrar', info.registrar, icon='fa-building', tag='domain'))
                        result_counter[0] += 1
                    for field, label, icon in [
                        ('creation_date','Created','fa-calendar-plus'),
                        ('expiration_date','Expires','fa-calendar-times'),
                        ('updated_date','Updated','fa-calendar-check'),
                    ]:
                        val = getattr(info, field, None)
                        if val:
                            if isinstance(val, list): val = val[0]
                            ds = val.strftime('%Y-%m-%d') if hasattr(val,'strftime') else str(val)[:10]
                            q.put(make_card(label, ds, icon=icon, tag='domain'))
                            result_counter[0] += 1
                    if info.name_servers:
                        ns = info.name_servers
                        txt = ', '.join(str(x).lower() for x in (ns[:3] if isinstance(ns,list) else [ns]))
                        q.put(make_card('Name Servers', txt, icon='fa-server', tag='domain'))
                        result_counter[0] += 1
                    if info.status:
                        st = info.status
                        if isinstance(st, list): st = st[0]
                        q.put(make_card('WHOIS Status', str(st)[:80], icon='fa-tag', tag='domain'))
                        result_counter[0] += 1
                    if info.emails:
                        em = info.emails
                        if isinstance(em, list): em = ', '.join(em[:3])
                        q.put(make_card('Registrant Email', str(em), icon='fa-envelope', tag='domain'))
                        result_counter[0] += 1
                    if info.country:
                        q.put(make_card('Country', str(info.country), icon='fa-flag', tag='domain'))
                        result_counter[0] += 1
                except Exception as e:
                    q.put(make_card('WHOIS Error', str(e)[:80], icon='fa-exclamation-triangle'))

                # DNS
                try:
                    import dns.resolver
                    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA']:
                        try:
                            answers = dns.resolver.resolve(target, rtype, lifetime=5)
                            for rec in answers:
                                q.put(make_card(f'DNS {rtype}', str(rec),
                                               icon='fa-network-wired', tag='domain'))
                                result_counter[0] += 1
                        except Exception:
                            pass
                except ImportError:
                    pass

                # IP
                try:
                    ip_addr = socket.gethostbyname(target)
                    q.put(make_card('IP Address', ip_addr, icon='fa-map-marker-alt', tag='domain'))
                    result_counter[0] += 1
                    try:
                        rev = socket.gethostbyaddr(ip_addr)[0]
                        q.put(make_card('Reverse DNS', rev, icon='fa-exchange-alt', tag='domain'))
                        result_counter[0] += 1
                    except Exception:
                        pass
                except Exception:
                    pass

                # HTTP
                for scheme in ('https://', 'http://'):
                    try:
                        r = requests.get(scheme + target, timeout=6,
                                        headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
                        srv  = r.headers.get('Server', '—')
                        powered = r.headers.get('X-Powered-By', '')
                        cf = 'Cloudflare' if 'cloudflare' in r.headers.get('CF-RAY','').lower() or \
                                             'cloudflare' in r.headers.get('Server','').lower() else ''
                        body = f'{scheme}{target} → HTTP {r.status_code}<br>Server: {srv}'
                        if powered: body += f'<br>Powered-By: {powered}'
                        if cf:      body += f'<br><span style="color:var(--o)">⚡ {cf}</span>'
                        q.put(make_card('Web Server', body,
                                       body_plain=f'{scheme}{target} HTTP {r.status_code} {srv}',
                                       icon='fa-globe', tag='domain'))
                        result_counter[0] += 1
                        break
                    except Exception:
                        pass

                # TLS
                try:
                    ctx = ssl.create_default_context()
                    with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
                        s.settimeout(6)
                        s.connect((target, 443))
                        cert = s.getpeercert()
                    cn = next((item[0][1] for sub in cert.get('subject',[]) for item in sub if item[0][0]=='commonName'), None)
                    issuer = next((item[0][1] for sub in cert.get('issuer',[]) for item in sub if item[0][0]=='organizationName'), None)
                    not_after = cert.get('notAfter','')
                    exp = None
                    for fmt in ('%b %d %H:%M:%S %Y %Z','%b %d %H:%M %Y %Z','%Y%m%d%H%M%SZ'):
                        try: exp = datetime.datetime.strptime(not_after, fmt); break
                        except: pass
                    days = (exp - datetime.datetime.now()).days if exp else None
                    col = 'var(--g)' if days and days>30 else ('var(--y)' if days and days>7 else 'var(--pk)')
                    parts = []
                    if cn:     parts.append(f'CN: {cn}')
                    if issuer: parts.append(f'Issuer: {issuer}')
                    if exp:    parts.append(f'Expires: {exp.strftime("%Y-%m-%d")}')
                    if days is not None: parts.append(f'<span style="color:{col}">{days} days remaining</span>')
                    sans = [v for t,v in cert.get('subjectAltName',[]) if t=='DNS']
                    if sans: parts.append(f'SANs: {", ".join(sans[:4])}{"..." if len(sans)>4 else ""}')
                    if parts:
                        q.put(make_card('TLS Certificate', '<br>'.join(parts),
                                       body_plain=' | '.join(p for p in parts if '<' not in p),
                                       icon='fa-lock', tag='domain'))
                        result_counter[0] += 1
                except Exception as e:
                    q.put(make_card('TLS', f'No TLS or error: {str(e)[:60]}', icon='fa-lock-open', tag='domain'))

            elif mode_v == 'phone':
                try:
                    import phonenumbers
                    from phonenumbers import geocoder, carrier, timezone as tz_mod
                    pn = phonenumbers.parse(target, None)
                    valid = phonenumbers.is_valid_number(pn)
                    q.put(make_card('Validity', 'Valid ✓' if valid else 'Invalid ✗',
                                   icon='fa-check-circle' if valid else 'fa-times-circle', tag='phone'))
                    result_counter[0] += 1
                    intl = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                    e164 = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
                    nat  = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL)
                    q.put(make_card('International', intl, icon='fa-phone-alt', tag='phone'))
                    q.put(make_card('E.164 Format', e164, icon='fa-hashtag', tag='phone'))
                    q.put(make_card('National', nat, icon='fa-phone', tag='phone'))
                    result_counter[0] += 3
                    region = geocoder.description_for_number(pn, 'en')
                    if region:
                        q.put(make_card('Region', region, icon='fa-map-marker-alt', tag='phone'))
                        result_counter[0] += 1
                    carr = carrier.name_for_number(pn, 'en')
                    if carr:
                        q.put(make_card('Carrier', carr, icon='fa-satellite-dish', tag='phone'))
                        result_counter[0] += 1
                    zones = tz_mod.time_zones_for_number(pn)
                    if zones:
                        q.put(make_card('Timezone', ', '.join(zones), icon='fa-clock', tag='phone'))
                        result_counter[0] += 1
                    ntype = phonenumbers.number_type(pn)
                    type_names = {0:'Fixed Line',1:'Mobile',2:'Fixed/Mobile',3:'Toll Free',4:'Premium',6:'VOIP',7:'Personal'}
                    q.put(make_card('Number Type', type_names.get(ntype,'Unknown'), icon='fa-tag', tag='phone'))
                    result_counter[0] += 1
                except Exception as e:
                    q.put(make_card('Parse Error', str(e)[:100], icon='fa-exclamation-triangle', tag='phone'))

                digits = re.sub(r'\D', '', target)
                if len(digits) >= 7:
                    wa_url = f'https://wa.me/{digits}'
                    tg_url = f'https://t.me/{digits}'
                    g_url  = f'https://www.google.com/search?q={digits}'
                    q.put(make_card('WhatsApp', f'<a href="{wa_url}" target="_blank">Open chat →</a>',
                                   body_plain=wa_url, icon='fab fa-whatsapp', tag='phone', url=wa_url))
                    q.put(make_card('Telegram',  f'<a href="{tg_url}" target="_blank">Check profile →</a>',
                                   body_plain=tg_url, icon='fab fa-telegram', tag='phone', url=tg_url))
                    q.put(make_card('Google',    f'<a href="{g_url}" target="_blank">Search number →</a>',
                                   body_plain=g_url, icon='fab fa-google', tag='phone', url=g_url))
                    result_counter[0] += 3

        except Exception as e:
            q.put(make_card('Unexpected Error', str(e)[:120], icon='fa-exclamation-circle'))
        finally:
            q.put('__DONE__')
            # Log to DB after scan completes
            db_log_scan(ip, mode_v, target, ua, result_counter[0])
            with request_lock:
                active_requests -= 1
                if request_queue:
                    request_queue.popleft()
            threading.Timer(600, lambda: jobs.pop(job_id, None)).start()

    threading.Thread(target=runner, daemon=True).start()
    return jsonify({'status': 'started', 'job_id': job_id})


@app.route('/queue-status/<job_id>')
def queue_status(job_id):
    global active_requests
    with request_lock:
        if job_id in request_queue:
            pos = list(request_queue).index(job_id) + 1
            return jsonify({'status': 'queued', 'queue_position': pos})
        elif job_id in jobs:
            if active_requests < MAX_CONCURRENT_REQUESTS:
                active_requests += 1
                return jsonify({'status': 'started'})
            else:
                if job_id not in request_queue:
                    request_queue.append(job_id)
                pos = list(request_queue).index(job_id) + 1
                return jsonify({'status': 'queued', 'queue_position': pos})
        return jsonify({'status': 'error', 'message': 'Job not found'})


@app.route('/stream/<job_id>')
def stream(job_id):
    def gen():
        q = jobs.get(job_id)
        if not q:
            yield 'data: __DONE__\n\n'
            return
        while True:
            try:
                m = q.get(timeout=60)
                if m == '__DONE__':
                    yield 'data: __DONE__\n\n'
                    break
                yield f'data: {m}\n\n'
            except queue.Empty:
                yield 'data: __DONE__\n\n'
                break
    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


# ============================================================
#  ROUTES — ADMIN (hidden, unlisted)
# ============================================================
import secrets as _secrets

def _get_csrf():
    if '_csrf' not in session:
        session['_csrf'] = _secrets.token_hex(16)
    return session['_csrf']

def _admin_stats():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    stats = {
        'total':      cur.execute('SELECT COUNT(*) FROM scans').fetchone()[0],
        'today':      cur.execute('SELECT COUNT(*) FROM scans WHERE ts LIKE ?', (today+'%',)).fetchone()[0],
        'today_date': today,
        'unique_ips': cur.execute('SELECT COUNT(DISTINCT ip) FROM scans').fetchone()[0],
        'blocks':     cur.execute('SELECT COUNT(*) FROM rate_blocks').fetchone()[0],
        'emails':     cur.execute("SELECT COUNT(*) FROM scans WHERE mode='email'").fetchone()[0],
    }
    con.close()
    return stats

def _admin_scans(limit=500):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute('SELECT id,ts,ip,mode,target,ua,result_ct FROM scans ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
    con.close()
    return rows

def _admin_blocks(limit=500):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute('SELECT id,ts,ip,msg FROM rate_blocks ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
    con.close()
    return rows

def _admin_ip_summary():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute('''
        SELECT ip,
               COUNT(*) as total,
               SUM(CASE WHEN mode='email' THEN 1 ELSE 0 END),
               SUM(CASE WHEN mode='phone' THEN 1 ELSE 0 END),
               SUM(CASE WHEN mode='domain' THEN 1 ELSE 0 END),
               SUM(CASE WHEN mode='username' THEN 1 ELSE 0 END),
               MAX(ts)
        FROM scans GROUP BY ip ORDER BY total DESC LIMIT 200
    ''').fetchall()
    con.close()
    return rows

def _export_csv(table):
    import csv, io
    con = sqlite3.connect(DB_PATH)
    if table == 'scans':
        rows = con.execute('SELECT * FROM scans ORDER BY id DESC').fetchall()
        header = ['id','ts','ip','mode','target','ua','result_ct']
    elif table == 'blocks':
        rows = con.execute('SELECT * FROM rate_blocks ORDER BY id DESC').fetchall()
        header = ['id','ts','ip','msg']
    elif table == 'ips':
        rows = _admin_ip_summary()
        header = ['ip','total','email','phone','domain','username','last_seen']
    else:
        con.close()
        return None, None
    con.close()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue(), table

@app.route(f'/{ADMIN_PREFIX}', methods=['GET', 'POST'])
@app.route(f'/{ADMIN_PREFIX}/', methods=['GET', 'POST'])
def admin_panel():
    # Handle logout
    if request.args.get('logout'):
        session.clear()
        return redirect(f'/{ADMIN_PREFIX}')

    logged_in = session.get('admin_ok', False)
    error = None
    csrf_token = _get_csrf()

    # Handle login
    if request.method == 'POST' and not logged_in:
        uname = request.form.get('username', '')
        passw = request.form.get('password', '')
        csrf_in = request.form.get('csrf', '')
        # Constant-time compare
        if (hmac.compare_digest(uname, ADMIN_USERNAME) and
            hmac.compare_digest(passw, ADMIN_PASSWORD) and
            hmac.compare_digest(csrf_in, csrf_token)):
            session['admin_ok'] = True
            session.permanent = True
            return redirect(f'/{ADMIN_PREFIX}')
        else:
            error = 'Invalid credentials'
            import time as _t; _t.sleep(1.5)  # Throttle brute force

    if not logged_in:
        return render_template('admin.html',
            logged_in=False, error=error, csrf_token=csrf_token)

    # Handle clear
    clear = request.args.get('clear')
    if clear in ('scans', 'blocks'):
        con = sqlite3.connect(DB_PATH)
        if clear == 'scans':
            con.execute('DELETE FROM scans')
        else:
            con.execute('DELETE FROM rate_blocks')
        con.commit(); con.close()
        return redirect(f'/{ADMIN_PREFIX}')

    # Handle export
    export = request.args.get('export')
    if export:
        csv_data, fname = _export_csv(export)
        if csv_data:
            return Response(csv_data, mimetype='text/csv',
                headers={'Content-Disposition': f'attachment;filename=shadowtrace_{fname}.csv'})

    return render_template('admin.html',
        logged_in=True,
        csrf_token=csrf_token,
        stats=_admin_stats(),
        scans=_admin_scans(),
        blocks=_admin_blocks(),
        ip_summary=_admin_ip_summary(),
        all_notices=get_all_notices(),
        notice_colors=NOTICE_COLORS,
        notice_action=f'/{ADMIN_PREFIX}/notice/save',
        notice_toggle_url=f'/{ADMIN_PREFIX}/notice/toggle/',
        notice_delete_url=f'/{ADMIN_PREFIX}/notice/delete/'
    )


@app.route(f'/{ADMIN_PREFIX}/notice/save', methods=['POST'])
def admin_notice_save():
    if not session.get('admin_ok'):
        return redirect(f'/{ADMIN_PREFIX}')
    if not hmac.compare_digest(request.form.get('csrf', ''), _get_csrf()):
        return redirect(f'/{ADMIN_PREFIX}?tab=notices')

    nid     = request.form.get('id', '').strip()
    heading = request.form.get('heading', '').strip()[:120]
    content = request.form.get('content', '').strip()[:600]
    link    = request.form.get('link_url', '').strip()[:300]
    if link and not re.match(r'^https?://', link, re.I):
        link = ''  # reject unsafe / non-http(s) link schemes
    color_key = request.form.get('color_key', 'cyan')
    if color_key not in NOTICE_COLORS:
        color_key = 'cyan'
    active = 1 if request.form.get('active') == '1' else 0

    if heading and content:
        con = sqlite3.connect(DB_PATH)
        if nid.isdigit():
            con.execute('UPDATE notices SET heading=?,content=?,link_url=?,color_key=?,active=? WHERE id=?',
                        (heading, content, link, color_key, active, nid))
        else:
            con.execute('INSERT INTO notices (heading,content,link_url,color_key,active,created_at) VALUES (?,?,?,?,?,?)',
                        (heading, content, link, color_key, active, datetime.datetime.utcnow().isoformat()))
        con.commit()
        con.close()
    return redirect(f'/{ADMIN_PREFIX}?tab=notices')


@app.route(f'/{ADMIN_PREFIX}/notice/toggle/<int:nid>')
def admin_notice_toggle(nid):
    if not session.get('admin_ok'):
        return redirect(f'/{ADMIN_PREFIX}')
    con = sqlite3.connect(DB_PATH)
    con.execute('UPDATE notices SET active = 1-active WHERE id=?', (nid,))
    con.commit()
    con.close()
    return redirect(f'/{ADMIN_PREFIX}?tab=notices')


@app.route(f'/{ADMIN_PREFIX}/notice/delete/<int:nid>')
def admin_notice_delete(nid):
    if not session.get('admin_ok'):
        return redirect(f'/{ADMIN_PREFIX}')
    con = sqlite3.connect(DB_PATH)
    con.execute('DELETE FROM notices WHERE id=?', (nid,))
    con.commit()
    con.close()
    return redirect(f'/{ADMIN_PREFIX}?tab=notices')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port, threaded=True)
