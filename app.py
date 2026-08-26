import io
import os
import re
import json
import time
import string
import secrets
import zipfile
import datetime
import threading
from collections import defaultdict, deque
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, flash, jsonify, make_response, session)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash

from models import (db, User, LicenseKey, ApiDoc, ResetToken, AuditLog,
                    utc_now, generate_user_api_key, generate_portal_token)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static')
)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max payload to prevent memory-exhaustion DoS

# Cookie Hardening & Cloaking (Hidden from JavaScript, HTTPS only, Disguised names)
app.config['SESSION_COOKIE_NAME'] = '__cf_bm_sess'   # Disguised cookie name
app.config['SESSION_COOKIE_HTTPONLY'] = True         # 100% hidden from JS/XSS
app.config['SESSION_COOKIE_SECURE'] = True           # Transmitted only over HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'        # Anti-CSRF protection
app.config['REMEMBER_COOKIE_NAME'] = '__cf_uid'      # Disguised remember token
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)

# Database configuration (Supports Vercel serverless /tmp or remote PostgreSQL like Neon/Supabase)
if (os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME')) and not os.environ.get('DATABASE_URL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/auth.db'
else:
    db_uri = os.environ.get('DATABASE_URL', 'sqlite:///auth.db')
    if db_uri and db_uri.startswith('postgres://'):
        db_uri = db_uri.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# ---------------------------------------------------------------------------
# ANTI-DDOS & FLOOD PROTECTION SHIELD
# ---------------------------------------------------------------------------
class AntiDDoSShield:
    def __init__(self):
        self._lock = threading.Lock()
        self.ip_requests = defaultdict(deque)       # IP -> deque of request timestamps
        self.ip_auth_requests = defaultdict(deque)  # IP -> deque of auth/login timestamps
        self.banned_ips = {}                        # IP -> unban timestamp
        self.violation_counts = defaultdict(int)

        # Scanner and exploit tool blacklists
        self.bad_agents = [
            'sqlmap', 'nikto', 'masscan', 'zgrab', 'gobuster', 'dirbuster',
            'nmap', 'wpscan', 'acunetix', 'havij', 'pangolin'
        ]

    def get_real_ip(self, req):
        """Extract true client IP behind Cloudflare, Nginx, Vercel, or Railway proxies."""
        if req.headers.get('CF-Connecting-IP'):
            return req.headers.get('CF-Connecting-IP').strip()
        if req.headers.get('X-Forwarded-For'):
            return req.headers.get('X-Forwarded-For').split(',')[0].strip()
        if req.headers.get('X-Real-IP'):
            return req.headers.get('X-Real-IP').strip()
        return req.remote_addr or '127.0.0.1'

    def is_bad_bot(self, user_agent):
        if not user_agent:
            return False
        ua = user_agent.lower()
        return any(bad in ua for bad in self.bad_agents)

    def check_request(self, req):
        ip = self.get_real_ip(req)
        now = time.time()
        ua = req.headers.get('User-Agent', '')

        # 1. Block automated vulnerability scanners
        if self.is_bad_bot(ua):
            return False, "Automated vulnerability scanner blocked by Anti-DDoS Shield."

        with self._lock:
            # 2. Check if currently banned
            if ip in self.banned_ips:
                if now < self.banned_ips[ip]:
                    remaining = int(self.banned_ips[ip] - now)
                    return False, f"Your IP is temporarily banned due to flood detection. Retry in {remaining}s."
                else:
                    del self.banned_ips[ip]
                    self.violation_counts[ip] = 0

            # 3. Clean up timestamps older than 60 seconds
            history = self.ip_requests[ip]
            while history and history[0] < now - 60:
                history.popleft()

            # Record this request
            history.append(now)

            # 4. Burst limit: Max 50 requests in 3 seconds
            recent_burst = sum(1 for t in history if t > now - 3)
            if recent_burst > 50:
                self.banned_ips[ip] = now + 900  # 15 min ban
                return False, "DDoS flood detected (Burst threshold exceeded). IP banned for 15 minutes."

            # 5. Sustained limit: Max 200 requests in 60 seconds
            if len(history) > 200:
                self.violation_counts[ip] += 1
                if self.violation_counts[ip] >= 3:
                    self.banned_ips[ip] = now + 900  # 15 min ban
                    return False, "Excessive request rate detected. IP banned for 15 minutes."
                return False, "Rate limit exceeded (Anti-DDoS Protection). Please slow down."

            # 6. Sensitive Auth Endpoint Flood (Login / Reset / Auth API)
            if req.path.startswith('/api/v1/auth') or req.path in ['/login', '/portal/reset']:
                auth_hist = self.ip_auth_requests[ip]
                while auth_hist and auth_hist[0] < now - 60:
                    auth_hist.popleft()
                auth_hist.append(now)

                # Max 25 auth calls per 30 seconds
                recent_auth = sum(1 for t in auth_hist if t > now - 30)
                if recent_auth > 25:
                    return False, "Too many authentication attempts. Please wait 30 seconds."

        return True, ""

ddos_shield = AntiDDoSShield()

_db_initialized = False

@app.before_request
def security_and_ddos_filter():
    global _db_initialized
    if not _db_initialized:
        try:
            db.create_all()
            seed_database()
            _db_initialized = True
        except Exception as e:
            print(f"[!] DB init error: {e}")

    # Allow static assets without strict rate limiting
    if request.path.startswith('/static/'):
        return None

    # Check Anti-DDoS rules
    allowed, reason = ddos_shield.check_request(request)
    if not allowed:
        if request.is_json or request.path.startswith('/api/'):
            resp = jsonify({
                'success': False,
                'error': 'ddos_rate_limited',
                'message': reason
            })
            resp.status_code = 429
            resp.headers['Retry-After'] = '30'
            return resp
        else:
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>429 Too Many Requests — Anti-DDoS Shield</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ background:#0b0d17; color:#fff; font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
        .card {{ background:#131728; border:1px solid rgba(239,68,68,0.3); border-radius:14px; padding:36px; max-width:440px; text-align:center; box-shadow:0 20px 40px rgba(0,0,0,0.5); }}
        h2 {{ margin:0 0 10px; color:#f87171; font-size:22px; }}
        p {{ color:#94a3b8; font-size:14px; line-height:1.6; margin-bottom:20px; }}
        .btn {{ display:inline-block; background:#7c3aed; color:#fff; text-decoration:none; padding:10px 22px; border-radius:8px; font-weight:600; font-size:14px; transition:0.2s; }}
        .btn:hover {{ background:#6d28d9; }}
    </style>
</head>
<body>
    <div class="card">
        <div style="font-size:44px;margin-bottom:12px;">🛡️</div>
        <h2>Anti-DDoS Shield Active</h2>
        <p>{reason}</p>
        <a href="javascript:location.reload()" class="btn">🔄 Refresh Page</a>
    </div>
</body>
</html>"""
            resp = make_response(html, 429)
            resp.headers['Retry-After'] = '30'
            return resp


@app.after_request
def add_security_headers(response):
    # Remove revealing server & technology headers
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)

    # Security & Anti-Inspection Armor
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-DDoS-Protection'] = 'Active-Shield-v2'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Prevent sensitive dashboard & auth caching in browser memory
    if request.path.startswith('/admin') or request.path.startswith('/reseller') or request.path.startswith('/api'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

    # Dynamically minify HTML output to strip readable indentation and comments
    if response.content_type and 'text/html' in response.content_type:
        try:
            html_text = response.get_data(as_text=True)
            html_text = re.sub(r'<!--(?!\[if)[\s\S]*?-->', '', html_text)
            html_text = re.sub(r'\s+', ' ', html_text)
            response.set_data(html_text)
        except Exception:
            pass

    return response

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to continue.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------------
# Helpers & decorators
# ---------------------------------------------------------------------------

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            if request.is_json:
                return jsonify({'success': False, 'message': 'Admin access required'}), 403
            flash('Admin access required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def reseller_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['admin', 'reseller']:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Reseller access required'}), 403
            flash('Reseller access required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def generate_license_key():
    chars = string.ascii_uppercase + string.digits
    return '-'.join(''.join(secrets.choice(chars) for _ in range(4)) for _ in range(3))


def generate_reset_token():
    return secrets.token_urlsafe(40)


def log_action(action, actor_id=None, details=None):
    try:
        entry = AuditLog(action=action, actor_id=actor_id,
                         details=details, timestamp=utc_now())
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()


def parse_duration_type(duration_type, custom_value=None):
    if not duration_type or duration_type == 'lifetime' or duration_type == '0':
        return None, None
    elif str(duration_type).isdigit():
        return float(duration_type), None
    elif duration_type == '1d':
        return 1.0, None
    elif duration_type == '3d':
        return 3.0, None
    elif duration_type == '7d':
        return 7.0, None
    elif duration_type == '14d':
        return 14.0, None
    elif duration_type == '30d':
        return 30.0, None
    elif duration_type == '60d':
        return 60.0, None
    elif duration_type == '90d':
        return 90.0, None
    elif duration_type == '180d':
        return 180.0, None
    elif duration_type == '365d':
        return 365.0, None
    elif duration_type == 'custom_date' and custom_value:
        try:
            clean_str = str(custom_value).replace('T', ' ')
            if len(clean_str) == 10:
                clean_str += ' 23:59:59'
            elif len(clean_str) == 16:
                clean_str += ':00'
            fixed_dt = datetime.datetime.strptime(clean_str, '%Y-%m-%d %H:%M:%S')
            return None, fixed_dt
        except ValueError:
            return 30.0, None
    return 30.0, None


# ---------------------------------------------------------------------------
# DB seed
# ---------------------------------------------------------------------------

def seed_database():
    """Create admin user and default API docs on first run."""
    admin = User.query.filter_by(role='admin').first()
    if not admin:
        admin = User(
            username='admin',
            password_hash=generate_password_hash('Admin@1234'),
            role='admin',
            is_active=True,
            api_key=generate_user_api_key(),
            reset_portal_token=generate_portal_token(),
            duration_type='lifetime',
            duration_days=None,
            activated_at=utc_now(),
            expires_at=None
        )
        db.session.add(admin)
    else:
        if not admin.api_key:
            admin.api_key = generate_user_api_key()
        if not admin.reset_portal_token:
            admin.reset_portal_token = generate_portal_token()

    if not ApiDoc.query.first():
        doc = ApiDoc(
            title='Reseller Bot & Remote Management API Documentation',
            content="""# Reseller & Bot Management API

Integrate our high-performance authentication and key generation API into your own Telegram bot, Discord bot, website, or client code.

---

## 1. Remote Management Endpoint

### `GET / POST /api/v1/manage`
### `GET / POST /api/v1/manage?key=<API_KEY>&action=<action>`

**Parameters:**
- `key`: Your Reseller API Key (e.g. `AUTH-API-XXXXXXXXXXXXXXXX`)
- `action`: `'add'` / `'add_user'`, `'add_license'`, `'reset_hwid'`, `'update'` / `'extend'`, `'remove'` / `'delete'`, `'status'`
- `username`: App username (1-char to unlimited letters, isolated per reseller)
- `password`: App password (1-char to unlimited letters)
- `license_key`: (Optional) Custom license string, or leave empty for auto `XXXX-XXXX-XXXX`
- `duration`: Number of days (e.g. `1`, `7`, `30`, `90`, `365` or `'lifetime'`)
"""
        )
        db.session.add(doc)

    db.session.commit()
    print('[*] Database initialized. Admin: admin / Admin@1234')


# ---------------------------------------------------------------------------
# Core web routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'reseller':
            return redirect(url_for('reseller_dashboard_view'))
        else:
            return redirect(url_for('client_dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))

        if not username or not password:
            flash('Username and password are required.', 'error')
        else:
            # First check admin/reseller roles
            user = User.query.filter(User.role.in_(['admin', 'reseller']), User.username == username).first()
            if not user:
                # If not admin/reseller, search any client user
                candidates = User.query.filter_by(username=username).all()
                for c in candidates:
                    if check_password_hash(c.password_hash, password):
                        user = c
                        break

            if user:
                if user.is_paused:
                    flash('Your reseller account has been paused by administrator.', 'error')
                elif not user.is_active:
                    flash('This account is suspended/disabled by administrator.', 'error')
                elif user.is_expired:
                    flash(f'Account subscription expired on {user.expires_at.strftime("%Y-%m-%d %H:%M")}.', 'error')
                elif check_password_hash(user.password_hash, password):
                    login_user(user, remember=remember)
                    log_action('User logged in', actor_id=user.id)
                    if user.role == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    elif user.role == 'reseller':
                        return redirect(url_for('reseller_dashboard_view'))
                    else:
                        return redirect(url_for('client_dashboard'))
                else:
                    flash('Invalid username or password.', 'error')
            else:
                flash('Invalid username or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    log_action('User logged out', actor_id=current_user.id)
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Reseller Dashboard routes (Dedicated 5-tab Portal)
# ---------------------------------------------------------------------------

@app.route('/reseller/dashboard')
@login_required
@reseller_required
def reseller_dashboard_view():
    if not current_user.api_key:
        current_user.api_key = generate_user_api_key()
    if not current_user.reset_portal_token:
        current_user.reset_portal_token = generate_portal_token()
    db.session.commit()
    base_url = request.host_url.rstrip('/')
    return render_template('reseller_dashboard.html', user=current_user, base_url=base_url)


@app.route('/reseller/api/stats')
@login_required
@reseller_required
def reseller_api_stats():
    total_users = User.query.filter_by(created_by_id=current_user.id).count()
    active_users = User.query.filter_by(created_by_id=current_user.id, is_active=True).count()
    total_lic = LicenseKey.query.filter_by(created_by_id=current_user.id).count()
    active_lic = LicenseKey.query.filter_by(created_by_id=current_user.id, status='active').count()

    recent = (AuditLog.query
              .filter_by(actor_id=current_user.id)
              .order_by(AuditLog.timestamp.desc())
              .limit(10).all())
    activity = []
    for log in recent:
        activity.append({
            'action': log.action,
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M')
        })

    return jsonify({
        'credits': current_user.credits or 0,
        'panel_name': current_user.panel_name or 'Reseller Panel',
        'total_users': total_users,
        'active_users': active_users,
        'total_licenses': total_lic,
        'active_licenses': active_lic,
        'activity': activity
    })


@app.route('/reseller/api/users', methods=['GET'])
@login_required
@reseller_required
def reseller_list_users():
    users = User.query.filter_by(created_by_id=current_user.id).order_by(User.created_at.desc()).all()
    out = []
    for u in users:
        out.append({
            'id': u.id,
            'username': u.username,
            'status_label': u.status_label,
            'is_active': u.is_active,
            'is_activated': u.is_activated,
            'is_expired': u.is_expired,
            'time_left': u.time_left,
            'expires_at': u.expires_at.strftime('%Y-%m-%d %H:%M') if u.expires_at else ('Lifetime' if u.duration_type == 'lifetime' else 'Starts on 1st login'),
            'hwid': u.hwid or 'Not Bound',
            'created_at': u.created_at.strftime('%Y-%m-%d')
        })
    return jsonify(out)


@app.route('/reseller/api/users', methods=['POST'])
@login_required
@reseller_required
def reseller_create_user():
    if current_user.role == 'reseller' and (current_user.credits is None or current_user.credits < 1):
        return jsonify({'success': False, 'message': 'Insufficient credits! Please contact admin to recharge credits.'}), 400

    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    duration_type = data.get('duration_type', '30d')

    if not username:
        return jsonify({'success': False, 'message': 'Username is required.'})
    if not password:
        return jsonify({'success': False, 'message': 'Password is required.'})

    # MULTI-TENANT: Check uniqueness ONLY within THIS reseller's created users!
    if User.query.filter_by(created_by_id=current_user.id, username=username).first():
        return jsonify({'success': False, 'message': f'Username "{username}" already exists in your reseller account.'})

    days, fixed_expiry = parse_duration_type(duration_type, data.get('custom_date'))

    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role='client',
        is_active=True,
        api_key=generate_user_api_key(),
        duration_type=duration_type,
        duration_days=days,
        activated_at=None,
        expires_at=fixed_expiry,
        hwid=None,
        created_by_id=current_user.id
    )
    if current_user.role == 'reseller':
        current_user.credits -= 1

    db.session.add(user)
    db.session.commit()
    log_action(f'Reseller {current_user.username} created User: {username}', actor_id=current_user.id)

    return jsonify({
        'success': True,
        'message': f'User "{username}" created successfully (1 Credit deducted).',
        'credits': current_user.credits or 0
    })


@app.route('/reseller/api/users/<int:uid>', methods=['PUT'])
@login_required
@reseller_required
def reseller_update_user(uid):
    user = User.query.filter_by(id=uid, created_by_id=current_user.id).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found in your account.'}), 404

    data = request.get_json() or {}
    if data.get('password'):
        user.password_hash = generate_password_hash(data['password'])

    if 'duration_type' in data:
        days, fixed_expiry = parse_duration_type(data['duration_type'], data.get('custom_date'))
        user.duration_type = data['duration_type']
        user.duration_days = days
        if user.is_activated and days:
            user.expires_at = utc_now() + datetime.timedelta(days=days)
        else:
            user.expires_at = fixed_expiry

    if data.get('reset_hwid'):
        user.hwid = None
        user.activated_at = None
        user.expires_at = None

    db.session.commit()
    log_action(f'Reseller updated user: {user.username}', actor_id=current_user.id)
    return jsonify({'success': True, 'message': f'User "{user.username}" updated successfully.'})


@app.route('/reseller/api/users/<int:uid>', methods=['DELETE'])
@login_required
@reseller_required
def reseller_delete_user(uid):
    user = User.query.filter_by(id=uid, created_by_id=current_user.id).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found in your account.'}), 404

    name = user.username
    LicenseKey.query.filter_by(user_id=uid).delete()
    ResetToken.query.filter_by(user_id=uid).delete()
    db.session.delete(user)
    db.session.commit()
    log_action(f'Reseller deleted user: {name}', actor_id=current_user.id)
    return jsonify({'success': True, 'message': f'User "{name}" deleted.'})


@app.route('/reseller/api/licenses', methods=['GET'])
@login_required
@reseller_required
def reseller_list_licenses():
    licenses = LicenseKey.query.filter_by(created_by_id=current_user.id).order_by(LicenseKey.created_at.desc()).all()
    out = []
    for lic in licenses:
        out.append({
            'id': lic.id,
            'key': lic.key,
            'status': lic.display_status,
            'is_activated': lic.is_activated,
            'is_expired': lic.is_expired,
            'time_left': lic.time_left,
            'expires_at': lic.expires_at.strftime('%Y-%m-%d %H:%M') if lic.expires_at else ('Lifetime' if lic.duration_type == 'lifetime' else 'Starts on 1st use'),
            'hwid': lic.hwid or 'Not Bound',
            'created_at': lic.created_at.strftime('%Y-%m-%d')
        })
    return jsonify(out)


@app.route('/reseller/api/licenses', methods=['POST'])
@login_required
@reseller_required
def reseller_create_license():
    if current_user.role == 'reseller' and (current_user.credits is None or current_user.credits < 1):
        return jsonify({'success': False, 'message': 'Insufficient credits! Please contact admin.'}), 400

    data = request.get_json() or {}
    custom_key = data.get('custom_key', '').strip()
    duration_type = data.get('duration_type', '30d')
    days, fixed_expiry = parse_duration_type(duration_type, data.get('custom_date'))

    if custom_key:
        if LicenseKey.query.filter_by(created_by_id=current_user.id, key=custom_key).first():
            return jsonify({'success': False, 'message': f'License key "{custom_key}" already exists in your account.'})
        key = custom_key
    else:
        key = generate_license_key()

    lic = LicenseKey(
        key=key,
        status='unused',
        duration_type=duration_type,
        duration_days=days,
        activated_at=None,
        expires_at=fixed_expiry,
        hwid=None,
        created_by_id=current_user.id
    )
    if current_user.role == 'reseller':
        current_user.credits -= 1

    db.session.add(lic)
    db.session.commit()
    log_action(f'Reseller {current_user.username} generated License: {key}', actor_id=current_user.id)

    return jsonify({
        'success': True,
        'message': f'License key "{key}" generated (1 Credit deducted).',
        'key': key,
        'credits': current_user.credits or 0
    })


@app.route('/reseller/api/licenses/<int:lid>', methods=['PUT'])
@login_required
@reseller_required
def reseller_update_license(lid):
    lic = LicenseKey.query.filter_by(id=lid, created_by_id=current_user.id).first()
    if not lic:
        return jsonify({'success': False, 'message': 'License key not found.'}), 404

    data = request.get_json() or {}
    if 'duration_type' in data:
        days, fixed_expiry = parse_duration_type(data['duration_type'], data.get('custom_date'))
        lic.duration_type = data['duration_type']
        lic.duration_days = days
        if lic.is_activated and days:
            lic.expires_at = utc_now() + datetime.timedelta(days=days)
        else:
            lic.expires_at = fixed_expiry

    if data.get('reset_hwid'):
        lic.hwid = None
        lic.activated_at = None
        lic.expires_at = None
        lic.status = 'unused'

    db.session.commit()
    log_action(f'Reseller updated license: {lic.key}', actor_id=current_user.id)
    return jsonify({'success': True, 'message': f'License "{lic.key}" updated.'})


@app.route('/reseller/api/licenses/<int:lid>', methods=['DELETE'])
@login_required
@reseller_required
def reseller_delete_license(lid):
    lic = LicenseKey.query.filter_by(id=lid, created_by_id=current_user.id).first()
    if not lic:
        return jsonify({'success': False, 'message': 'License key not found.'}), 404

    key = lic.key
    db.session.delete(lic)
    db.session.commit()
    log_action(f'Reseller deleted license: {key}', actor_id=current_user.id)
    return jsonify({'success': True, 'message': f'License key "{key}" deleted.'})


@app.route('/reseller/api/users-list')
@login_required
@reseller_required
def reseller_users_list():
    users = User.query.filter_by(created_by_id=current_user.id).order_by(User.username).all()
    return jsonify([{'id': u.id, 'username': u.username, 'time_left': u.time_left} for u in users])


@app.route('/reseller/api/reset-user', methods=['POST'])
@login_required
@reseller_required
def reseller_reset_user():
    data = request.get_json() or {}
    uid = data.get('user_id')
    action = data.get('action')

    user = User.query.filter_by(id=uid, created_by_id=current_user.id).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found in your account.'}), 404

    extra = {}
    if action == 'password':
        pwd = data.get('new_password', '')
        if not pwd:
            return jsonify({'success': False, 'message': 'Password cannot be empty.'})
        user.password_hash = generate_password_hash(pwd)
        db.session.commit()
        extra['message'] = f'Password reset for "{user.username}".'

    elif action == 'duration':
        duration_type = data.get('duration_type', '30d')
        days, fixed_expiry = parse_duration_type(duration_type, data.get('custom_date'))
        user.duration_type = duration_type
        user.duration_days = days
        if user.is_activated and days:
            user.expires_at = utc_now() + datetime.timedelta(days=days)
        else:
            user.expires_at = fixed_expiry
        db.session.commit()
        extra['message'] = f'Duration updated for "{user.username}": {user.time_left}'

    elif action == 'hwid':
        user.hwid = None
        user.activated_at = None
        user.expires_at = None
        db.session.commit()
        extra['message'] = f'HWID lock & activation reset for "{user.username}".'

    log_action(f'Reseller reset [{action}] for user: {user.username}', actor_id=current_user.id)
    return jsonify({'success': True, **extra})


@app.route('/reseller/api/regen-portal-token', methods=['POST'])
@login_required
@reseller_required
def reseller_regen_portal_token():
    current_user.reset_portal_token = generate_portal_token()
    db.session.commit()
    log_action(f'Reseller regenerated reset portal link', actor_id=current_user.id)
    return jsonify({
        'success': True,
        'message': 'Public HWID Reset Portal Link regenerated successfully!',
        'portal_token': current_user.reset_portal_token
    })


# ---------------------------------------------------------------------------
# Public Self-Service Client HWID Reset Portal (Dedicated for each Reseller)
# ---------------------------------------------------------------------------

@app.route('/portal/reset/<token>', methods=['GET'])
def public_reset_portal(token):
    reseller = User.query.filter_by(reset_portal_token=token).first()
    if not reseller:
        return render_template('login.html'), 404
    if reseller.is_paused:
        return render_template('login.html'), 403

    return render_template('public_reset_portal.html', reseller=reseller, token=token)


@app.route('/portal/api/reset-hwid', methods=['POST'])
def public_api_reset_hwid():
    data = request.get_json(silent=True) or request.form
    token = data.get('token', '').strip()
    username = data.get('username', '').strip()

    if not token or not username:
        return jsonify({'success': False, 'message': 'Token and Username are required.'}), 400

    reseller = User.query.filter_by(reset_portal_token=token).first()
    if not reseller:
        return jsonify({'success': False, 'message': 'Invalid or expired Reset Portal link.'}), 404
    if reseller.is_paused:
        return jsonify({'success': False, 'message': 'This reseller panel is currently paused.'}), 403

    # Multi-tenant check: Find user under THIS specific reseller
    user = User.query.filter_by(created_by_id=reseller.id, username=username).first()
    if not user and reseller.role == 'admin':
        user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({
            'success': False,
            'message': f'App User "{username}" was not found under this reseller panel ({reseller.panel_name or reseller.username}).'
        }), 404

    # Reset HWID and activation
    user.hwid = None
    user.activated_at = None
    user.expires_at = None
    db.session.commit()
    log_action(f'Client user "{username}" self-reset HWID via Public Reset Portal ({reseller.username})')

    return jsonify({
        'success': True,
        'message': f'Hardware Lock (HWID) for "{username}" has been successfully cleared! You can now log into the application on your new PC.',
        'username': username
    }), 200


# ---------------------------------------------------------------------------
# Client Dashboard routes (For direct app clients)
# ---------------------------------------------------------------------------

@app.route('/client/dashboard')
@login_required
def client_dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'reseller':
        return redirect(url_for('reseller_dashboard_view'))

    if not current_user.api_key:
        current_user.api_key = generate_user_api_key()
        db.session.commit()

    license_key = LicenseKey.query.filter_by(
        user_id=current_user.id, status='active').first()
    api_doc = ApiDoc.query.first()
    now = utc_now()
    active_token = ResetToken.query.filter_by(
        user_id=current_user.id, used=False
    ).filter(ResetToken.expires_at > now).first()

    base_url = request.host_url.rstrip('/')

    return render_template('client_dashboard.html',
                           user=current_user,
                           license_key=license_key,
                           api_doc=api_doc,
                           active_token=active_token,
                           base_url=base_url)


@app.route('/client/api/reset-api-key', methods=['POST'])
@login_required
def client_reset_api_key():
    current_user.api_key = generate_user_api_key()
    db.session.commit()
    log_action('User regenerated API Key', actor_id=current_user.id)
    return jsonify({
        'success': True,
        'message': 'API Key regenerated successfully!',
        'api_key': current_user.api_key
    })


@app.route('/client/change-password', methods=['POST'])
@login_required
def client_change_password():
    data = request.get_json() or {}
    current_pwd = data.get('current_password', '')
    new_pwd = data.get('new_password', '')
    confirm_pwd = data.get('confirm_password', '')

    if not current_pwd or not new_pwd or not confirm_pwd:
        return jsonify({'success': False, 'message': 'All password fields are required.'})
    if not check_password_hash(current_user.password_hash, current_pwd):
        return jsonify({'success': False, 'message': 'Current password is incorrect.'})
    if new_pwd != confirm_pwd:
        return jsonify({'success': False, 'message': 'New passwords do not match.'})

    current_user.password_hash = generate_password_hash(new_pwd)
    db.session.commit()
    log_action('Client changed password', actor_id=current_user.id)
    return jsonify({'success': True, 'message': 'Password changed successfully!'})


@app.route('/client/generate-reset-token', methods=['POST'])
@login_required
def client_generate_reset_token():
    ResetToken.query.filter_by(user_id=current_user.id, used=False).update({'used': True})
    db.session.commit()

    token = generate_reset_token()
    expiry = utc_now() + datetime.timedelta(hours=24)
    rt = ResetToken(user_id=current_user.id, token=token, expires_at=expiry)
    db.session.add(rt)
    db.session.commit()

    reset_url = url_for('use_reset_token', token=token, _external=True)
    log_action('Generated reset token', actor_id=current_user.id)
    return jsonify({'success': True, 'reset_url': reset_url,
                    'expires': expiry.strftime('%Y-%m-%d %H:%M UTC')})


@app.route('/reset/<token>')
def use_reset_token(token):
    now = utc_now()
    rt = ResetToken.query.filter_by(token=token, used=False).first()
    if not rt or rt.expires_at < now:
        flash('This reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
    rt.used = True
    db.session.commit()
    user = db.session.get(User, rt.user_id)
    if user and user.is_active:
        login_user(user)
        flash('Logged in via reset link. You can now update your password.', 'warning')
        return redirect(url_for('index'))
    flash('User not found or inactive.', 'error')
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Reseller & Bot Management API Endpoints (GET & POST Supported)
# ---------------------------------------------------------------------------

@app.route('/api/v1/manage', methods=['GET', 'POST'])
@app.route('/api/v1/reseller', methods=['GET', 'POST'])
def api_reseller_manage():
    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form.to_dict()
    else:
        data = request.args.to_dict()

    api_key = data.get('key') or data.get('api_key') or request.headers.get('X-API-Key')
    if not api_key:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            api_key = auth_header[7:].strip()

    if not api_key:
        return jsonify({'success': False, 'message': 'API Key is required via ?key= or Header'}), 401

    reseller = User.query.filter_by(api_key=api_key).first()
    if not reseller:
        return jsonify({'success': False, 'message': 'Invalid API Key'}), 401
    if reseller.is_paused:
        return jsonify({'success': False, 'message': 'Your reseller account has been paused by administrator'}), 403
    if not reseller.is_active:
        return jsonify({'success': False, 'message': 'Your account is disabled'}), 403

    action = (data.get('action') or data.get('act') or '').lower().strip()

    # Action 1: Add User
    if action in ['add', 'add_user', 'create_user']:
        username = (data.get('username') or data.get('user') or data.get('uid') or '').strip()
        password = str(data.get('password') or data.get('pass') or '').strip()
        duration_raw = data.get('duration') or data.get('days') or '30'

        if not username:
            return jsonify({'success': False, 'message': 'Parameter "username" is required'}), 400
        if not password:
            return jsonify({'success': False, 'message': 'Parameter "password" is required'}), 400

        # Multi-tenant check: check within this reseller only
        if User.query.filter_by(created_by_id=reseller.id, username=username).first():
            return jsonify({'success': False, 'message': f'Username "{username}" already exists in your reseller account'}), 400

        if reseller.role == 'reseller' and (reseller.credits is None or reseller.credits < 1):
            return jsonify({'success': False, 'message': 'Insufficient reseller credits! Please contact admin.'}), 403

        days, fixed_expiry = parse_duration_type(duration_raw)
        dur_type = f'{int(days)}d' if days else ('lifetime' if duration_raw == 'lifetime' else '30d')

        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            role='client',
            is_active=True,
            api_key=generate_user_api_key(),
            duration_type=dur_type,
            duration_days=days,
            activated_at=None,
            expires_at=fixed_expiry,
            hwid=None,
            created_by_id=reseller.id
        )
        if reseller.role == 'reseller':
            reseller.credits -= 1

        db.session.add(new_user)
        db.session.commit()
        log_action(f'Reseller {reseller.username} created App User: {username}', actor_id=reseller.id)

        return jsonify({
            'success': True,
            'message': f'User "{username}" created successfully',
            'username': username,
            'password': password,
            'duration': f'{int(days)} days' if days else 'Lifetime',
            'time_left': new_user.time_left,
            'status': new_user.status_label,
            'credits_remaining': reseller.credits if reseller.role == 'reseller' else 'Unlimited'
        }), 200

    # Action 2: Add License Key
    elif action in ['add_license', 'create_license', 'generate_license']:
        custom_key = (data.get('license_key') or data.get('key_name') or data.get('lic') or '').strip()
        duration_raw = data.get('duration') or data.get('days') or '30'

        if reseller.role == 'reseller' and (reseller.credits is None or reseller.credits < 1):
            return jsonify({'success': False, 'message': 'Insufficient reseller credits! Please contact admin.'}), 403

        if custom_key:
            if LicenseKey.query.filter_by(created_by_id=reseller.id, key=custom_key).first():
                return jsonify({'success': False, 'message': f'License key "{custom_key}" already exists in your account'}), 400
            key = custom_key
        else:
            key = generate_license_key()

        days, fixed_expiry = parse_duration_type(duration_raw)
        dur_type = f'{int(days)}d' if days else ('lifetime' if duration_raw == 'lifetime' else '30d')

        lic = LicenseKey(
            key=key,
            status='unused',
            duration_type=dur_type,
            duration_days=days,
            activated_at=None,
            expires_at=fixed_expiry,
            hwid=None,
            created_by_id=reseller.id
        )
        if reseller.role == 'reseller':
            reseller.credits -= 1

        db.session.add(lic)
        db.session.commit()
        log_action(f'Reseller {reseller.username} created License: {key}', actor_id=reseller.id)

        return jsonify({
            'success': True,
            'message': f'License key "{key}" generated successfully',
            'license_key': key,
            'duration': f'{int(days)} days' if days else 'Lifetime',
            'time_left': lic.time_left,
            'status': lic.display_status,
            'credits_remaining': reseller.credits if reseller.role == 'reseller' else 'Unlimited'
        }), 200

    # Action 3: Reset HWID & Activation
    elif action in ['reset_hwid', 'reset', 'resethwid']:
        target_user = (data.get('username') or data.get('user') or '').strip()
        target_lic = (data.get('license_key') or data.get('key_name') or '').strip()

        if target_user:
            u = User.query.filter_by(created_by_id=reseller.id, username=target_user).first()
            if not u and reseller.role == 'admin':
                u = User.query.filter_by(username=target_user).first()
            if not u:
                return jsonify({'success': False, 'message': f'User "{target_user}" not found in your account'}), 404
            u.hwid = None
            u.activated_at = None
            u.expires_at = None
            db.session.commit()
            log_action(f'Reseller {reseller.username} reset HWID for user: {target_user}', actor_id=reseller.id)
            return jsonify({
                'success': True,
                'message': f'HWID lock & activation reset for user "{target_user}". Timer will restart on next EXE login.'
            }), 200

        elif target_lic:
            l = LicenseKey.query.filter_by(created_by_id=reseller.id, key=target_lic).first()
            if not l and reseller.role == 'admin':
                l = LicenseKey.query.filter_by(key=target_lic).first()
            if not l:
                return jsonify({'success': False, 'message': f'License key "{target_lic}" not found in your account'}), 404
            l.hwid = None
            l.activated_at = None
            l.expires_at = None
            l.status = 'unused'
            db.session.commit()
            log_action(f'Reseller {reseller.username} reset HWID for license: {target_lic}', actor_id=reseller.id)
            return jsonify({
                'success': True,
                'message': f'HWID lock & activation reset for license key "{target_lic}".'
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Please provide "username" or "license_key" to reset'}), 400

    # Action 4: Extend / Update Duration
    elif action in ['extend', 'update', 'set_duration']:
        target_user = (data.get('username') or data.get('user') or '').strip()
        target_lic = (data.get('license_key') or data.get('key_name') or '').strip()
        duration_raw = data.get('duration') or data.get('days') or '30'
        days, fixed_expiry = parse_duration_type(duration_raw)

        if target_user:
            u = User.query.filter_by(created_by_id=reseller.id, username=target_user).first()
            if not u and reseller.role == 'admin':
                u = User.query.filter_by(username=target_user).first()
            if not u:
                return jsonify({'success': False, 'message': f'User "{target_user}" not found in your account'}), 404
            u.duration_days = days
            u.duration_type = f'{int(days)}d' if days else 'lifetime'
            if u.is_activated and days:
                u.expires_at = utc_now() + datetime.timedelta(days=days)
            else:
                u.expires_at = fixed_expiry
            db.session.commit()
            return jsonify({
                'success': True,
                'message': f'Subscription for user "{target_user}" updated ({u.time_left})',
                'time_left': u.time_left,
                'expires_at': u.expires_at.isoformat() if u.expires_at else None
            }), 200

        elif target_lic:
            l = LicenseKey.query.filter_by(created_by_id=reseller.id, key=target_lic).first()
            if not l and reseller.role == 'admin':
                l = LicenseKey.query.filter_by(key=target_lic).first()
            if not l:
                return jsonify({'success': False, 'message': f'License "{target_lic}" not found in your account'}), 404
            l.duration_days = days
            l.duration_type = f'{int(days)}d' if days else 'lifetime'
            if l.is_activated and days:
                l.expires_at = utc_now() + datetime.timedelta(days=days)
            else:
                l.expires_at = fixed_expiry
            db.session.commit()
            return jsonify({
                'success': True,
                'message': f'License "{target_lic}" updated ({l.time_left})',
                'time_left': l.time_left,
                'expires_at': l.expires_at.isoformat() if l.expires_at else None
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Please provide "username" or "license_key"'}), 400

    # Action 5: Check Status
    elif action in ['status', 'check', 'info']:
        target_user = (data.get('username') or data.get('user') or '').strip()
        target_lic = (data.get('license_key') or data.get('key_name') or '').strip()

        if target_user:
            u = User.query.filter_by(created_by_id=reseller.id, username=target_user).first()
            if not u and reseller.role == 'admin':
                u = User.query.filter_by(username=target_user).first()
            if not u:
                return jsonify({'success': False, 'message': f'User "{target_user}" not found in your account'}), 404
            return jsonify({
                'success': True,
                'type': 'user',
                'username': u.username,
                'status': u.status_label,
                'is_activated': u.is_activated,
                'is_expired': u.is_expired,
                'time_left': u.time_left,
                'expires_at': u.expires_at.isoformat() if u.expires_at else None,
                'hwid': u.hwid or 'Not Bound'
            }), 200

        elif target_lic:
            l = LicenseKey.query.filter_by(created_by_id=reseller.id, key=target_lic).first()
            if not l and reseller.role == 'admin':
                l = LicenseKey.query.filter_by(key=target_lic).first()
            if not l:
                return jsonify({'success': False, 'message': f'License "{target_lic}" not found in your account'}), 404
            return jsonify({
                'success': True,
                'type': 'license',
                'license_key': l.key,
                'status': l.display_status,
                'is_activated': l.is_activated,
                'is_expired': l.is_expired,
                'time_left': l.time_left,
                'expires_at': l.expires_at.isoformat() if l.expires_at else None,
                'hwid': l.hwid or 'Not Bound'
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Please provide "username" or "license_key"'}), 400

    # Action 6: Remove / Delete
    elif action in ['remove', 'delete']:
        target_user = (data.get('username') or data.get('user') or '').strip()
        target_lic = (data.get('license_key') or data.get('key_name') or '').strip()

        if target_user:
            u = User.query.filter_by(created_by_id=reseller.id, username=target_user).first()
            if not u and reseller.role == 'admin':
                u = User.query.filter_by(username=target_user).first()
            if not u:
                return jsonify({'success': False, 'message': f'User "{target_user}" not found in your account'}), 404
            if u.role == 'admin':
                return jsonify({'success': False, 'message': 'Cannot delete admin'}), 403
            LicenseKey.query.filter_by(user_id=u.id).delete()
            ResetToken.query.filter_by(user_id=u.id).delete()
            db.session.delete(u)
            db.session.commit()
            return jsonify({'success': True, 'message': f'User "{target_user}" deleted successfully'}), 200

        elif target_lic:
            l = LicenseKey.query.filter_by(created_by_id=reseller.id, key=target_lic).first()
            if not l and reseller.role == 'admin':
                l = LicenseKey.query.filter_by(key=target_lic).first()
            if not l:
                return jsonify({'success': False, 'message': f'License "{target_lic}" not found in your account'}), 404
            db.session.delete(l)
            db.session.commit()
            return jsonify({'success': True, 'message': f'License "{target_lic}" deleted successfully'}), 200
        else:
            return jsonify({'success': False, 'message': 'Please provide "username" or "license_key"'}), 400

    else:
        return jsonify({
            'success': False,
            'message': f'Unknown action "{action}". Valid actions: add, add_license, reset_hwid, extend, status, remove'
        }), 400


# ---------------------------------------------------------------------------
# C# / EXE / KeyAuth API Endpoints (Multi-Tenant Login Support)
# ---------------------------------------------------------------------------

@app.route('/api/v1/auth/login', methods=['POST'])
def api_exe_user_login():
    data = request.get_json(silent=True) or request.form
    username = data.get('username', '').strip()
    password = data.get('password', '')
    hwid = data.get('hwid', '').strip() or None
    sid = data.get('sid', '').strip() or None
    seller_key = data.get('seller_key') or data.get('reseller_key') or data.get('api_key')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'}), 400

    user = None

    # Multi-tenant: If seller_key is supplied, authenticate against that specific reseller
    if seller_key:
        reseller = User.query.filter_by(api_key=seller_key).first()
        if not reseller:
            return jsonify({'success': False, 'message': 'Invalid seller key'}), 401
        user = User.query.filter_by(created_by_id=reseller.id, username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401
    else:
        # Search candidate matching username and password
        candidates = User.query.filter_by(username=username).all()
        matched = []
        for c in candidates:
            if check_password_hash(c.password_hash, password):
                matched.append(c)

        if not matched:
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

        if len(matched) == 1:
            user = matched[0]
        else:
            # If multiple users have the same username & password, match with bound HWID
            hwid_match = next((c for c in matched if c.hwid == hwid), None)
            user = hwid_match or matched[0]

    if user.is_reseller_paused:
        return jsonify({'success': False, 'message': 'Reseller account is paused. Please contact your reseller.'}), 403

    if user.is_paused or not user.is_active:
        return jsonify({'success': False, 'message': 'Account is suspended by administrator'}), 403

    now = utc_now()

    # FIRST TIME EXE ACTIVATION: Start Timer & Lock HWID + SID! (KeyAuth Style)
    if not user.is_activated:
        user.activated_at = now
        if hwid:
            user.hwid = hwid
        if sid:
            user.sid = sid
        if user.duration_type != 'lifetime' and user.duration_days:
            user.expires_at = now + datetime.timedelta(days=user.duration_days)
        db.session.commit()
        log_action(f'App User activated on EXE: {user.username} (HWID: {user.hwid or "None"}, SID: {user.sid or "None"}, Duration: {user.time_left})', actor_id=user.id)
    else:
        # Check HWID Lock
        if hwid and user.hwid and user.hwid != hwid:
            return jsonify({
                'success': False,
                'message': 'HWID mismatch! Hardware lock is bound to another PC. Please reset your HWID.',
                'hwid_locked': True
            }), 403
        elif hwid and not user.hwid:
            user.hwid = hwid
            db.session.commit()

        # Check SID Lock
        if sid and user.sid and user.sid != sid:
            return jsonify({
                'success': False,
                'message': 'SID mismatch! Security identifier does not match bound Windows profile.',
                'sid_locked': True
            }), 403
        elif sid and not user.sid:
            user.sid = sid
            db.session.commit()

        if user.is_expired:
            return jsonify({
                'success': False,
                'message': f'Subscription expired on {user.expires_at.strftime("%Y-%m-%d %H:%M:%S")}',
                'expired': True
            }), 403

    log_action(f'EXE client login success: {user.username}', actor_id=user.id)

    creator = db.session.get(User, user.created_by_id) if user.created_by_id else None
    panel_name = creator.panel_name if (creator and creator.panel_name) else (user.panel_name or 'Official Panel')

    return jsonify({
        'success': True,
        'message': 'Authentication successful',
        'username': user.username,
        'panel_name': panel_name,
        'role': user.role,
        'is_activated': True,
        'activated_at': user.activated_at.isoformat() if user.activated_at else None,
        'expires_at': user.expires_at.isoformat() if user.expires_at else None,
        'time_left': user.time_left,
        'is_lifetime': user.duration_type == 'lifetime',
        'hwid': user.hwid,
        'sid': user.sid
    }), 200


@app.route('/api/v1/auth/verify', methods=['POST'])
def api_verify_license():
    data = request.get_json(silent=True) or request.form
    key = data.get('license_key') or request.headers.get('X-License-Key')
    hwid = data.get('hwid', '').strip() or None
    sid = data.get('sid', '').strip() or None
    seller_key = data.get('seller_key') or data.get('reseller_key') or data.get('api_key')

    if not key:
        return jsonify({'valid': False, 'error': 'License key is required'}), 400

    lic = None
    if seller_key:
        reseller = User.query.filter_by(api_key=seller_key).first()
        if reseller:
            lic = LicenseKey.query.filter_by(created_by_id=reseller.id, key=key).first()
    if not lic:
        lic = LicenseKey.query.filter_by(key=key).first()

    if not lic:
        return jsonify({'valid': False, 'error': 'License key not found'}), 401

    if lic.is_reseller_paused:
        return jsonify({'valid': False, 'error': 'Reseller account is paused. Please contact your reseller.'}), 403

    if lic.status == 'revoked':
        return jsonify({'valid': False, 'error': 'License has been revoked by admin'}), 403

    now = utc_now()

    # FIRST TIME LICENSE ACTIVATION: Start Timer & Lock HWID + SID!
    if not lic.is_activated:
        lic.activated_at = now
        lic.status = 'active'
        if hwid:
            lic.hwid = hwid
        if sid:
            lic.sid = sid
        if lic.duration_type != 'lifetime' and lic.duration_days:
            lic.expires_at = now + datetime.timedelta(days=lic.duration_days)
        db.session.commit()
        log_action(f'License activated on EXE: {lic.key} (HWID: {lic.hwid or "None"}, SID: {lic.sid or "None"}, Duration: {lic.time_left})')
    else:
        if hwid and lic.hwid and lic.hwid != hwid:
            return jsonify({'valid': False, 'error': 'HWID mismatch on license key! Bound to another device.'}), 403
        elif hwid and not lic.hwid:
            lic.hwid = hwid
            db.session.commit()

        if sid and lic.sid and lic.sid != sid:
            return jsonify({'valid': False, 'error': 'SID mismatch on license key!'}), 403
        elif sid and not lic.sid:
            lic.sid = sid
            db.session.commit()

        if lic.is_expired:
            lic.status = 'expired'
            db.session.commit()
            return jsonify({'valid': False, 'error': 'License has expired'}), 403

    creator = db.session.get(User, lic.created_by_id) if lic.created_by_id else None
    panel_name = creator.panel_name if (creator and creator.panel_name) else 'Official Panel'

    return jsonify({
        'valid': True,
        'license_key': lic.key,
        'panel_name': panel_name,
        'status': lic.display_status,
        'is_activated': True,
        'time_left': lic.time_left,
        'expires_at': lic.expires_at.isoformat() if lic.expires_at else None,
        'hwid': lic.hwid,
        'sid': lic.sid
    }), 200


# --- Admin Dashboard routes ---

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    if not current_user.api_key:
        current_user.api_key = generate_user_api_key()
        db.session.commit()
    base_url = request.host_url.rstrip('/')
    return render_template('admin_dashboard.html', admin_api_key=current_user.api_key, base_url=base_url)


# --- Admin Stats ---

@app.route('/admin/api/stats')
@login_required
@admin_required
def admin_stats():
    total_users = User.query.filter_by(role='client').count()
    active_users = User.query.filter_by(role='client', is_active=True).count()
    total_lic = LicenseKey.query.count()
    active_lic = LicenseKey.query.filter_by(status='active').count()
    total_resellers = User.query.filter_by(role='reseller').count()
    recent = (AuditLog.query
              .order_by(AuditLog.timestamp.desc())
              .limit(12).all())
    activity = []
    for log in recent:
        actor = db.session.get(User, log.actor_id) if log.actor_id else None
        activity.append({
            'action': log.action,
            'actor': actor.username if actor else 'System',
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M')
        })
    return jsonify({
        'total_users': total_users,
        'active_users': active_users,
        'total_licenses': total_lic,
        'active_licenses': active_lic,
        'total_resellers': total_resellers,
        'activity': activity
    })


# --- Admin Resellers CRUD ---

@app.route('/admin/api/resellers', methods=['GET'])
@login_required
@admin_required
def admin_list_resellers():
    resellers = User.query.filter_by(role='reseller').order_by(User.created_at.desc()).all()
    out = []
    for r in resellers:
        user_count = User.query.filter_by(created_by_id=r.id).count()
        lic_count = LicenseKey.query.filter_by(created_by_id=r.id).count()
        out.append({
            'id': r.id,
            'username': r.username,
            'panel_name': r.panel_name or 'Default Reseller Panel',
            'credits': r.credits or 0,
            'is_paused': r.is_paused,
            'api_key': r.api_key,
            'created_at': r.created_at.strftime('%Y-%m-%d'),
            'total_users': user_count,
            'total_licenses': lic_count
        })
    return jsonify(out)


@app.route('/admin/api/resellers', methods=['POST'])
@login_required
@admin_required
def admin_create_reseller():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    credits_val = int(data.get('credits') or 0)
    panel_name = data.get('panel_name', '').strip() or f'{username.capitalize()} Store Panel'

    if not username:
        return jsonify({'success': False, 'message': 'Reseller username is required'}), 400
    if not password:
        return jsonify({'success': False, 'message': 'Reseller password is required'}), 400

    if User.query.filter(User.role.in_(['admin', 'reseller']), User.username == username).first():
        return jsonify({'success': False, 'message': f'Reseller username "{username}" is already taken'}), 400

    reseller = User(
        username=username,
        password_hash=generate_password_hash(password),
        role='reseller',
        panel_name=panel_name,
        credits=credits_val,
        is_active=True,
        is_paused=False,
        api_key=generate_user_api_key(),
        reset_portal_token=generate_portal_token(),
        duration_type='lifetime',
        activated_at=utc_now()
    )
    db.session.add(reseller)
    db.session.commit()
    log_action(f'Created Reseller: {username} (Credits: {credits_val}, Panel: {panel_name})', actor_id=current_user.id)

    return jsonify({
        'success': True,
        'message': f'Reseller "{username}" created successfully with {credits_val} credits!',
        'reseller_id': reseller.id
    })


@app.route('/admin/api/resellers/<int:rid>/toggle-pause', methods=['POST'])
@login_required
@admin_required
def admin_toggle_pause_reseller(rid):
    reseller = db.session.get(User, rid)
    if not reseller or reseller.role != 'reseller':
        return jsonify({'success': False, 'message': 'Reseller not found'}), 404

    reseller.is_paused = not reseller.is_paused
    status_str = 'Paused' if reseller.is_paused else 'Resumed (Active)'
    db.session.commit()
    log_action(f'Reseller {reseller.username} {status_str}', actor_id=current_user.id)

    return jsonify({
        'success': True,
        'message': f'Reseller "{reseller.username}" is now {status_str}. (All created users paused={reseller.is_paused})',
        'is_paused': reseller.is_paused
    })


@app.route('/admin/api/resellers/<int:rid>/credits', methods=['POST'])
@login_required
@admin_required
def admin_adjust_reseller_credits(rid):
    reseller = db.session.get(User, rid)
    if not reseller or reseller.role != 'reseller':
        return jsonify({'success': False, 'message': 'Reseller not found'}), 404

    data = request.get_json() or {}
    action = data.get('action', 'add')
    amount = int(data.get('amount') or 0)

    if amount <= 0:
        return jsonify({'success': False, 'message': 'Please enter a positive amount'}), 400

    if action == 'add':
        reseller.credits = (reseller.credits or 0) + amount
        msg = f'Added {amount} credits to "{reseller.username}". New Balance: {reseller.credits}'
    else:
        reseller.credits = max(0, (reseller.credits or 0) - amount)
        msg = f'Removed {amount} credits from "{reseller.username}". New Balance: {reseller.credits}'

    db.session.commit()
    log_action(msg, actor_id=current_user.id)

    return jsonify({'success': True, 'message': msg, 'credits': reseller.credits})


@app.route('/admin/api/resellers/<int:rid>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_reseller(rid):
    reseller = db.session.get(User, rid)
    if not reseller or reseller.role != 'reseller':
        return jsonify({'success': False, 'message': 'Reseller not found'}), 404

    name = reseller.username
    User.query.filter_by(created_by_id=rid).delete()
    LicenseKey.query.filter_by(created_by_id=rid).delete()
    ResetToken.query.filter_by(user_id=rid).delete()
    db.session.delete(reseller)
    db.session.commit()
    log_action(f'Deleted Reseller: {name}', actor_id=current_user.id)

    return jsonify({'success': True, 'message': f'Reseller "{name}" and all their client users have been deleted.'})


# --- Admin Users CRUD ---

@app.route('/admin/api/users', methods=['GET'])
@login_required
@admin_required
def admin_list_users():
    users = User.query.filter_by(role='client').order_by(User.created_at.desc()).all()
    out = []
    for u in users:
        lic = LicenseKey.query.filter_by(user_id=u.id, status='active').first()
        creator = db.session.get(User, u.created_by_id) if u.created_by_id else None
        out.append({
            'id': u.id,
            'username': u.username,
            'is_active': u.is_active,
            'is_activated': u.is_activated,
            'is_expired': u.is_expired,
            'status_label': u.status_label,
            'expires_at': u.expires_at.strftime('%Y-%m-%d %H:%M') if u.expires_at else ('Lifetime' if u.duration_type == 'lifetime' else 'Starts on 1st login'),
            'time_left': u.time_left,
            'hwid': u.hwid or 'Not Bound',
            'api_key': u.api_key or 'None',
            'created_by': creator.username if creator else 'Admin',
            'created_at': u.created_at.strftime('%Y-%m-%d'),
            'license_key': lic.key if lic else None
        })
    return jsonify(out)


@app.route('/admin/api/users', methods=['POST'])
@login_required
@admin_required
def admin_create_user():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    duration_type = data.get('duration_type', '30d')
    custom_duration = data.get('custom_duration', '')

    if not username:
        return jsonify({'success': False, 'message': 'Username is required.'})
    if not password:
        return jsonify({'success': False, 'message': 'Password is required.'})

    if User.query.filter_by(created_by_id=current_user.id, username=username).first():
        return jsonify({'success': False, 'message': f'Username "{username}" already exists in admin pool.'})

    days, fixed_expiry = parse_duration_type(duration_type, custom_duration)

    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role='client',
        is_active=True,
        api_key=generate_user_api_key(),
        duration_type=duration_type,
        duration_days=days,
        activated_at=None,
        expires_at=fixed_expiry,
        hwid=None,
        created_by_id=current_user.id
    )
    db.session.add(user)
    db.session.commit()
    log_action(f'Created App User: {username} ({user.time_left})', actor_id=current_user.id)
    return jsonify({
        'success': True,
        'message': f'User "{username}" created ({user.time_left}).',
        'user_id': user.id
    })


@app.route('/admin/api/users/<int:uid>', methods=['PUT'])
@login_required
@admin_required
def admin_update_user(uid):
    user = db.session.get(User, uid)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    if user.role == 'admin':
        return jsonify({'success': False, 'message': 'Cannot edit admin account via this endpoint.'})
    data = request.get_json() or {}

    new_username = data.get('username', '').strip()
    if new_username and new_username != user.username:
        user.username = new_username

    if data.get('password'):
        user.password_hash = generate_password_hash(data['password'])

    if 'is_active' in data:
        user.is_active = bool(data['is_active'])

    if 'duration_type' in data:
        days, fixed_expiry = parse_duration_type(data['duration_type'], data.get('custom_duration'))
        user.duration_type = data['duration_type']
        user.duration_days = days
        if user.is_activated and days:
            user.expires_at = utc_now() + datetime.timedelta(days=days)
        else:
            user.expires_at = fixed_expiry

    if data.get('reset_hwid'):
        user.hwid = None
        user.activated_at = None
        user.expires_at = None

    db.session.commit()
    log_action(f'Updated user: {user.username}', actor_id=current_user.id)
    return jsonify({'success': True, 'message': f'User "{user.username}" updated successfully.'})


@app.route('/admin/api/users/<int:uid>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_user(uid):
    user = db.session.get(User, uid)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    if user.role == 'admin':
        return jsonify({'success': False, 'message': 'Cannot delete admin user.'})
    name = user.username
    LicenseKey.query.filter_by(user_id=uid).delete()
    ResetToken.query.filter_by(user_id=uid).delete()
    db.session.delete(user)
    db.session.commit()
    log_action(f'Deleted user: {name}', actor_id=current_user.id)
    return jsonify({'success': True, 'message': f'User "{name}" deleted.'})


# --- Admin Licenses CRUD ---

@app.route('/admin/api/licenses', methods=['GET'])
@login_required
@admin_required
def admin_list_licenses():
    licenses = LicenseKey.query.order_by(LicenseKey.created_at.desc()).all()
    out = []
    for lic in licenses:
        out.append({
            'id': lic.id,
            'key': lic.key,
            'status': lic.display_status,
            'is_activated': lic.is_activated,
            'is_expired': lic.is_expired,
            'time_left': lic.time_left,
            'expires_at': lic.expires_at.strftime('%Y-%m-%d %H:%M') if lic.expires_at else ('Lifetime' if lic.duration_type == 'lifetime' else 'Starts on 1st use'),
            'hwid': lic.hwid or 'Not Bound',
            'created_at': lic.created_at.strftime('%Y-%m-%d')
        })
    return jsonify(out)


@app.route('/admin/api/licenses', methods=['POST'])
@login_required
@admin_required
def admin_create_license():
    data = request.get_json() or {}
    custom_key = data.get('custom_key', '').strip()
    duration_type = data.get('duration_type', '30d')
    custom_val = data.get('custom_duration', '')
    days, fixed_expiry = parse_duration_type(duration_type, custom_val)

    if custom_key:
        key = custom_key
    else:
        key = generate_license_key()

    lic = LicenseKey(
        key=key,
        status='unused',
        duration_type=duration_type,
        duration_days=days,
        activated_at=None,
        expires_at=fixed_expiry,
        hwid=None,
        created_by_id=current_user.id
    )
    db.session.add(lic)
    db.session.commit()
    log_action(f'Created license key: {key} ({lic.time_left})', actor_id=current_user.id)
    return jsonify({'success': True, 'message': f'License key "{key}" created ({lic.time_left}).', 'key': key})


@app.route('/admin/api/licenses/<int:lid>', methods=['PUT'])
@login_required
@admin_required
def admin_update_license(lid):
    lic = db.session.get(LicenseKey, lid)
    if not lic:
        return jsonify({'success': False, 'message': 'License key not found.'}), 404
    data = request.get_json() or {}

    new_key = data.get('key', '').strip()
    if new_key:
        lic.key = new_key

    if 'status' in data:
        lic.status = data['status']
    if 'duration_type' in data:
        days, fixed_expiry = parse_duration_type(data['duration_type'], data.get('custom_duration'))
        lic.duration_type = data['duration_type']
        lic.duration_days = days
        if lic.is_activated and days:
            lic.expires_at = utc_now() + datetime.timedelta(days=days)
        else:
            lic.expires_at = fixed_expiry

    if data.get('reset_hwid'):
        lic.hwid = None
        lic.activated_at = None
        lic.expires_at = None
        lic.status = 'unused'

    db.session.commit()
    log_action(f'Updated license: {lic.key}', actor_id=current_user.id)
    return jsonify({'success': True, 'message': f'License "{lic.key}" updated successfully.'})


@app.route('/admin/api/licenses/<int:lid>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_license(lid):
    lic = db.session.get(LicenseKey, lid)
    if not lic:
        return jsonify({'success': False, 'message': 'License key not found.'}), 404
    key = lic.key
    db.session.delete(lic)
    db.session.commit()
    log_action(f'Deleted license: {key}', actor_id=current_user.id)
    return jsonify({'success': True, 'message': f'License key "{key}" deleted.'})


# --- Admin API Docs ---

@app.route('/admin/api/docs', methods=['GET'])
@login_required
@admin_required
def admin_get_docs():
    doc = ApiDoc.query.first()
    if doc:
        return jsonify({'id': doc.id, 'title': doc.title, 'content': doc.content,
                        'updated_at': doc.updated_at.strftime('%Y-%m-%d %H:%M')})
    return jsonify({'id': None, 'title': '', 'content': ''})


@app.route('/admin/api/docs', methods=['POST'])
@login_required
@admin_required
def admin_update_docs():
    data = request.get_json() or {}
    doc = ApiDoc.query.first()
    if doc:
        doc.title = data.get('title', doc.title)
        doc.content = data.get('content', doc.content)
        doc.updated_at = utc_now()
    else:
        doc = ApiDoc(title=data.get('title', 'API Docs'),
                     content=data.get('content', ''))
        db.session.add(doc)
    db.session.commit()
    log_action('Updated API docs', actor_id=current_user.id)
    return jsonify({'success': True, 'message': 'API documentation saved.'})


# --- Admin Reset User ---

@app.route('/admin/api/reset-user', methods=['POST'])
@login_required
@admin_required
def admin_reset_user():
    data = request.get_json() or {}
    uid = data.get('user_id')
    action = data.get('action')

    user = db.session.get(User, uid)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'})

    extra = {}
    if action == 'password':
        pwd = data.get('new_password', '')
        if not pwd:
            return jsonify({'success': False, 'message': 'Password cannot be empty.'})
        user.password_hash = generate_password_hash(pwd)
        db.session.commit()
        extra['message'] = f'Password reset for "{user.username}".'

    elif action == 'duration':
        duration_type = data.get('duration_type', '30d')
        custom_val = data.get('custom_duration', '')
        days, fixed_expiry = parse_duration_type(duration_type, custom_val)
        user.duration_type = duration_type
        user.duration_days = days
        if user.is_activated and days:
            user.expires_at = utc_now() + datetime.timedelta(days=days)
        else:
            user.expires_at = fixed_expiry
        db.session.commit()
        extra['message'] = f'Duration updated for "{user.username}": {user.time_left}'

    elif action == 'hwid':
        user.hwid = None
        user.activated_at = None
        user.expires_at = None
        db.session.commit()
        extra['message'] = f'HWID lock & activation reset for "{user.username}". Timer will restart on next EXE login.'

    elif action == 'token':
        ResetToken.query.filter_by(user_id=uid, used=False).update({'used': True})
        db.session.commit()
        token = generate_reset_token()
        expiry = utc_now() + datetime.timedelta(hours=24)
        rt = ResetToken(user_id=uid, token=token, expires_at=expiry)
        db.session.add(rt)
        db.session.commit()
        reset_url = url_for('use_reset_token', token=token, _external=True)
        extra['message'] = f'Reset token generated for "{user.username}".'
        extra['reset_url'] = reset_url

    else:
        return jsonify({'success': False, 'message': 'Unknown action.'})

    log_action(f'Admin reset [{action}] for user: {user.username}', actor_id=current_user.id)
    return jsonify({'success': True, **extra})


# --- Admin Helper: users list for dropdowns ---

@app.route('/admin/api/users-list')
@login_required
@admin_required
def admin_users_list():
    users = User.query.filter_by(role='client').order_by(User.username).all()
    return jsonify([{'id': u.id, 'username': u.username, 'time_left': u.time_left} for u in users])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    app.run(host='0.0.0.0', port=port, debug=False)
