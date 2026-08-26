import secrets
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timezone

db = SQLAlchemy()


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def generate_user_api_key():
    return f"AUTH-API-{secrets.token_hex(16).upper()}"


def generate_portal_token():
    return secrets.token_hex(12)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)  # Multi-tenant: isolated per reseller
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='client')  # 'admin', 'reseller', 'client'
    panel_name = db.Column(db.String(255), nullable=True)  # For Reseller (e.g. "Alpha Store VIP")
    credits = db.Column(db.Integer, default=0)  # Reseller Credits balance
    is_active = db.Column(db.Boolean, default=True)
    is_paused = db.Column(db.Boolean, default=False)  # Reseller pause flag
    api_key = db.Column(db.String(100), unique=True, nullable=True)  # Reseller API Key
    reset_portal_token = db.Column(db.String(100), unique=True, nullable=True)  # Reseller's Public HWID Reset Portal Link
    duration_type = db.Column(db.String(50), default='30d')  # 'lifetime', '1d', '7d', '30d', etc.
    duration_days = db.Column(db.Float, nullable=True)  # Days countdown
    activated_at = db.Column(db.DateTime, nullable=True)  # Timestamp when first logged in from EXE
    expires_at = db.Column(db.DateTime, nullable=True)  # Exact expiry (calculated at activation)
    hwid = db.Column(db.String(255), nullable=True)  # Hardware ID locked on first EXE login
    sid = db.Column(db.String(255), nullable=True)   # Security Identifier (SID) locked on first EXE login
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Reseller creator
    created_at = db.Column(db.DateTime, default=utc_now)
    
    licenses = db.relationship('LicenseKey', backref='user', lazy=True,
                               foreign_keys='LicenseKey.user_id')
    reset_tokens = db.relationship('ResetToken', backref='user', lazy=True)

    def get_id(self):
        return str(self.id)

    @property
    def is_reseller_paused(self):
        """Returns True if the creator reseller is paused"""
        if self.created_by_id:
            parent = db.session.get(User, self.created_by_id)
            if parent and parent.is_paused:
                return True
        return False

    @property
    def is_activated(self):
        return self.activated_at is not None

    @property
    def is_expired(self):
        if self.role in ['admin', 'reseller']:
            return False
        if self.duration_type == 'lifetime' or (self.expires_at is None and not self.is_activated):
            return False
        if self.expires_at is None:
            return False
        return utc_now() > self.expires_at

    @property
    def time_left(self):
        if self.role in ['admin', 'reseller'] or self.duration_type == 'lifetime':
            return 'Lifetime'
        if not self.is_activated:
            days_str = f'{int(self.duration_days)}d' if self.duration_days else (self.duration_type or 'Custom')
            return f'Unused ({days_str} starts on 1st login)'
        now = utc_now()
        if self.expires_at and now > self.expires_at:
            return 'Expired'
        if self.expires_at:
            delta = self.expires_at - now
            if delta.days > 0:
                return f'{delta.days}d {delta.seconds // 3600}h left'
            elif delta.seconds >= 3600:
                return f'{delta.seconds // 3600}h {(delta.seconds % 3600) // 60}m left'
            else:
                return f'{max(1, delta.seconds // 60)}m left'
        return 'Not Activated'

    @property
    def status_label(self):
        if self.is_paused:
            return 'Paused'
        if not self.is_active:
            return 'Disabled'
        if self.is_reseller_paused:
            return 'Paused (Reseller)'
        if self.is_expired:
            return 'Expired'
        if not self.is_activated and self.role == 'client':
            return 'Unused (Pending Login)'
        return 'Active'


class LicenseKey(db.Model):
    __tablename__ = 'license_keys'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(255), nullable=False)  # Multi-tenant: can exist per reseller
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    status = db.Column(db.String(20), default='unused')  # 'unused' / 'active' / 'expired' / 'revoked'
    duration_type = db.Column(db.String(50), default='30d')
    duration_days = db.Column(db.Float, nullable=True)  # Days countdown
    activated_at = db.Column(db.DateTime, nullable=True)  # Timestamp when first used in EXE
    expires_at = db.Column(db.DateTime, nullable=True)  # Calculated when activated
    hwid = db.Column(db.String(255), nullable=True)  # Hardware ID locked on first activation
    sid = db.Column(db.String(255), nullable=True)   # Security Identifier (SID) locked on first activation
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Reseller creator
    created_at = db.Column(db.DateTime, default=utc_now)
    notes = db.Column(db.String(512), nullable=True)

    @property
    def is_reseller_paused(self):
        if self.created_by_id:
            parent = db.session.get(User, self.created_by_id)
            if parent and parent.is_paused:
                return True
        return False

    @property
    def is_activated(self):
        return self.activated_at is not None

    @property
    def is_expired(self):
        if self.duration_type == 'lifetime' or (self.expires_at is None and not self.is_activated):
            return False
        if self.expires_at is None:
            return False
        return utc_now() > self.expires_at

    @property
    def time_left(self):
        if self.duration_type == 'lifetime':
            return 'Lifetime'
        if not self.is_activated:
            days_str = f'{int(self.duration_days)}d' if self.duration_days else (self.duration_type or 'Custom')
            return f'Unused ({days_str} starts on 1st use)'
        now = utc_now()
        if self.expires_at and now > self.expires_at:
            return 'Expired'
        if self.expires_at:
            delta = self.expires_at - now
            if delta.days > 0:
                return f'{delta.days}d {delta.seconds // 3600}h left'
            elif delta.seconds >= 3600:
                return f'{delta.seconds // 3600}h {(delta.seconds % 3600) // 60}m left'
            else:
                return f'{max(1, delta.seconds // 60)}m left'
        return 'Not Activated'

    @property
    def display_status(self):
        if self.status == 'revoked':
            return 'Revoked'
        if self.is_reseller_paused:
            return 'Paused (Reseller)'
        if self.is_expired:
            return 'Expired'
        if not self.is_activated:
            return 'Unused'
        return 'Active'


class ApiDoc(db.Model):
    __tablename__ = 'api_docs'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now)


class ResetToken(db.Model):
    __tablename__ = 'reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(120), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=utc_now)


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(300), nullable=False)
    actor_id = db.Column(db.Integer, nullable=True)
    timestamp = db.Column(db.DateTime, default=utc_now)
    details = db.Column(db.Text, nullable=True)
