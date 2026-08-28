import csv
import hashlib
import io
import json
import os
import secrets
import smtplib
import string
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from email.message import EmailMessage
from functools import wraps

import pyotp
import qrcode
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
    abort, Response, jsonify, g,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image as RLImage, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "rgc-dev-secret-key-change-me")

# --- Database: Postgres in production, SQLite fallback for local dev -------
# Render's managed Postgres add-on injects DATABASE_URL automatically once
# the database is attached to this service. Locally, if you don't set
# DATABASE_URL, it falls back to a SQLite file next to app.py so `python
# app.py` still works with zero setup.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "rgc.db"))
if DATABASE_URL.startswith("postgres://"):
    # SQLAlchemy 1.4+ requires the "postgresql://" scheme; Render (and Heroku)
    # hand back the older "postgres://" form.
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# Without this, SQLAlchemy will hand out a pooled connection without
# checking it's still alive first. Managed Postgres providers (and some
# local setups) silently drop idle connections after a while, so a
# connection that's sat unused in the pool can come back corrupted --
# symptom: random "SSL error: decryption failed or bad record mac" on
# totally unrelated queries. pool_pre_ping runs a cheap check before each
# checkout and transparently reconnects if needed; pool_recycle proactively
# retires connections before they get that old in the first place.
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 280,
}
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB uploads

# Keeps the admin logged in across visits — the browser holds a signed
# session cookie for 30 days instead of just until it's closed, so the
# owner stays logged in site-wide without re-entering credentials each time.
# (This requires SECRET_KEY to stay the same across restarts/deploys — see
# the note below.)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

# The owner's admin login. Change both before deploying — these defaults
# only exist so the admin panel works out of the box for local testing.
# IMPORTANT: also set a real SECRET_KEY (any long random string) and keep
# it the SAME value across restarts/deploys. The session cookie is signed
# with SECRET_KEY, so if it changes, every logged-in admin session
# (including this 30-day one) is invalidated and everyone gets logged out.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")

# --- A second, FULL admin login (e.g. a co-owner or manager) ---------------
# Unset by default (both env vars blank) — this login doesn't exist at all
# until you set BOTH ADMIN2_USERNAME and ADMIN2_PASSWORD. There's no
# insecure default like ADMIN_PASSWORD's "changeme123" here on purpose: a
# second admin door should never be open unless someone deliberately opened
# it. Once configured, this account has the exact same access as the owner
# login above — everything, including Orders/Invoices/Mailbox/Pickups/
# Subscribers/Users (see ADMIN_ACCOUNTS' "full_access" below). It gets its
# own separate two-factor enrollment, same as every other account here.
ADMIN2_USERNAME = os.environ.get("ADMIN2_USERNAME", "")
ADMIN2_PASSWORD = os.environ.get("ADMIN2_PASSWORD", "")

# --- A third, RESTRICTED login for whoever maintains the site (developer/
# technical support), separate from the two full-access accounts above ----
# Unset by default (both env vars blank) — this login doesn't exist at all
# until you set BOTH CREATOR_USERNAME and CREATOR_PASSWORD.
#
# This account can do everything technical/content-related (Updates,
# Products, Pages, Settings — including its own two-factor setup) but is
# refused, both on the website and in the RGC Manager app, at anything
# touching customers or money: Orders, Invoices, Mailbox, Pickups,
# Subscribers. See owner_required/api_owner_required below and
# ADMIN_SECTIONS' role_required field for exactly where that line is drawn.
# If you ever want this account to see everything the owner does, just add
# it to ADMIN_ROLES_FULL_ACCESS below instead of removing the check.
CREATOR_USERNAME = os.environ.get("CREATOR_USERNAME", "")
CREATOR_PASSWORD = os.environ.get("CREATOR_PASSWORD", "")

# Central registry of every admin login this app recognizes: identity ->
# username/password/display label/full-access flag. _match_admin_credentials,
# ADMIN_ROLES_FULL_ACCESS, and every other place that used to hardcode
# "owner" vs. "creator" now key off this instead, so adding another login
# later (or changing who has full access) is a one-line change here, not a
# hunt through the file. An account with a blank username/password (the
# default for ADMIN2_* and CREATOR_*) simply doesn't match any login attempt
# — see _match_admin_credentials.
ADMIN_ACCOUNTS = {
    "owner": {
        "username": ADMIN_USERNAME, "password": ADMIN_PASSWORD,
        "label": "Owner", "full_access": True,
    },
    "admin2": {
        "username": ADMIN2_USERNAME, "password": ADMIN2_PASSWORD,
        "label": "Admin 2", "full_access": True,
    },
    "creator": {
        "username": CREATOR_USERNAME, "password": CREATOR_PASSWORD,
        "label": "Creator", "full_access": False,
    },
}


def _match_admin_credentials(username, password):
    """Checks `username`/`password` against every configured account in
    ADMIN_ACCOUNTS and returns the identity string of whichever one
    matched, or None if neither did (or if `username`/`password` are
    blank — a blank ADMIN2_USERNAME/CREATOR_USERNAME means that slot isn't
    configured at all, never "log in with an empty username"). That
    identity is what everything else in this file keys off of:
    session["admin_identity"] / the "id" claim in the mobile token (see
    admin_login/api_login below), which account's MFA Setting rows apply
    (see verify_mfa_code and friends), and which routes are allowed (see
    owner_required/api_owner_required)."""
    if not username or not password:
        return None
    for identity, account in ADMIN_ACCOUNTS.items():
        acct_username, acct_password = account["username"], account["password"]
        if not acct_username or not acct_password:
            continue  # this login slot isn't configured
        if secrets.compare_digest(username, acct_username) and secrets.compare_digest(password, acct_password):
            return identity
    return None


# Identities allowed past owner_required/api_owner_required, i.e. allowed to
# touch Orders/Invoices/Mailbox/Pickups/Subscribers/Users — every identity
# in ADMIN_ACCOUNTS flagged "full_access": True (owner and admin2 by
# default). Add "creator" to ADMIN_ACCOUNTS' "full_access" instead of
# editing this line if you'd rather that account have full access too.
ADMIN_ROLES_FULL_ACCESS = {
    identity for identity, account in ADMIN_ACCOUNTS.items() if account["full_access"]
}

# --- Two-factor authentication (TOTP), optional -----------------------------
# Off by default — nothing changes for any account until it turns MFA on
# from its own Admin > Site Settings. Once enabled for an account it's
# required on BOTH the web login (/admin/login) and the mobile app login
# (/api/v1/login) for that account specifically.
#
# State lives in the Setting key/value table (see the Setting model), not an
# env var like ADMIN_PASSWORD, because it needs to be turned on/off — and the
# secret regenerated — from the admin UI without a server restart or
# redeploy. Every key below is namespaced by admin identity (one of the keys
# in ADMIN_ACCOUNTS — "owner", "admin2", "creator" — see
# _match_admin_credentials) so each configured account enrolls its own
# authenticator app and never sees another account's codes:
#   mfa_enabled:<identity>               "1" once enrollment is confirmed
#                                         with a real code, unset otherwise
#   mfa_totp_secret:<identity>           the ACTIVE base32 TOTP secret for
#                                         that identity; only read by the
#                                         login routes once ...enabled is "1"
#   mfa_totp_secret_pending:<identity>   a freshly generated secret sitting
#                                         in that account's Settings > 2FA
#                                         setup, waiting to be confirmed with
#                                         a code before it becomes
#                                         ...totp_secret (see
#                                         admin_settings_mfa_setup)
#   mfa_backup_codes:<identity>          JSON list of {"hash": <sha256 hex>,
#                                         "used": bool} — that identity's
#                                         one-time recovery codes, shown once
#                                         at enrollment (see
#                                         generate_backup_codes)
#
# LOCKOUT RECOVERY: there's no "forgot your code" flow for any admin
# account. If one of them loses their authenticator app AND their backup
# codes, the only way back in is direct database access — connect to the DB
# (see deploy/) and run, e.g. for the owner:
#   UPDATE setting SET value = '0' WHERE key = 'mfa_enabled:owner';
# (substitute 'mfa_enabled:admin2' or 'mfa_enabled:creator' for the other
# accounts; or just delete the row). That's the exact same trust model as
# forgetting ADMIN_PASSWORD, ADMIN2_PASSWORD, or CREATOR_PASSWORD, just one
# row over.

# --- Mobile app API (companion Android manager app) -------------------------
# The Android app doesn't use the browser session cookie above — it signs in
# once against /api/v1/login and gets back a signed token (itsdangerous,
# using the same SECRET_KEY as everything else) to send as
# "Authorization: Bearer <token>" on every request after that. There's still
# only one admin account, so this token just proves "this request was signed
# with our SECRET_KEY within the last MOBILE_TOKEN_MAX_AGE_SECONDS" — same
# trust model as the session cookie, just usable outside a browser.
MOBILE_TOKEN_MAX_AGE_SECONDS = int(
    os.environ.get("MOBILE_TOKEN_MAX_AGE_DAYS", "180")
) * 24 * 60 * 60
_mobile_token_serializer = URLSafeTimedSerializer(app.secret_key, salt="rgc-mobile-api-token")

# --- Customer "forgot password" reset links ----------------------------------
# A reset link's token embeds the account id and a short slice of its
# CURRENT password hash. That means once the link is used (or the customer
# changes their password some other way), every previously-issued link for
# that account stops working on its own -- there's no separate "used"
# flag to track. Links expire after PASSWORD_RESET_MAX_AGE_SECONDS either
# way. Sent by email via _send_email, same SMTP plumbing as everything else.
PASSWORD_RESET_MAX_AGE_SECONDS = 60 * 60  # 1 hour
_password_reset_serializer = URLSafeTimedSerializer(app.secret_key, salt="rgc-customer-password-reset")

# --- "Sign in with Google" for the customer portal ---------------------------
# Off by default — the login page's Google button only shows up once BOTH
# GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set. Get these from a
# project in the Google Cloud Console (APIs & Services > Credentials >
# OAuth client ID, type "Web application"), with this exact redirect URI
# authorized: <your site's base URL>/customer/login/google/callback
# (e.g. https://rgcdoortodoorboxservices.ca/customer/login/google/callback).
#
# This uses plain OAuth 2.0 "authorization code" flow by hand (urllib, no
# extra dependency) rather than verifying a signed ID token: after Google
# redirects back with a one-time `code`, customer_login_google_callback
# exchanges it server-to-server for an access token, then calls Google's
# userinfo endpoint with that token to get the person's email/name. Google
# itself is what authenticated them; we never see or store a password.
#
# First-time sign-in creates a new CustomerUser (role "customer", a random
# unusable password so "forgot password" can still recover the account
# later if they ever want email/password login too) with
# needs_profile_details=True, which forces them through
# customer_complete_profile (phone + address) before anything else — see
# enforce_customer_page_restrictions. Matching an EXISTING account is by
# email only (same lookup a normal login uses); google_id is just a record
# of how the account was created, not a separate lookup key.
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_OAUTH_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_OAUTH_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


def google_signin_enabled():
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


db = SQLAlchemy(app)

# --- File storage: local disk ------------------------------------------------
# Uploaded images (post photos, product photos, the site favicon) are saved
# straight into this app's own static/ folder and served like any other
# static file. This app is meant to run on a server you control end to end,
# so the disk is always there between restarts — no cloud object storage
# (Cloudflare R2, S3, etc.) needed. Files live under static/<prefix>/, e.g.
# static/uploads/<uuid>.png or static/branding/<uuid>.ico.

COMPANY = {
    "name": "RGC Door-to-Door Box Express Services",
    "tagline": "Door-to-Door Box Express Service to the Philippines",
    "location": "Whitchurch-Stouffville, ON, Canada",
    "email": "rgcparcelexpress@gmail.com",
    "contact_email": "info@rgcdoortodoorboxservices.ca",
    "areas": ["METRO MANILA (NCR)", "LUZON", "VISAYAS", "MINDANAO"],
}

# --- Outbound email (Microsoft 365 SMTP) --------------------------------
# Contact-form, pickup-request, order, and admin-Mailbox-reply emails are
# sent by authenticating directly as the info@rgcdoortodoorboxservices.ca
# mailbox over SMTP. Sending and reading/replying by hand both live on
# Microsoft 365 now — no third-party relay involved.
#
# SMTP_USERNAME is the mailbox's own sign-in address (defaults to the
# company's contact email). SMTP_PASSWORD is that mailbox's sign-in
# password. CONTACT_RECIPIENT_EMAIL defaults to the company's
# contact_email above if not set separately.
#
# If SMTP_PASSWORD isn't set, sending is simply skipped — the contact form
# still works and shows its confirmation message, it just won't actually
# deliver anywhere. Handy for local dev; set it in production.
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.office365.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", COMPANY["contact_email"])
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
CONTACT_RECIPIENT_EMAIL = os.environ.get("CONTACT_RECIPIENT_EMAIL", COMPANY["contact_email"])


def _send_email(to_email, subject, body, reply_to=None):
    """Low-level send shared by the contact form and the admin Mailbox.

    Returns True if Microsoft 365 accepted it, False otherwise (not
    configured, or the send failed) — either way the reason is logged, and
    this never raises, so a flaky SMTP call never 500s a page.
    """
    if not SMTP_PASSWORD:
        app.logger.warning(
            "Tried to send an email to %s but SMTP_PASSWORD isn't set, "
            "so nothing was sent.", to_email,
        )
        return False

    msg = EmailMessage()
    msg["From"] = f"{COMPANY['name']} <{SMTP_USERNAME}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)
    if reply_to:
        msg["Reply-To"] = reply_to

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except smtplib.SMTPException as exc:
        app.logger.error("Microsoft 365 rejected an email to %s: %s", to_email, exc)
        return False
    except OSError as exc:
        app.logger.error("Failed to send email to %s via SMTP: %s", to_email, exc)
        return False


def send_contact_email(name, email, message):
    """Email a contact-form submission to CONTACT_RECIPIENT_EMAIL."""
    return _send_email(
        to_email=CONTACT_RECIPIENT_EMAIL,
        subject=f"New contact form message from {name or 'website visitor'}",
        body=(
            f"Name: {name or '(not provided)'}\n"
            f"Email: {email}\n\n"
            f"Message:\n{message or '(no message provided)'}"
        ),
        reply_to=email,
    )


def send_pickup_request_email(pickup):
    """Email a new Book a Pick Up submission to CONTACT_RECIPIENT_EMAIL."""
    return _send_email(
        to_email=CONTACT_RECIPIENT_EMAIL,
        subject=f"New pickup request from {pickup.name}",
        body=(
            f"Name: {pickup.name}\n"
            f"Email: {pickup.email}\n"
            f"Phone: {pickup.phone}\n"
            f"Pickup address: {pickup.address}\n"
            f"Preferred date: {pickup.pickup_date.strftime('%B %d, %Y')}\n"
            f"Preferred time: {pickup.time_window}\n"
            f"Number of boxes: {pickup.box_count or '(not specified)'}\n\n"
            f"Notes:\n{pickup.notes or '(none)'}"
        ),
        reply_to=pickup.email,
    )


def send_pickup_confirmation_to_customer(pickup):
    """Send the customer a confirmation that their pickup request was received."""
    notes_line = f"  Notes:    {pickup.notes}\n" if pickup.notes else ""
    return _send_email(
        to_email=pickup.email,
        subject=f"Your Pickup Request — {pickup.pickup_date.strftime('%B %d, %Y')}",
        body=(
            f"Hi {pickup.name},\n\n"
            f"Thanks for booking a pickup with {COMPANY['name']}! Here are your request details:\n\n"
            f"  Date:     {pickup.pickup_date.strftime('%B %d, %Y')}\n"
            f"  Time:     {pickup.time_window}\n"
            f"  Address:  {pickup.address}\n"
            f"  Boxes:    {pickup.box_count or '(not specified)'}\n"
            f"{notes_line}"
            f"\nWe'll review your request and be in touch to confirm the details shortly.\n\n"
            f"If you have any questions, reply to this email or reach us at "
            f"{CONTACT_RECIPIENT_EMAIL}.\n\n"
            f"{COMPANY['name']}"
        ),
        reply_to=CONTACT_RECIPIENT_EMAIL,
    )


def send_pickup_status_email(pickup):
    """Notify the customer that their pickup status has changed."""
    status_messages = {
        "Confirmed": (
            f"Great news! Your pickup scheduled for "
            f"{pickup.pickup_date.strftime('%B %d, %Y')} ({pickup.time_window}) "
            f"at {pickup.address} has been confirmed. We'll see you then!"
        ),
        "Picked Up": (
            f"Your pickup on {pickup.pickup_date.strftime('%B %d, %Y')} "
            f"has been marked as completed. Thank you for choosing {COMPANY['name']}!"
        ),
        "Cancelled": (
            f"Your pickup request for {pickup.pickup_date.strftime('%B %d, %Y')} "
            f"has been cancelled. If this was unexpected or you have questions, please "
            f"reply to this email or contact us at {CONTACT_RECIPIENT_EMAIL}."
        ),
    }
    detail = status_messages.get(
        pickup.status,
        f"Your pickup request status has been updated to: {pickup.status}."
    )
    return _send_email(
        to_email=pickup.email,
        subject=f"Pickup Update — {pickup.status} | {COMPANY['name']}",
        body=(
            f"Hi {pickup.name},\n\n"
            f"{detail}\n\n"
            f"Pickup details:\n"
            f"  Date:     {pickup.pickup_date.strftime('%B %d, %Y')}\n"
            f"  Time:     {pickup.time_window}\n"
            f"  Address:  {pickup.address}\n\n"
            f"Questions? Reply to this email or reach us at {CONTACT_RECIPIENT_EMAIL}.\n\n"
            f"{COMPANY['name']}"
        ),
        reply_to=CONTACT_RECIPIENT_EMAIL,
    )


def send_order_status_email(order):
    """Notify the customer that their order status has changed."""
    status_messages = {
        "Paid": (
            f"We've received your payment for order {order.order_number}. "
            f"We'll start preparing your order right away!"
        ),
        "Fulfilled": (
            f"Your order {order.order_number} has been fulfilled and is on its way. "
            f"Thank you for shopping with {COMPANY['name']}!"
        ),
        "Cancelled": (
            f"Your order {order.order_number} has been cancelled. "
            f"If this was unexpected or you have questions, please reply to this email "
            f"or contact us at {CONTACT_RECIPIENT_EMAIL}."
        ),
    }
    detail = status_messages.get(
        order.status,
        f"Your order {order.order_number} status has been updated to: {order.status}."
    )
    item_lines = "\n".join(
        f"  {item.quantity} x {item.product_name} — ${item.subtotal:.2f}"
        for item in order.items
    )
    return _send_email(
        to_email=order.customer_email,
        subject=f"Order Update — {order.status} | {order.order_number}",
        body=(
            f"Hi {order.customer_name},\n\n"
            f"{detail}\n\n"
            f"Order summary:\n{item_lines}\n\n"
            f"  Subtotal: ${order.subtotal:.2f}\n"
            f"  HST (13%): ${(order.tax_amount or Decimal('0.00')):.2f}\n"
            f"  Total: ${order.total:.2f} CAD\n\n"
            f"Questions? Reply to this email or reach us at {CONTACT_RECIPIENT_EMAIL}.\n\n"
            f"{COMPANY['name']}"
        ),
        reply_to=CONTACT_RECIPIENT_EMAIL,
    )


def send_registration_confirmation_email(user):
    """Welcome email sent when a customer creates an account."""
    return _send_email(
        to_email=user.email,
        subject=f"Welcome to {COMPANY['name']}!",
        body=(
            f"Hi {user.name},\n\n"
            f"Your account has been created successfully. You can now log in to track "
            f"your orders, view pickup requests, and manage your profile.\n\n"
            f"  Email: {user.email}\n\n"
            f"If you didn't create this account, please contact us at "
            f"{CONTACT_RECIPIENT_EMAIL} right away.\n\n"
            f"{COMPANY['name']}"
        ),
        reply_to=CONTACT_RECIPIENT_EMAIL,
    )

# --- Admin Mailbox (compose/reply only — no inbound mirror) -----------------
# See the MailboxMessage model for the full picture. Contact-form and
# pickup-request submissions are still saved here automatically. There's no
# live mirror of everything else sent to the real mailbox, though: that
# previously relied on Mailgun's Inbound Route parsing a copy of incoming
# mail and posting it to this app. Microsoft 365 through GoDaddy doesn't
# expose Entra ID (so no Graph API access to read the real inbox), and
# Microsoft disabled IMAP for every tenant in 2023 with no way to re-enable
# it — so there's currently no working way to mirror inbound mail without a
# third-party relay like Mailgun back in the picture.

# Canned one-tap replies for the Mailbox. Removed from the web admin
# Mailbox UI (mailbox_thread.html / mailbox_compose.html no longer render
# these) but still served to the mobile app via /api/v1/me, which pre-fills
# its own reply box with them. Never sent without the owner reviewing/
# editing and tapping Send, same as a manually typed reply.
QUICK_REPLIES = [
    ("Thanks for reaching out",
     "Thanks for reaching out! We've received your message and will get back to you shortly."),
    ("Order update",
     "Thanks for your patience — your order is being processed and we'll update you as soon as "
     "it ships."),
    ("Pricing info",
     "Thanks for your interest! For current pricing and availability, please check the Products "
     "page on our website, or let us know what you're looking for and we'll follow up with "
     "details."),
    ("Following up",
     "Just following up on this — let us know if you still need anything from us!"),
]


def _send_mailbox_reply(thread_key, to_email, subject, body):
    """Sends a reply/new message from the admin Mailbox via Microsoft 365
    SMTP (reusing the same _send_email plumbing the contact form uses) and,
    only on a successful send, saves it as an outbound MailboxMessage row so
    it shows up in the thread going forward. Returns (message_or_none, error_or_none).
    """
    sent = _send_email(
        to_email=to_email, subject=subject, body=body, reply_to=CONTACT_RECIPIENT_EMAIL,
    )
    if not sent:
        if not SMTP_PASSWORD:
            return None, "Couldn't send: Microsoft 365 isn't configured on the server (set SMTP_PASSWORD)."
        return None, "The email server rejected the message. Please try again."
    message = MailboxMessage(
        direction="outbound",
        thread_key=thread_key,
        from_name=COMPANY["name"],
        from_email=SMTP_USERNAME,
        to_email=to_email,
        subject=subject,
        body_text=body,
        is_read=True,
    )
    db.session.add(message)
    db.session.commit()
    return message, None


# --- Keep-alive (prevent Render free-tier spin-down) ------------------------
# Render's free web services spin down after 15 minutes with no inbound HTTP
# traffic, then take about a minute to cold-start on the next visit. When
# running on Render, a background thread pings this service's own public
# URL every few minutes (well under that 15-minute window) so it never goes
# quiet long enough to spin down.
#
# This turns itself on automatically — it only runs when RENDER_EXTERNAL_URL
# is present, which Render sets automatically and which never exists in
# local dev — so there's nothing to configure to use it. Set
# KEEP_ALIVE_ENABLED=false to turn it off (e.g. once you're on a paid plan
# that doesn't spin down, or if you'd rather rely on an external monitor
# like UptimeRobot pinging /healthz instead).
#
# Worth knowing: this keeps the service running around the clock, which
# uses up free-tier instance hours faster than occasional real visitors
# would, and it's a workaround rather than something Render provides — if
# you have more than one instance/worker running, each one pings
# independently, which is harmless but slightly wasteful.
KEEP_ALIVE_INTERVAL_SECONDS = int(os.environ.get("KEEP_ALIVE_INTERVAL_SECONDS", "600"))
KEEP_ALIVE_ENABLED = (
    os.environ.get("KEEP_ALIVE_ENABLED", "true").lower() not in ("false", "0", "no")
    and bool(os.environ.get("RENDER_EXTERNAL_URL"))
)


def _keep_alive_loop():
    url = os.environ.get("RENDER_EXTERNAL_URL", "").rstrip("/") + "/healthz"
    while True:
        time.sleep(KEEP_ALIVE_INTERVAL_SECONDS)
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                app.logger.info("Keep-alive ping to %s -> %s", url, resp.status)
        except Exception as exc:  # noqa: BLE001 - best-effort; never crash the app over this
            app.logger.warning("Keep-alive ping to %s failed: %s", url, exc)


if KEEP_ALIVE_ENABLED:
    threading.Thread(target=_keep_alive_loop, daemon=True).start()


SHIPMENT_STATUSES = [
    "Order Received",
    "Picked Up",
    "In Transit",
    "Arrived at Philippines Hub",
    "Customs Clearance",
    "Out for Delivery",
    "Delivered",
    "Delayed",
]

# (value, label) pairs for the product listings on the site.
PRODUCT_CATEGORIES = [
    ("packaging", "Packaging Item"),
    ("box", "Empty Box"),
    ("sari-sari", "Sari-Sari Item"),
]
PRODUCT_CATEGORY_VALUES = {value for value, _label in PRODUCT_CATEGORIES}

ORDER_STATUSES = ["Awaiting Payment", "Paid", "Fulfilled", "Cancelled"]
CART_SESSION_KEY = "cart"

# 13% HST (Ontario), applied to every cart at checkout. Kept as one constant
# so the rate is a one-line change if it ever needs updating.
HST_RATE = Decimal("0.13")


def calculate_hst(subtotal):
    """Round HST to the cent using standard half-up rounding (not banker's
    rounding), matching how tax is shown on a real receipt."""
    return (subtotal * HST_RATE).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


# --- Invoices (PDF) ----------------------------------------------------------
# Two kinds of invoice share one PDF layout and letterhead: an automatic one
# generated straight from an Order (no typing required — the order already
# has everything), and a manual one for anything outside the normal
# box/product shop that the owner types up by hand. Both invoice under this
# trade name rather than the full "RGC Door-to-Door Box Express Services"
# used on the rest of the site.
INVOICE_BUSINESS_NAME = "Sari Sari By Regueca"
INVOICE_ADDRESS = COMPANY["location"]
INVOICE_EMAIL = COMPANY["contact_email"]


def _format_invoice_quantity(quantity):
    """Render a Decimal quantity without a pointless '.00' (e.g. "2" instead
    of "2.00"), but keep a fractional part when there genuinely is one."""
    quantity = quantity.normalize()
    if quantity == quantity.to_integral_value():
        return str(quantity.to_integral_value())
    return str(quantity)


def render_invoice_pdf(invoice_number, issue_date, bill_to_lines, items, subtotal,
                        tax_label, tax_amount, total, notes=None):
    """Build a one-page invoice PDF and return it as a BytesIO buffer.

    `items` is a list of (description, quantity, unit_price, line_total)
    tuples, already formatted as display strings. `tax_label`/`tax_amount`
    may both be None to omit the tax line entirely (some manual invoices are
    for non-taxable work).
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )
    styles = getSampleStyleSheet()
    right_style = ParagraphStyle("InvoiceRightAlign", parent=styles["Normal"], alignment=TA_RIGHT)
    title_style = ParagraphStyle(
        "InvoiceTitle", parent=styles["Heading1"], fontSize=22,
        textColor=colors.HexColor("#3a5fc0"),
    )

    elements = []

    logo_path = os.path.join(app.static_folder, "images", "logo.webp")
    logo_cell = ""
    if os.path.exists(logo_path):
        try:
            logo_cell = RLImage(logo_path, width=0.85 * inch, height=0.85 * inch)
        except Exception:
            logo_cell = ""  # a broken/unreadable logo file shouldn't block the invoice

    header_info = Paragraph(
        f"<b>{INVOICE_BUSINESS_NAME}</b><br/>Address: {INVOICE_ADDRESS}<br/>Email: {INVOICE_EMAIL}",
        styles["Normal"],
    )
    header_table = Table([[logo_cell, header_info]], colWidths=[1.0 * inch, 5.4 * inch])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "LEFT"),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 18))

    meta_table = Table(
        [[
            Paragraph("INVOICE", title_style),
            Paragraph(
                f"Invoice #: {invoice_number}<br/>Date: {issue_date.strftime('%B %d, %Y')}",
                right_style,
            ),
        ]],
        colWidths=[3.4 * inch, 3.0 * inch],
    )
    meta_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    elements.append(meta_table)
    elements.append(Spacer(1, 14))

    if bill_to_lines:
        bill_to_html = "<b>Bill To:</b><br/>" + "<br/>".join(bill_to_lines)
        elements.append(Paragraph(bill_to_html, styles["Normal"]))
        elements.append(Spacer(1, 18))

    table_data = [["Description", "Qty", "Unit Price", "Amount"]]
    table_data.extend(items)

    items_table = Table(table_data, colWidths=[3.2 * inch, 0.7 * inch, 1.2 * inch, 1.3 * inch])
    items_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#507de5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("ALIGN", (0, 0), (0, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f4")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fe")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(items_table)
    elements.append(Spacer(1, 14))

    totals_rows = [["Subtotal", f"${subtotal:.2f}"]]
    if tax_label and tax_amount is not None:
        totals_rows.append([tax_label, f"${tax_amount:.2f}"])
    totals_rows.append(["Total", f"${total:.2f} CAD"])
    totals_table = Table(totals_rows, colWidths=[5.0 * inch, 1.4 * inch])
    totals_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "RIGHT"),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, -1), (-1, -1), 12),
        ("LINEABOVE", (0, -1), (-1, -1), 0.75, colors.HexColor("#1f2430")),
        ("TOPPADDING", (0, -1), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (0, -1), 14),
    ]))
    elements.append(totals_table)

    if notes:
        elements.append(Spacer(1, 20))
        elements.append(Paragraph(f"<b>Notes:</b> {notes}", styles["Normal"]))

    elements.append(Spacer(1, 28))
    elements.append(Paragraph("Thank you for your business!", styles["Normal"]))

    doc.build(elements)
    buffer.seek(0)
    return buffer


def _order_invoice_pdf_response(order):
    """Build the automatic invoice for a product Order — no typing required,
    every field comes straight from the order's own saved data."""
    bill_to = [order.customer_name]
    if order.customer_email:
        bill_to.append(order.customer_email)
    if order.customer_phone:
        bill_to.append(order.customer_phone)
    if order.shipping_address:
        bill_to.extend(line for line in order.shipping_address.splitlines() if line.strip())

    items = [
        [item.product_name, str(item.quantity), f"${item.unit_price:.2f}", f"${item.subtotal:.2f}"]
        for item in order.items
    ]
    buffer = render_invoice_pdf(
        invoice_number=order.order_number,
        issue_date=order.created_at.date(),
        bill_to_lines=bill_to,
        items=items,
        subtotal=order.subtotal,
        tax_label="HST (13%)",
        tax_amount=(order.tax_amount if order.tax_amount is not None else Decimal("0.00")),
        total=order.total,
        notes=(
            f"Payment: Interac e-Transfer to {COMPANY['contact_email']}, "
            f"referencing order {order.order_number}."
        ),
    )
    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f'inline; filename="invoice-{order.order_number}.pdf"'},
    )


def _manual_invoice_pdf_response(invoice):
    """Build the PDF for a ManualInvoice — shared by the web admin's
    /admin/invoices/<id>/pdf and the mobile API's
    /api/v1/invoices/<id>/pdf, same as _order_invoice_pdf_response above."""
    bill_to = [invoice.customer_name]
    if invoice.customer_email:
        bill_to.append(invoice.customer_email)
    if invoice.customer_phone:
        bill_to.append(invoice.customer_phone)
    if invoice.customer_address:
        bill_to.extend(line for line in invoice.customer_address.splitlines() if line.strip())

    items = [
        [
            item.description,
            _format_invoice_quantity(item.quantity),
            f"${item.unit_price:.2f}",
            f"${item.line_total:.2f}",
        ]
        for item in invoice.items
    ]
    buffer = render_invoice_pdf(
        invoice_number=invoice.invoice_number,
        issue_date=invoice.issue_date,
        bill_to_lines=bill_to,
        items=items,
        subtotal=invoice.subtotal,
        tax_label=invoice.tax_label,
        tax_amount=(invoice.tax_amount if invoice.has_tax else None),
        total=invoice.total,
        notes=invoice.notes,
    )
    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f'inline; filename="invoice-{invoice.invoice_number}.pdf"'},
    )


PICKUP_STATUSES = ["Requested", "Confirmed", "Picked Up", "Cancelled"]
PICKUP_TIME_WINDOWS = [
    "9 - 10am",
    "10 - 11am",
    "11am - 12pm",
    "12 - 1pm",
    "1 - 2pm",
    "2 - 3pm",
    "3 - 4pm",
    "4 - 5pm",
]

# (Setting key, label) pairs for the owner-editable social media links shown
# as icon buttons in the footer. Stored in the generic Setting key/value
# table (see below) so adding another platform later is a one-line change,
# not a schema migration.
SOCIAL_PLATFORMS = [
    ("social_facebook", "Facebook"),
    ("social_instagram", "Instagram"),
    ("social_linkedin", "LinkedIn"),
    ("social_pinterest", "Pinterest"),
    ("social_x", "X (Twitter)"),
    ("social_youtube", "YouTube"),
]

# --- Admin sidebar/topbar sections --------------------------------------
# One source of truth for the admin nav's icons, labels, and which routes
# belong to which section — drives both the sidebar (templates loop over
# this instead of nine hardcoded <a> tags) and each page's topbar icon +
# "Back to main menu" link (see inject_globals below and _admin_base.html).
ADMIN_SECTIONS = [
    ("📝", "Updates", "admin_dashboard",
     {"admin_dashboard", "admin_post_new", "admin_post_edit"}),
    ("📬", "Mailbox", "admin_mailbox",
     {"admin_mailbox", "admin_mailbox_thread", "admin_mailbox_compose"}),
    ("🧾", "Orders", "admin_orders",
     {"admin_orders", "admin_order_detail"}),
    ("💵", "Invoices", "admin_invoices",
     {"admin_invoices", "admin_invoice_new", "admin_invoice_detail"}),
    ("📅", "Pickups", "admin_pickups", {"admin_pickups", "admin_pickup_detail"}),
    ("📧", "Subscribers", "admin_subscribers", {"admin_subscribers"}),
    ("👥", "Users", "admin_users",
     {"admin_users", "admin_user_new", "admin_user_edit"}),
    ("🛍️", "Products", "admin_products",
     {"admin_products", "admin_product_new", "admin_product_edit"}),
    ("📄", "Pages", "admin_pages", {"admin_pages", "admin_page_edit"}),
    ("⚙️", "Settings", "admin_settings",
     {"admin_settings", "admin_settings_mfa_setup"}),
]

# Sidebar sections hidden from the creator's technical-only account —
# exactly the sections whose routes are behind @owner_required above
# (Mailbox, Orders, Invoices, Pickups, Subscribers all touch customer or
# financial data). Kept as a lookup by section label rather than a 5th
# ADMIN_SECTIONS tuple field so _admin_base.html's plain 4-item unpacking
# doesn't need to change.
OWNER_ONLY_ADMIN_SECTIONS = {"Mailbox", "Orders", "Invoices", "Pickups", "Subscribers", "Users"}


@app.context_processor
def inject_globals():
    favicon_key = get_setting("favicon_filename")
    favicon_url = url_for("static", filename=favicon_key) if favicon_key else None
    cart_count = sum(session.get(CART_SESSION_KEY, {}).values())
    social_links = {key: get_setting(key) for key, _label in SOCIAL_PLATFORMS}
    # "year" is computed fresh each request (not stored in COMPANY) so the
    # footer's copyright notice always shows the current year without
    # needing a code change every January.
    company = {**COMPANY, "year": datetime.utcnow().year}
    # Which ADMIN_SECTIONS entry (icon, label, section_endpoint) the current
    # request falls under, or None outside the admin area (public pages,
    # login, API) — see ADMIN_SECTIONS above.
    admin_section = next(
        ((icon, label, endpoint) for icon, label, endpoint, endpoints in ADMIN_SECTIONS
         if request.endpoint in endpoints),
        None,
    )
    is_admin_logged_in = bool(session.get("is_admin"))
    admin_identity = session.get("admin_identity", "owner")
    is_owner_account = admin_identity in ADMIN_ROLES_FULL_ACCESS
    visible_admin_sections = [
        section for section in ADMIN_SECTIONS
        if is_owner_account or section[1] not in OWNER_ONLY_ADMIN_SECTIONS
    ]
    # Customer portal user (separate from the admin session above)
    customer_user_id = session.get("customer_user_id")
    current_customer = (
        CustomerUser.query.get(customer_user_id) if customer_user_id else None
    )
    return {
        "company": company,
        "favicon_url": favicon_url,
        "cart_count": cart_count,
        "social_links": social_links,
        "admin_username": (
            _admin_display_username(admin_identity) if is_admin_logged_in else ADMIN_USERNAME
        ),
        "admin_identity": admin_identity if is_admin_logged_in else None,
        "is_owner_account": is_owner_account,
        "admin_account_label": _admin_account_label(admin_identity) if is_admin_logged_in else None,
        "admin_sections": visible_admin_sections if is_admin_logged_in else ADMIN_SECTIONS,
        "admin_section": admin_section,
        "current_customer": current_customer,
        "google_signin_enabled": google_signin_enabled(),
    }


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(300), nullable=True)
    is_published = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    @property
    def image_url(self):
        if self.image_filename:
            return url_for("static", filename=self.image_filename)
        return None


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(20), nullable=False, index=True)  # "packaging" or "box"
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Numeric(8, 2), nullable=True)  # null = "Contact for pricing"
    image_filename = db.Column(db.String(300), nullable=True)
    is_available = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    @property
    def image_url(self):
        if self.image_filename:
            return url_for("static", filename=self.image_filename)
        return None

    @property
    def category_label(self):
        return dict(PRODUCT_CATEGORIES).get(self.category, self.category)


class Order(db.Model):
    """A customer order, paid for by Interac e-Transfer.

    There's no payment gateway here — Interac doesn't offer a public API a
    small merchant can integrate with for real-time verification. Instead:
    the order is created as "Awaiting Payment", the customer is emailed
    instructions to e-Transfer the total to CONTACT_RECIPIENT_EMAIL with
    this order's order_number as the reference, and the owner marks it
    "Paid" by hand from /admin/orders once they see it land in their online
    banking.

    order_number doubles as the public order_confirmation page's lookup
    key, so it's generated with `secrets` (not `random`) for real
    unguessability — anyone with the number can view that order's contact
    details.

    `total` is the grand total (subtotal + tax) — the amount actually owed
    and shown in payment instructions. `tax_amount` is nullable so orders
    placed before HST was added keep displaying correctly (their `total`
    was the whole amount, with no tax split out); new orders always get it
    set. `subtotal` isn't its own column — it's derived below from the
    OrderItem snapshots, which is already the accurate historical amount.
    """
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(40), unique=True, nullable=False, index=True)
    customer_name = db.Column(db.String(200), nullable=False)
    customer_email = db.Column(db.String(320), nullable=False)
    customer_phone = db.Column(db.String(50), nullable=True)
    shipping_address = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    total = db.Column(db.Numeric(10, 2), nullable=False)
    tax_amount = db.Column(db.Numeric(10, 2), nullable=True)
    status = db.Column(db.String(30), nullable=False, default=ORDER_STATUSES[0])
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    items = db.relationship(
        "OrderItem", backref="order", cascade="all, delete-orphan", order_by="OrderItem.id",
    )

    @property
    def subtotal(self):
        return sum((item.subtotal for item in self.items), Decimal("0.00"))

    @property
    def status_badge_class(self):
        return {
            "Awaiting Payment": "badge-pending",
            "Paid": "badge-published",
            "Fulfilled": "badge-delivered",
            "Cancelled": "badge-delayed",
        }.get(self.status, "badge-status")


class OrderItem(db.Model):
    """One product line within an Order.

    product_name/unit_price are snapshotted at checkout time (not just a
    live join to Product) so an order's receipt stays accurate even if the
    product's price changes or it's deleted later. product_id is kept
    (nullable) only to link back to the product page when it still exists.
    """
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=True)
    product_name = db.Column(db.String(200), nullable=False)
    unit_price = db.Column(db.Numeric(8, 2), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)

    @property
    def subtotal(self):
        return self.unit_price * self.quantity


class ManualInvoice(db.Model):
    """A one-off invoice for anything outside the normal box/product shop —
    a custom job, a favour, whatever the checkout flow doesn't cover. There's
    no cart or product catalog link here, just line items typed in by hand,
    but it shares the same PDF letterhead as an automatic Order invoice.
    """
    id = db.Column(db.Integer, primary_key=True)
    invoice_number = db.Column(db.String(40), unique=True, nullable=False, index=True)
    customer_name = db.Column(db.String(200), nullable=False)
    customer_email = db.Column(db.String(320), nullable=True)
    customer_phone = db.Column(db.String(50), nullable=True)
    customer_address = db.Column(db.Text, nullable=True)
    issue_date = db.Column(db.Date, nullable=False)
    apply_tax = db.Column(db.Boolean, nullable=False, default=False)
    # An exact tax amount, set only by the mobile app's manual-invoice screen
    # (it lets the owner type any tax figure, not just a 13% HST toggle like
    # the web admin form). When set, this wins over apply_tax/calculate_hst.
    tax_override = db.Column(db.Numeric(10, 2), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    items = db.relationship(
        "ManualInvoiceItem", backref="invoice", cascade="all, delete-orphan",
        order_by="ManualInvoiceItem.id",
    )

    @property
    def subtotal(self):
        return sum((item.line_total for item in self.items), Decimal("0.00"))

    @property
    def tax_amount(self):
        if self.tax_override is not None:
            return self.tax_override
        if not self.apply_tax:
            return Decimal("0.00")
        return calculate_hst(self.subtotal)

    @property
    def has_tax(self):
        return self.tax_override is not None or self.apply_tax

    @property
    def tax_label(self):
        if self.tax_override is not None:
            return "Tax"
        return "HST (13%)" if self.apply_tax else None

    @property
    def total(self):
        return self.subtotal + self.tax_amount


class ManualInvoiceItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice_id = db.Column(db.Integer, db.ForeignKey("manual_invoice.id"), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    quantity = db.Column(db.Numeric(10, 2), nullable=False, default=1)
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)

    @property
    def line_total(self):
        return (self.quantity * self.unit_price).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


class PickupRequest(db.Model):
    """A customer's request to have boxes picked up, submitted from the
    public Book a Pick Up page. There's no live dispatch/routing system
    behind this — it's a request queue the owner works from /admin/pickups,
    the same "owner checks a list and follows up" pattern used for Orders
    and the contact form."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(320), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    address = db.Column(db.Text, nullable=False)
    pickup_date = db.Column(db.Date, nullable=False)
    time_window = db.Column(db.String(50), nullable=False)
    box_count = db.Column(db.Integer, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(30), nullable=False, default=PICKUP_STATUSES[0])
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    # Set from /admin/pickups/<id> when the owner uploads an invoice for this
    # pickup (a scanned/exported PDF or image, not a generated one) — stored
    # relative to the static folder via save_uploaded_image(), same pattern
    # as product photos and the site favicon. Shown to the customer on their
    # My Account > My Pickup Requests tab once set.
    invoice_filename = db.Column(db.String(300), nullable=True)

    @property
    def status_badge_class(self):
        return {
            "Requested": "badge-pending",
            "Confirmed": "badge-published",
            "Picked Up": "badge-delivered",
            "Cancelled": "badge-delayed",
        }.get(self.status, "badge-status")


class Shipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tracking_number = db.Column(db.String(40), unique=True, nullable=False, index=True)
    recipient_name = db.Column(db.String(200), nullable=False)
    destination = db.Column(db.String(300), nullable=False)
    sender_name = db.Column(db.String(200), nullable=True)
    current_status = db.Column(db.String(60), nullable=False, default=SHIPMENT_STATUSES[0])
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    events = db.relationship(
        "TrackingEvent",
        backref="shipment",
        cascade="all, delete-orphan",
        order_by="desc(TrackingEvent.timestamp)",
    )


class TrackingEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shipment_id = db.Column(db.Integer, db.ForeignKey("shipment.id"), nullable=False)
    status = db.Column(db.String(60), nullable=False)
    location = db.Column(db.String(200), nullable=True)
    note = db.Column(db.String(400), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Setting(db.Model):
    """Simple key/value store for site-wide settings, e.g. the favicon.
    Small and generic on purpose so more settings can be added later
    without a schema change."""
    key = db.Column(db.String(100), primary_key=True)
    # Text, not a bounded VARCHAR: this table also stores things like the
    # MFA backup-codes JSON blob (8 codes x sha256 hash = well over 500
    # chars), and Postgres — unlike SQLite — actually enforces a VARCHAR
    # length limit and raises StringDataRightTruncation instead of just
    # storing it. See _ensure_setting_value_is_text() below for the
    # migration that widens this column on databases created before this
    # was Text.
    value = db.Column(db.Text, nullable=True)


class PageContent(db.Model):
    """Owner-editable body text for otherwise-static pages: Privacy Policy,
    Terms and Conditions, and the intro paragraph on Contact Us. Plain text,
    the same way Updates posts work — line breaks are preserved but there's
    no HTML/markup, so there's nothing an admin could paste in here that
    would break the page. (About Us keeps its own hand-built layout — its
    timeline and feature cards don't fit a single text box.)"""
    slug = db.Column(db.String(50), primary_key=True)
    label = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class MailboxMessage(db.Model):
    """A local record of messages tied to the business inbox — contact-form
    submissions (saved automatically, see contact_us()) and any reply/compose
    sent from the admin Mailbox (see _send_mailbox_reply()). This is NOT the
    real Microsoft 365 mailbox — nothing here is fetched live from it, and
    there's currently no mechanism that mirrors other incoming mail into this
    table (see the comment above the "Admin Mailbox" section for why).

    `direction` is "inbound" for contact-form submissions, "outbound" for
    replies sent from the Mailbox. thread_key groups messages into a
    conversation: the other party's email address, lowercased.
    """
    id = db.Column(db.Integer, primary_key=True)
    direction = db.Column(db.String(10), nullable=False, default="inbound")
    thread_key = db.Column(db.String(320), nullable=False, index=True)
    from_name = db.Column(db.String(200), nullable=True)
    from_email = db.Column(db.String(320), nullable=False)
    to_email = db.Column(db.String(320), nullable=False)
    subject = db.Column(db.String(500), nullable=True)
    body_text = db.Column(db.Text, nullable=True)
    body_html = db.Column(db.Text, nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    @property
    def preview(self):
        text = " ".join((self.body_text or "").split())
        return (text[:140] + "…") if len(text) > 140 else text


class Subscriber(db.Model):
    """An email newsletter signup from the site's footer form.

    Just a list — this app doesn't send newsletters itself. Export the list
    from /admin/subscribers as CSV and paste it into whatever you actually
    send campaigns from.
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=True)
    address = db.Column(db.String(300), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


# ---------------------------------------------------------------------------
# Customer user accounts
# ---------------------------------------------------------------------------
#
# Only one account type exists on the public-facing portal: "customer". The
# old "staff"/"admin" CustomerUser roles (which used to skip the page
# restriction below entirely) have been removed — every self-registered or
# admin-created account here is a customer account, full stop. Staff who
# need the back-office admin panel use the separate ADMIN_USERNAME/
# CREATOR_USERNAME login system above (see _match_admin_credentials); that
# system was never tied to CustomerUser.role in the first place.

CUSTOMER_USER_ROLES = ["customer"]

# Endpoints every logged-in customer can always reach, regardless of the
# per-account page access chosen by the admin below: core account/auth
# flows, the cart/checkout/order pipeline, legal pages, and static assets.
# Without this floor, an admin could accidentally lock a customer out of
# their own cart or the ability to log out.
CUSTOMER_ALWAYS_ALLOWED_ENDPOINTS = {
    "home", "cart_view", "cart_add", "cart_update", "cart_remove",
    "checkout", "order_confirmation", "order_confirmation_invoice",
    "order_invoice",  # /order-confirmation/<number>/invoice.pdf
    "privacy_policy", "terms_and_conditions", "newsletter_signup", "healthz",
    # customer portal / auth endpoints
    "customer_portal", "customer_logout", "customer_login", "customer_register",
    "customer_profile_update", "customer_forgot_password", "customer_reset_password",
    "customer_login_google", "customer_login_google_callback", "customer_complete_profile",
    "customer_pickup_invoice",
    # static files, etc.
    "static",
}

# Content pages an admin can individually grant or revoke per customer
# account from Admin > Users (see CustomerUser.allowed_pages below). Each
# entry is (key stored in the account's allowed_pages list, label shown in
# the admin UI, the set of endpoints that page key unlocks).
CUSTOMER_TOGGLEABLE_PAGES = [
    ("about_us", "About Us", {"about_us"}),
    ("contact_us", "Contact Us", {"contact_us"}),
    ("rates", "Rates", {"rates"}),
    ("updates", "Updates / Blog", {"updates", "update_detail"}),
    ("track", "Track a Shipment", {"track"}),
    ("sari_sari", "Sari-Sari Store", {"sari_sari"}),
    ("empty_box_sales", "Empty Box Sales", {"empty_box_sales"}),
    ("packaging_items", "Packaging Items", {"packaging_items"}),
    ("book_a_pickup", "Book a Pickup", {"book_a_pickup"}),
]
CUSTOMER_TOGGLEABLE_PAGE_KEYS = [key for key, _label, _endpoints in CUSTOMER_TOGGLEABLE_PAGES]


class CustomerUser(db.Model):
    """A site-registered customer account for the public-facing portal:
    customers can track their orders, book pickups, and view their
    purchase history.

    Separate from the env-var admin credentials (ADMIN_USERNAME/ADMIN_PASSWORD)
    — those are the back-office owner/creator logins that manage the admin
    panel and have nothing to do with this table.

    Which public pages a given customer can browse while logged in is
    controlled per-account by `allowed_pages` (see get_allowed_page_keys/
    allowed_endpoints below) rather than by a role — every account here is
    a "customer".

    Passwords are stored as a SHA-256 hex digest (same simple approach used
    for MFA backup codes elsewhere). For a larger deployment you'd use
    bcrypt/argon2, but this matches the existing pattern.
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="customer")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    phone = db.Column(db.String(50), nullable=True)
    address = db.Column(db.String(400), nullable=True)
    # JSON list of CUSTOMER_TOGGLEABLE_PAGES keys this account may view.
    # NULL means "not yet configured by an admin" and is treated as "every
    # page allowed" (see get_allowed_page_keys) so existing accounts aren't
    # suddenly locked out the moment this column appears.
    allowed_pages = db.Column(db.Text, nullable=True)
    # Set once a customer signs in with Google (see customer_login_google_*
    # below); NULL for accounts created by the normal email/password form.
    # Not used for lookup (email is still the unique key both paths share)
    # -- just a record of how the account was created.
    google_id = db.Column(db.String(64), nullable=True, index=True)
    # True only for a brand-new Google sign-up, until they fill in the
    # profile-completion form (phone + address) — see
    # customer_complete_profile and enforce_customer_page_restrictions.
    # Accounts created the normal way never need this (they can add
    # phone/address whenever they like from My Profile).
    needs_profile_details = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return secrets.compare_digest(
            self.password_hash,
            hashlib.sha256(password.encode()).hexdigest(),
        )

    @property
    def role_label(self):
        return "Customer"

    def get_allowed_page_keys(self):
        """Which CUSTOMER_TOGGLEABLE_PAGES keys this account can view, on
        top of the always-allowed floor. NULL/unparseable -> every page
        (see the allowed_pages column note above)."""
        if self.allowed_pages is None:
            return list(CUSTOMER_TOGGLEABLE_PAGE_KEYS)
        try:
            keys = json.loads(self.allowed_pages)
        except (TypeError, ValueError):
            return list(CUSTOMER_TOGGLEABLE_PAGE_KEYS)
        if not isinstance(keys, list):
            return list(CUSTOMER_TOGGLEABLE_PAGE_KEYS)
        return [k for k in keys if k in CUSTOMER_TOGGLEABLE_PAGE_KEYS]

    def set_allowed_page_keys(self, keys):
        valid = [k for k in CUSTOMER_TOGGLEABLE_PAGE_KEYS if k in (keys or [])]
        self.allowed_pages = json.dumps(valid)

    def has_full_page_access(self):
        return set(self.get_allowed_page_keys()) == set(CUSTOMER_TOGGLEABLE_PAGE_KEYS)

    def allowed_endpoints(self):
        """The full set of endpoints this account may reach on the public
        site: the always-allowed floor plus whichever toggleable pages the
        admin granted it."""
        endpoints = set(CUSTOMER_ALWAYS_ALLOWED_ENDPOINTS)
        granted = set(self.get_allowed_page_keys())
        for key, _label, page_endpoints in CUSTOMER_TOGGLEABLE_PAGES:
            if key in granted:
                endpoints |= page_endpoints
        return endpoints


def generate_password_reset_token(user):
    """A signed, time-limited token for `user`'s "forgot password" link.
    Embeds a short slice of the account's CURRENT password hash so the
    link stops working the moment the password actually changes (by this
    link or any other means) -- no separate used-token bookkeeping needed.
    """
    return _password_reset_serializer.dumps({
        "uid": user.id,
        "ph": user.password_hash[:16],
    })


def verify_password_reset_token(token):
    """Returns the CustomerUser a still-valid reset `token` belongs to, or
    None if it's missing, malformed, expired, or already used (i.e. the
    password has changed since it was issued)."""
    try:
        data = _password_reset_serializer.loads(token, max_age=PASSWORD_RESET_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    user = CustomerUser.query.get(data.get("uid"))
    if not user or not user.is_active:
        return None
    if data.get("ph") != user.password_hash[:16]:
        return None
    return user


def send_password_reset_email(user):
    """Emails `user` a one-hour reset link. Reuses _send_email (same
    Microsoft 365 SMTP plumbing as the contact form and admin Mailbox)."""
    token = generate_password_reset_token(user)
    reset_url = url_for("customer_reset_password", token=token, _external=True)
    return _send_email(
        to_email=user.email,
        subject=f"Reset your {COMPANY['name']} password",
        body=(
            f"Hi {user.name},\n\n"
            "We received a request to reset the password on your account. "
            "Click the link below to choose a new one -- it expires in 1 hour:\n\n"
            f"{reset_url}\n\n"
            "If you didn't request this, you can safely ignore this email; "
            "your password won't change."
        ),
    )


# Starting copy for the editable pages below — seeded once into the
# database on first run so nothing visually changes until the owner
# actually edits a page from /admin/pages. Plain text: blank lines start a
# new paragraph, same as an Updates post.
DEFAULT_PAGE_CONTENT = {
    "privacy-policy": (
        "Privacy Policy",
        f'{COMPANY["name"]} ("we", "us", or "our") respects your privacy. '
        "This policy explains what information we collect through this "
        "website and how we use it.\n\n"
        "Information We Collect\n"
        "When you use our contact form or newsletter signup, we collect the "
        "name, email address, and message you provide. We may also collect "
        "any file you choose to attach to a message.\n\n"
        "How We Use Your Information\n"
        "We use the information you provide to respond to your inquiries, "
        "process shipping requests, and, if you subscribe, to send "
        "occasional updates about our services and promotions.\n\n"
        "Cookies\n"
        "This site uses a small cookie to remember your cookie consent "
        "preference. You can accept or decline this cookie using the "
        "banner shown on your first visit.\n\n"
        "Sharing Your Information\n"
        "We do not sell your personal information. We only share "
        "information as needed to fulfill a shipping request or as "
        "required by law.\n\n"
        "Contact Us\n"
        f'If you have questions about this policy, please contact us at '
        f'{COMPANY["contact_email"]}.'
    ),
    "terms-and-conditions": (
        "Terms and Conditions",
        "By using this website and our shipping services, you agree to the "
        "following terms and conditions.\n\n"
        "Our Services\n"
        f'{COMPANY["name"]} provides door-to-door box shipping from Canada '
        "to the Philippines, along with empty box sales and packaging "
        "items. Rates and availability are subject to change and confirmed "
        "at the time of booking.\n\n"
        "Prohibited Items\n"
        "Customers are responsible for ensuring shipped items comply with "
        "Philippine customs regulations. We do not accept illegal, "
        "hazardous, or prohibited items for shipment.\n\n"
        "Delivery Times\n"
        "While we aim to deliver on time, delivery windows are estimates "
        "and may be affected by customs processing, weather, or other "
        "factors outside our control.\n\n"
        "Promotions\n"
        "Promotional offers, such as $10.00 off per box for mobile "
        "warehouse drop-offs, are subject to change or discontinuation at "
        "any time.\n\n"
        "Limitation of Liability\n"
        f'{COMPANY["name"]} is not liable for delays or damages caused by '
        "circumstances beyond our reasonable control.\n\n"
        "Contact\n"
        f'Questions about these terms can be directed to {COMPANY["contact_email"]}.'
    ),
    "contact-intro": (
        "Contact Us (intro text)",
        "Feel free to contact us with any questions about rates, drop-off "
        "locations, or scheduling. We're happy to arrange an in-person "
        "meeting during business hours."
    ),
}


PROMO_POST_TITLE = "Our Promos — Save More When You Ship More!"
PROMO_POST_BODY = (
    "Great news from RGC Door-to-Door Box Express Services! Here's how you "
    "can save on your next shipment to the Philippines.\n"
    "\n"
    "Send 3 Regular Size Boxes\n"
    "To NCR / Metro Manila, Luzon 1, Luzon 2, Visayas, or Mindanao — and "
    "get $25.00 off.\n"
    "\n"
    "Send 5 Regular Size Boxes\n"
    "To the same destinations — and get $50.00 off.\n"
    "\n"
    "NEW for 2026: Mobile Warehouse Drop-Off\n"
    "Drop off your box at our mobile warehouse and get $10.00 OFF per box. "
    "Hurry — this offer won't last!\n"
    "\n"
    "Our Warehouse Location\n"
    "Trece Martirez City, Cavite, Philippines.\n"
    "\n"
    "Questions? Email us anytime at info@rgcdoortodoorboxservices.ca and "
    "we'll be happy to help.\n"
    "\n"
    "RGC Door-to-Door Box Express — proudly serving Metro Manila, Luzon, "
    "Visayas, and Mindanao, including Hard Port and Super Hard Port areas."
)


def _ensure_column(table, column, ddl_type):
    """Add a column to an already-existing table if it's missing.

    db.create_all() below only creates tables that don't exist yet — it never
    alters a table that's already there, so a column added to a model after
    its table was first created (e.g. Order.tax_amount) never reaches a live
    database on its own. Any query touching that table then fails with an
    "column does not exist" error. This makes that self-healing: it runs on
    every startup, is a no-op once the column is present, and works against
    both Postgres and SQLite.
    """
    inspector = inspect(db.engine)
    if table not in inspector.get_table_names():
        return  # table doesn't exist yet; create_all() will create it with every column
    existing = {col["name"] for col in inspector.get_columns(table)}
    if column not in existing:
        db.session.execute(text(f'ALTER TABLE "{table}" ADD COLUMN {column} {ddl_type}'))
        db.session.commit()


def _ensure_setting_value_is_text():
    """Widen setting.value to an unbounded TEXT column if it's still the
    old VARCHAR(500) from before this was Text (see the comment on
    Setting.value). Bounded VARCHAR is fine on SQLite, which never
    enforces the length — that's why this never showed up in local/dev
    testing — but Postgres does enforce it and raises
    StringDataRightTruncation the first time something long (e.g. the MFA
    backup-codes JSON) is written. No-op once already Text/unbounded, and
    safe to run on every startup."""
    inspector = inspect(db.engine)
    if "setting" not in inspector.get_table_names():
        return
    for col in inspector.get_columns("setting"):
        if col["name"] != "value":
            continue
        col_type = col["type"]
        # A bounded string type reports a numeric .length; Text/unbounded
        # types report None (or don't have the attribute at all).
        if getattr(col_type, "length", None):
            if db.engine.dialect.name == "postgresql":
                db.session.execute(text('ALTER TABLE "setting" ALTER COLUMN value TYPE TEXT'))
            else:
                # SQLite has no real ALTER COLUMN TYPE, but it's untyped/
                # dynamically-typed storage anyway, so the existing column
                # already accepts values of any length — nothing to do.
                pass
            db.session.commit()
        break


with app.app_context():
    db.create_all()
    _ensure_setting_value_is_text()
    _ensure_column("order", "tax_amount", "NUMERIC(10, 2)")
    _ensure_column("subscriber", "name", "VARCHAR(200)")
    _ensure_column("subscriber", "address", "VARCHAR(300)")
    _ensure_column("subscriber", "phone", "VARCHAR(50)")
    _ensure_column("manual_invoice", "customer_phone", "VARCHAR(50)")
    _ensure_column("manual_invoice", "tax_override", "NUMERIC(10, 2)")
    # CustomerUser columns (safe if table already existed without them)
    _ensure_column("customer_user", "is_active", "BOOLEAN DEFAULT TRUE")
    _ensure_column("customer_user", "phone", "VARCHAR(50)")
    _ensure_column("customer_user", "address", "VARCHAR(400)")
    _ensure_column("customer_user", "allowed_pages", "TEXT")
    _ensure_column("customer_user", "google_id", "VARCHAR(64)")
    _ensure_column("customer_user", "needs_profile_details", "BOOLEAN DEFAULT FALSE")
    _ensure_column("pickup_request", "invoice_filename", "VARCHAR(300)")
    # The "staff"/"admin" CustomerUser roles have been removed — every
    # account on the public portal is a "customer" now, with page access
    # controlled individually via allowed_pages instead. Any pre-existing
    # rows from before this change are folded into "customer" here so
    # nothing is left in a role that no longer means anything.
    CustomerUser.query.filter(CustomerUser.role.in_(["staff", "admin"])).update(
        {"role": "customer"}, synchronize_session=False,
    )
    for slug, (label, body) in DEFAULT_PAGE_CONTENT.items():
        if not PageContent.query.get(slug):
            db.session.add(PageContent(slug=slug, label=label, body=body))
    if not Post.query.filter_by(title=PROMO_POST_TITLE).first():
        db.session.add(Post(
            title=PROMO_POST_TITLE,
            body=PROMO_POST_BODY,
            image_filename="images/hero-flyer.png",
            is_published=True,
        ))
    db.session.commit()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAVICON_EXTENSIONS = {"ico", "png", "jpg", "jpeg", "svg"}
INVOICE_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}


def _has_allowed_extension(filename, allowed_extensions):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def allowed_file(filename):
    return _has_allowed_extension(filename, ALLOWED_EXTENSIONS)


def save_uploaded_image(file_storage, prefix="uploads", allowed_extensions=None):
    """Save an uploaded image into static/<prefix>/ on local disk. Returns the
    stored path relative to the static folder (e.g. "uploads/<uuid>.png"), or
    None if no valid file was provided.

    `prefix` groups uploads by kind (e.g. "uploads" for post/product photos,
    "branding" for the site favicon). `allowed_extensions` overrides the
    default PNG/JPG/GIF/WEBP set when needed (favicons also accept .ico and
    .svg)."""
    allowed_extensions = allowed_extensions or ALLOWED_EXTENSIONS
    if not file_storage or not file_storage.filename:
        return None
    if not _has_allowed_extension(file_storage.filename, allowed_extensions):
        nice_list = ", ".join(sorted(ext.upper() for ext in allowed_extensions))
        flash(f"That file type isn't supported. Please use: {nice_list}.", "error")
        return None
    ext = file_storage.filename.rsplit(".", 1)[1].lower()
    folder = os.path.join(app.static_folder, prefix)
    filename = f"{uuid.uuid4().hex}.{ext}"
    key = f"{prefix}/{filename}"
    try:
        os.makedirs(folder, exist_ok=True)
        file_storage.save(os.path.join(folder, filename))
    except OSError:
        flash("There was a problem saving the image. Please try again.", "error")
        return None
    return key


def delete_uploaded_image(key):
    """Best-effort delete of a locally stored image; safe to call with None."""
    if not key:
        return
    path = os.path.join(app.static_folder, key)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def get_setting(key, default=None):
    setting = Setting.query.get(key)
    return setting.value if setting and setting.value else default


def set_setting(key, value):
    setting = Setting.query.get(key)
    if setting is None:
        setting = Setting(key=key, value=value)
        db.session.add(setting)
    else:
        setting.value = value
    db.session.commit()


def _reset_pg_sequence(table_name):
    """Reset a single Postgres table's id sequence to MAX(id)+1. No-op (and
    safe to call) on SQLite, and safe to call on a table with no such
    sequence (e.g. a string primary key)."""
    if db.engine.dialect.name != "postgresql":
        return
    try:
        with db.engine.begin() as conn:
            conn.execute(text(
                f'SELECT setval('
                f"pg_get_serial_sequence('\"{table_name}\"', 'id'), "
                f'COALESCE((SELECT MAX(id) FROM "{table_name}"), 0) + 1, false)'
            ))
    except Exception:
        pass


def commit_with_sequence_repair(build_fn, table_names):
    """Calls build_fn() (which should db.session.add() one or more new rows
    and return them) and commits. If the commit fails with a duplicate
    primary key, this is almost always a stale Postgres id sequence left
    over from a JSON database restore (see _db_import_json / the Settings
    page's "Fix Database Sequences" button) — restoring inserts rows with
    explicit ids, but Postgres's own auto-increment counter for that table
    doesn't know that happened, so the very next ORM insert can collide
    with an id that already exists. Rather than making every fresh booking
    or order depend on the admin remembering to click that button first,
    this repairs the affected table(s)' sequence(s) automatically and
    retries once. `table_names` should list every table build_fn() inserts
    into (e.g. ["pickup_request", "mailbox_message"]).

    Raises IntegrityError if the retry also fails (a real data problem,
    not a sequence one) or if this isn't Postgres.
    """
    try:
        result = build_fn()
        db.session.commit()
        return result
    except IntegrityError:
        db.session.rollback()
        if db.engine.dialect.name != "postgresql":
            raise
        for table_name in table_names:
            _reset_pg_sequence(table_name)
        # Retry once, now that the sequence(s) are corrected.
        result = build_fn()
        db.session.commit()
        return result


# --- Two-factor authentication (TOTP) helpers --------------------------------
# See the big comment above ADMIN_USERNAME for how this state is stored in
# Setting (namespaced per `identity` -- "owner" or "creator") and how to
# recover a lockout. Every function here takes that `identity` explicitly
# rather than assuming "the" admin, so the two accounts' MFA never overlap.

def _mfa_setting_key(name, identity):
    return f"{name}:{identity}"


def mfa_is_enabled(identity):
    return get_setting(_mfa_setting_key("mfa_enabled", identity)) == "1"


def _totp_for_secret(secret):
    return pyotp.TOTP(secret)


def verify_totp_code(identity, code):
    """Check a 6-digit authenticator code against `identity`'s ACTIVE
    secret. False if that account's MFA isn't enabled, no secret is set, or
    the code is missing/wrong. valid_window=1 allows the previous/next
    30-second step too, so a slightly-off phone clock doesn't lock anyone
    out."""
    secret = get_setting(_mfa_setting_key("mfa_totp_secret", identity))
    code = (code or "").strip().replace(" ", "")
    if not secret or not code:
        return False
    try:
        return _totp_for_secret(secret).verify(code, valid_window=1)
    except Exception:
        return False


def _hash_backup_code(code):
    # Salted with app.secret_key (same value the mobile token and session
    # cookie are signed with — see the note above ADMIN_USERNAME about
    # keeping SECRET_KEY stable across deploys). Backup codes are shown
    # once, in plaintext, at enrollment; only this hash is ever stored.
    # (Not per-identity -- the identity's whole set of codes already lives
    # under that identity's own mfa_backup_codes:<identity> key, and a hash
    # collision between the two accounts' codes would be meaningless since
    # each is only ever checked against its own account's Setting row.)
    normalized = (code or "").strip().upper().replace("-", "").replace(" ", "")
    return hashlib.sha256((normalized + app.secret_key).encode("utf-8")).hexdigest()


def generate_backup_codes(identity, count=8):
    """Generate `count` fresh single-use recovery codes for `identity`,
    store their hashes in Setting (replacing any previous set for that
    identity only), and return the plaintext codes so the caller can show
    them ONCE — there is no way to display them again later, only
    regenerate a new set."""
    codes = []
    records = []
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(count):
        raw = "".join(secrets.choice(alphabet) for _ in range(8))
        formatted = f"{raw[:4]}-{raw[4:]}"
        codes.append(formatted)
        records.append({"hash": _hash_backup_code(formatted), "used": False})
    set_setting(_mfa_setting_key("mfa_backup_codes", identity), json.dumps(records))
    return codes


def consume_backup_code(identity, code):
    """Check `code` against `identity`'s stored backup codes. If it matches
    an unused one, marks it used (so it can't be replayed) and returns
    True."""
    code = (code or "").strip()
    if not code:
        return False
    key = _mfa_setting_key("mfa_backup_codes", identity)
    raw = get_setting(key)
    if not raw:
        return False
    try:
        records = json.loads(raw)
    except (TypeError, ValueError):
        return False
    target_hash = _hash_backup_code(code)
    matched = False
    for record in records:
        if not record.get("used") and record.get("hash") == target_hash:
            record["used"] = True
            matched = True
            break
    if matched:
        set_setting(key, json.dumps(records))
    return matched


def verify_mfa_code(identity, code):
    """Accepts either a live 6-digit authenticator code or an unused backup
    code, both checked against `identity`'s own MFA state — used by both
    the web login's second step and the mobile API login."""
    return verify_totp_code(identity, code) or consume_backup_code(identity, code)


def get_page_content(slug):
    page = PageContent.query.get(slug)
    return page.body if page else ""


def generate_order_number():
    """A public-facing, unguessable order reference like ORD-A1B2C3D4.

    Used both as the friendly reference customers put in their e-Transfer
    memo AND as the lookup key for the public order-confirmation page, so
    it needs real entropy (secrets, not random) rather than just looking
    distinctive.
    """
    while True:
        suffix = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        candidate = f"ORD-{suffix}"
        if not Order.query.filter_by(order_number=candidate).first():
            return candidate


def get_cart_items():
    """Cart contents as dicts of {product, quantity, subtotal}, validated
    against the database — silently drops anything that's since been
    deleted, hidden, or switched to "contact for pricing", and prunes those
    from the session so the cart badge count stays accurate."""
    cart = session.get(CART_SESSION_KEY, {})
    items = []
    changed = False
    for product_id_str, qty in list(cart.items()):
        product = Product.query.get(int(product_id_str))
        if not product or product.price is None or not product.is_available or qty < 1:
            del cart[product_id_str]
            changed = True
            continue
        items.append({"product": product, "quantity": qty, "subtotal": product.price * qty})
    if changed:
        session[CART_SESSION_KEY] = cart
    return items


def _send_order_emails(order):
    lines = [f"Order {order.order_number} — ${order.total:.2f} CAD", ""]
    for item in order.items:
        lines.append(f"  {item.quantity} x {item.product_name} @ ${item.unit_price:.2f} = ${item.subtotal:.2f}")
    lines += [
        "",
        f"Subtotal: ${order.subtotal:.2f}",
        f"HST (13%): ${(order.tax_amount or Decimal('0.00')):.2f}",
        f"Total: ${order.total:.2f} CAD",
        "",
        f"Customer: {order.customer_name} <{order.customer_email}>",
        f"Phone: {order.customer_phone or '(not provided)'}",
        f"Shipping / notes: {order.shipping_address or '(none)'}"
        + (f"\n{order.notes}" if order.notes else ""),
        "",
        "Status: Awaiting Payment — waiting on an Interac e-Transfer for the "
        "total above, referencing this order number.",
    ]
    _send_email(
        to_email=CONTACT_RECIPIENT_EMAIL,
        subject=f"New order {order.order_number} — ${order.total:.2f} CAD",
        body="\n".join(lines),
        reply_to=order.customer_email,
    )

    item_lines = "\n".join(
        f"  {item.quantity} x {item.product_name} — ${item.subtotal:.2f}" for item in order.items
    )
    customer_body = (
        f"Hi {order.customer_name},\n\n"
        f"Thanks for your order! Here's what you ordered:\n\n{item_lines}\n\n"
        f"Subtotal: ${order.subtotal:.2f}\n"
        f"HST (13%): ${(order.tax_amount or Decimal('0.00')):.2f}\n"
        f"Total: ${order.total:.2f} CAD\n\n"
        "To complete your order, please send an Interac e-Transfer for the "
        f"total above to {CONTACT_RECIPIENT_EMAIL}, and include your order "
        f"number, {order.order_number}, in the message/memo field so we can "
        "match your payment to this order. If a security question is "
        f"required, contact us at {CONTACT_RECIPIENT_EMAIL} for the answer.\n\n"
        f"Your order number is {order.order_number} — keep this for your "
        "records; you can also look your order up any time at the "
        "confirmation link from this email.\n\n"
        f"{COMPANY['name']}"
    )
    _send_email(
        to_email=order.customer_email,
        subject=f"Your order {order.order_number} — payment instructions",
        body=customer_body,
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Please log in to access the admin area.", "error")
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def owner_required(view):
    """Stack this UNDER @login_required (i.e. @login_required goes above
    it, closer to @app.route) on any route that touches customers or
    money: Orders, Invoices, Mailbox, Pickups, Subscribers. Blocks the
    creator's technical-only account (see ADMIN_ROLES_FULL_ACCESS and the
    comment above ADMIN_USERNAME) while leaving it logged in — this is a
    "not for your account" redirect, not a "please log in" one."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("admin_identity", "owner") not in ADMIN_ROLES_FULL_ACCESS:
            flash("Your account doesn't have access to that section.", "error")
            return redirect(url_for("admin_dashboard"))
        return view(*args, **kwargs)
    return wrapped


def api_login_required(view):
    """Auth guard for the /api/v1/* mobile endpoints. Expects
    "Authorization: Bearer <token>" (a token minted by /api/v1/login), not
    the browser session cookie the rest of the admin panel uses. Stashes
    the token's identity/username on flask.g for api_owner_required (and
    api_me) to read."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
        if not token:
            return jsonify(error="Missing or malformed Authorization header."), 401
        try:
            payload = _mobile_token_serializer.loads(token, max_age=MOBILE_TOKEN_MAX_AGE_SECONDS)
        except SignatureExpired:
            return jsonify(error="Session expired. Please log in again."), 401
        except BadSignature:
            return jsonify(error="Invalid token."), 401
        # "id" is missing on tokens minted before the creator account
        # existed -- treat those as "owner" so anyone already signed in to
        # the app when this ships isn't unexpectedly locked out of
        # anything; they'll get an "id" claim on their next login.
        g.admin_identity = payload.get("id") or "owner"
        g.admin_username = payload.get("u")
        return view(*args, **kwargs)
    return wrapped


def api_owner_required(view):
    """Stack this UNDER @api_login_required on the same
    Orders/Invoices/Mailbox/Pickups/Subscribers endpoints owner_required
    covers on the website -- see that docstring."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("admin_identity") not in ADMIN_ROLES_FULL_ACCESS:
            return jsonify(error="This account doesn't have access to that."), 403
        return view(*args, **kwargs)
    return wrapped


def customer_login_required(view):
    """Requires any logged-in customer user (via the customer portal
    session). Which pages that user may reach beyond this is checked
    against their own allowed_endpoints() by enforce_customer_page_restrictions
    below.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        user_id = session.get("customer_user_id")
        if not user_id:
            flash("Please log in to continue.", "error")
            return redirect(url_for("customer_login", next=request.path))
        user = CustomerUser.query.get(user_id)
        # After a DB restore the stored ID may point to the wrong row.
        # Re-anchor by email (the stable identity used everywhere else) if
        # the ID lookup fails or returns a different email than the session.
        session_email = session.get("customer_email", "")
        if (not user or not user.is_active) and session_email:
            user = CustomerUser.query.filter_by(email=session_email).first()
            if user and user.is_active:
                # Update the session ID to match the restored row's new ID
                session["customer_user_id"] = user.id
        if not user or not user.is_active:
            session.pop("customer_user_id", None)
            session.pop("customer_email", None)
            flash("Your account is inactive. Please contact us.", "error")
            return redirect(url_for("customer_login"))
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def enforce_customer_page_restrictions():
    """If a logged-in customer tries to access a page outside their own
    allowed_endpoints() (see CustomerUser above — the always-allowed floor
    plus whatever pages the admin granted them), redirect them to their
    portal. Separately, a brand-new Google sign-up (needs_profile_details)
    is held on the profile-completion form until they've given us a phone
    number and address, before they can go anywhere else at all.

    Admin routes (/admin/*, /api/*) are always skipped — they have their
    own session guard and the customer session is irrelevant there.
    This prevents the customer session from interfering with admin MFA setup
    or any other admin-only workflow.
    """
    user_id = session.get("customer_user_id")
    if not user_id:
        return  # not logged in as a customer — no restriction

    endpoint = request.endpoint
    # Skip for static files, missing endpoints, and ALL admin/API routes
    if not endpoint or endpoint == "static":
        return
    if request.path.startswith("/admin") or request.path.startswith("/api"):
        return

    user = CustomerUser.query.get(user_id)
    # After a DB restore the stored ID may point to the wrong row — re-anchor
    # by email (the stable identity used everywhere else) if needed.
    session_email = session.get("customer_email", "")
    if (not user or not user.is_active) and session_email:
        user = CustomerUser.query.filter_by(email=session_email).first()
        if user and user.is_active:
            session["customer_user_id"] = user.id
    if not user or not user.is_active:
        return
    if user.needs_profile_details and endpoint not in {"customer_complete_profile", "customer_logout"}:
        return redirect(url_for("customer_complete_profile"))
    if endpoint not in user.allowed_endpoints():
        flash("You don't have permission to view that page.", "error")
        return redirect(url_for("customer_portal"))


# ---------------------------------------------------------------------------
# Public site routes
# ---------------------------------------------------------------------------

@app.route("/healthz")
def healthz():
    # Deliberately does no DB/disk work — this exists to be pinged often (by
    # the keep-alive thread below, and/or an external uptime monitor)
    # without costing much each time it's hit.
    return "OK", 200


@app.route("/")
def home():
    latest_posts = (
        Post.query.filter_by(is_published=True)
        .order_by(Post.created_at.desc())
        .limit(3)
        .all()
    )
    return render_template("home.html", latest_posts=latest_posts)


@app.route("/about-us")
def about_us():
    return render_template("about_us.html")


@app.route("/contact-us", methods=["GET", "POST"])
def contact_us():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        message = request.form.get("message", "").strip()
        if not email:
            flash("Please enter your email address.", "error")
        else:
            send_contact_email(name, email, message)
            # Also mirror it into the admin Mailbox — the contact form IS
            # mail to CONTACT_RECIPIENT_EMAIL, so it belongs in the same
            # inbox view as everything forwarded from the real mailbox.
            db.session.add(MailboxMessage(
                direction="inbound",
                thread_key=email.lower(),
                from_name=name or None,
                from_email=email,
                to_email=CONTACT_RECIPIENT_EMAIL,
                subject=f"Contact form message from {name or 'website visitor'}",
                body_text=message,
                is_read=False,
            ))
            db.session.commit()
            flash(f"Thanks {name or 'there'}! Your message has been received. "
                  f"We'll get back to you at {email} soon.", "success")
        return redirect(url_for("contact_us"))
    customer_id = session.get("customer_user_id")
    prefill = CustomerUser.query.get(customer_id) if customer_id else None
    return render_template("contact_us.html", intro_text=get_page_content("contact-intro"), prefill=prefill)


@app.route("/book-a-pickup", methods=["GET", "POST"])
def book_a_pickup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        pickup_date_raw = request.form.get("pickup_date", "").strip()
        time_window = request.form.get("time_window", "").strip()
        box_count_raw = request.form.get("box_count", "").strip()
        notes = request.form.get("notes", "").strip()

        errors = []
        if not name:
            errors.append("Please enter your name.")
        if not email:
            errors.append("Please enter your email address.")
        if not phone:
            errors.append("Please enter a contact number.")
        if not address:
            errors.append("Please enter the pickup address.")
        if time_window not in PICKUP_TIME_WINDOWS:
            errors.append("Please choose a preferred pickup time.")

        pickup_date = None
        if not pickup_date_raw:
            errors.append("Please choose a pickup date.")
        else:
            try:
                pickup_date = datetime.strptime(pickup_date_raw, "%Y-%m-%d").date()
                if pickup_date < datetime.utcnow().date():
                    errors.append("Pickup date can't be in the past.")
            except ValueError:
                errors.append("Please choose a valid pickup date.")

        box_count = None
        if box_count_raw:
            try:
                box_count = max(1, min(99, int(box_count_raw)))
            except ValueError:
                errors.append("Number of boxes must be a number.")

        if errors:
            for error in errors:
                flash(error, "error")
            customer_id = session.get("customer_user_id")
            prefill = CustomerUser.query.get(customer_id) if customer_id else None
            return render_template(
                "book_a_pickup.html", time_windows=PICKUP_TIME_WINDOWS, form=request.form, prefill=prefill,
            )

        def _create_pickup_and_mailbox_entry():
            pickup = PickupRequest(
                name=name, email=email, phone=phone, address=address,
                pickup_date=pickup_date, time_window=time_window,
                box_count=box_count, notes=notes or None,
            )
            db.session.add(pickup)
            db.session.flush()  # get pickup.id before referencing it below, if ever needed
            # Mirror into the admin Mailbox too, same reasoning as the contact
            # form: this IS an email to CONTACT_RECIPIENT_EMAIL, so it belongs
            # in the same inbox view as everything else sent to the business.
            db.session.add(MailboxMessage(
                direction="inbound",
                thread_key=email.lower(),
                from_name=name,
                from_email=email,
                to_email=CONTACT_RECIPIENT_EMAIL,
                subject=f"Pickup request from {name}",
                body_text=(
                    f"Pickup address: {address}\n"
                    f"Preferred date: {pickup_date.strftime('%B %d, %Y')}\n"
                    f"Preferred time: {time_window}\n"
                    f"Number of boxes: {box_count or '(not specified)'}\n"
                    f"Phone: {phone}\n\n"
                    f"Notes:\n{notes or '(none)'}"
                ),
                is_read=False,
            ))
            return pickup

        pickup = commit_with_sequence_repair(
            _create_pickup_and_mailbox_entry, ["pickup_request", "mailbox_message"],
        )

        send_pickup_request_email(pickup)
        send_pickup_confirmation_to_customer(pickup)

        flash(
            f"Thanks {name}! Your pickup request for {pickup_date.strftime('%B %d, %Y')} "
            f"has been received — we'll confirm the details with you shortly.", "success",
        )
        return redirect(url_for("book_a_pickup"))

    customer_id = session.get("customer_user_id")
    prefill = CustomerUser.query.get(customer_id) if customer_id else None
    return render_template("book_a_pickup.html", time_windows=PICKUP_TIME_WINDOWS, form={}, prefill=prefill)


@app.route("/privacy-policy")
def privacy_policy():
    return render_template("privacy_policy.html", page_body=get_page_content("privacy-policy"))


@app.route("/terms-and-conditions")
def terms_and_conditions():
    return render_template("terms_and_conditions.html", page_body=get_page_content("terms-and-conditions"))


@app.route("/empty-box-sales")
def empty_box_sales():
    products = (
        Product.query.filter_by(category="box", is_available=True)
        .order_by(Product.created_at.desc())
        .all()
    )
    return render_template("empty_box_sales.html", products=products)


@app.route("/packaging-items")
def packaging_items():
    products = (
        Product.query.filter_by(category="packaging", is_available=True)
        .order_by(Product.created_at.desc())
        .all()
    )
    return render_template("packaging_items.html", products=products)


@app.route("/cart/add/<int:product_id>", methods=["POST"])
def cart_add(product_id):
    product = Product.query.get_or_404(product_id)
    if product.price is None or not product.is_available:
        flash("Sorry, that item isn't available for online purchase — please contact us instead.", "error")
        return redirect(request.referrer or url_for("home"))

    try:
        quantity = int(request.form.get("quantity", 1))
    except ValueError:
        quantity = 1
    quantity = max(1, min(99, quantity))

    cart = session.get(CART_SESSION_KEY, {})
    key = str(product_id)
    cart[key] = min(99, cart.get(key, 0) + quantity)
    session[CART_SESSION_KEY] = cart
    flash(f"Added {product.name} to your cart.", "success")
    return redirect(request.referrer or url_for("cart_view"))


@app.route("/cart")
def cart_view():
    items = get_cart_items()
    subtotal = sum((item["subtotal"] for item in items), Decimal("0.00"))
    tax = calculate_hst(subtotal)
    total = subtotal + tax
    return render_template(
        "cart.html", items=items, subtotal=subtotal, tax=tax, total=total, hst_rate=HST_RATE,
    )


@app.route("/cart/update/<int:product_id>", methods=["POST"])
def cart_update(product_id):
    cart = session.get(CART_SESSION_KEY, {})
    key = str(product_id)
    try:
        quantity = int(request.form.get("quantity", 0))
    except ValueError:
        quantity = 0
    if quantity <= 0:
        cart.pop(key, None)
        flash("Item removed from your cart.", "success")
    else:
        cart[key] = min(99, quantity)
        flash("Cart updated.", "success")
    session[CART_SESSION_KEY] = cart
    return redirect(url_for("cart_view"))


@app.route("/cart/remove/<int:product_id>", methods=["POST"])
def cart_remove(product_id):
    cart = session.get(CART_SESSION_KEY, {})
    cart.pop(str(product_id), None)
    session[CART_SESSION_KEY] = cart
    flash("Item removed from your cart.", "success")
    return redirect(url_for("cart_view"))


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    items = get_cart_items()
    if not items:
        flash("Your cart is empty.", "error")
        return redirect(url_for("cart_view"))
    subtotal = sum((item["subtotal"] for item in items), Decimal("0.00"))
    tax = calculate_hst(subtotal)
    total = subtotal + tax

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        notes = request.form.get("notes", "").strip()
        if not name or not email:
            flash("Name and email are required.", "error")
            return render_template(
                "checkout.html", items=items, subtotal=subtotal, tax=tax, total=total, hst_rate=HST_RATE,
            )

        def _create_order_and_items():
            order = Order(
                order_number=generate_order_number(),
                customer_name=name,
                customer_email=email,
                customer_phone=phone or None,
                shipping_address=address or None,
                notes=notes or None,
                tax_amount=tax,
                total=total,
            )
            db.session.add(order)
            db.session.flush()  # get order.id before adding items
            for item in items:
                db.session.add(OrderItem(
                    order_id=order.id,
                    product_id=item["product"].id,
                    product_name=item["product"].name,
                    unit_price=item["product"].price,
                    quantity=item["quantity"],
                ))
            return order

        order = commit_with_sequence_repair(_create_order_and_items, ["order", "order_item"])
        session[CART_SESSION_KEY] = {}

        _send_order_emails(order)

        return redirect(url_for("order_confirmation", order_number=order.order_number))

    customer_id = session.get("customer_user_id")
    prefill = CustomerUser.query.get(customer_id) if customer_id else None
    return render_template(
        "checkout.html", items=items, subtotal=subtotal, tax=tax, total=total, hst_rate=HST_RATE, prefill=prefill,
    )


@app.route("/order-confirmation/<order_number>")
def order_confirmation(order_number):
    order = Order.query.filter_by(order_number=order_number).first_or_404()
    return render_template("order_confirmation.html", order=order)


@app.route("/order-confirmation/<order_number>/invoice.pdf")
def order_invoice(order_number):
    # order_number is generated with `secrets` (see the Order model) so
    # knowing it is already treated as proof of ownership everywhere else on
    # this page — same rule applies here, no separate login needed.
    order = Order.query.filter_by(order_number=order_number).first_or_404()
    return _order_invoice_pdf_response(order)


@app.route("/rates")
def rates():
    return render_template("rates.html")


@app.route("/sari-sari")
def sari_sari():
    products = (
        Product.query.filter_by(category="sari-sari", is_available=True)
        .order_by(Product.created_at.desc())
        .all()
    )
    return render_template("sari_sari.html", products=products)


@app.route("/updates")
def updates():
    posts = Post.query.filter_by(is_published=True).order_by(Post.created_at.desc()).all()
    return render_template("updates.html", posts=posts)


@app.route("/updates/<int:post_id>")
def update_detail(post_id):
    post = Post.query.get_or_404(post_id)
    if not post.is_published and not session.get("is_admin"):
        abort(404)
    return render_template("update_detail.html", post=post)


@app.route("/track", methods=["GET"])
def track():
    return render_template("track.html")


@app.route("/newsletter-signup", methods=["POST"])
def newsletter_signup():
    email = request.form.get("newsletter_email", "").strip().lower()
    name = request.form.get("newsletter_name", "").strip() or None
    address = request.form.get("newsletter_address", "").strip() or None
    phone = request.form.get("newsletter_phone", "").strip() or None
    if not email:
        flash("Please enter a valid email to subscribe.", "error")
        return redirect(request.referrer or url_for("home"))

    existing = Subscriber.query.filter_by(email=email).first()
    if existing:
        # Refresh their details in case they're re-subscribing with updated info.
        existing.name = name or existing.name
        existing.address = address or existing.address
        existing.phone = phone or existing.phone
        db.session.commit()
        flash(f"You're already subscribed, {email}!", "success")
    else:
        db.session.add(Subscriber(email=email, name=name, address=address, phone=phone))
        db.session.commit()
        flash(f"Thanks for subscribing, {email}!", "success")

    # The newsletter list (Subscriber) and the customer portal (CustomerUser)
    # are deliberately separate — subscribing doesn't create a login. But if
    # this email doesn't already have a portal account, nudge them toward
    # one (with their address/phone already carried over if they gave it in
    # the footer form) instead of just silently adding them to a list they
    # can't do anything else with.
    if not CustomerUser.query.filter_by(email=email).first():
        flash(
            "Want to track orders and pickups too? Create a free account below — "
            "we've already filled in your email.",
            "success",
        )
        return redirect(url_for("customer_login", tab="register", email=email))
    return redirect(request.referrer or url_for("home"))


# ---------------------------------------------------------------------------
# Admin routes (owner-only: create / edit / delete posts)
# ---------------------------------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        identity = _match_admin_credentials(username, password)
        if identity:
            next_url = request.args.get("next") or url_for("admin_dashboard")
            if mfa_is_enabled(identity):
                # Password's right, but there's a second step before the
                # session is actually marked in — see admin_login_verify().
                # mfa_pending is what proves that step is allowed to run.
                session["mfa_pending"] = True
                session["mfa_pending_identity"] = identity
                session["mfa_pending_next"] = next_url
                return redirect(url_for("admin_login_verify"))
            session.permanent = True  # use the 30-day PERMANENT_SESSION_LIFETIME
            session["is_admin"] = True
            session["admin_identity"] = identity
            flash("Logged in.", "success")
            return redirect(next_url)
        flash("Incorrect username or password.", "error")
    return render_template("admin/login.html")


@app.route("/admin/login/verify", methods=["GET", "POST"])
def admin_login_verify():
    """Second step of admin login, only reached once the username/password
    check in admin_login() has already passed (session["mfa_pending"]
    proves it) and only when that account has 2FA turned on."""
    identity = session.get("mfa_pending_identity")
    if not session.get("mfa_pending") or not identity:
        return redirect(url_for("admin_login"))
    if request.method == "POST":
        code = request.form.get("code", "")
        if verify_mfa_code(identity, code):
            next_url = session.pop("mfa_pending_next", None) or url_for("admin_dashboard")
            session.pop("mfa_pending", None)
            session.pop("mfa_pending_identity", None)
            session.permanent = True
            session["is_admin"] = True
            session["admin_identity"] = identity
            flash("Logged in.", "success")
            return redirect(next_url)
        flash("That code didn't match. You can also use one of your backup codes.", "error")
    return render_template("admin/login_verify.html")


@app.route("/admin/login/verify/cancel")
def admin_login_verify_cancel():
    session.pop("mfa_pending", None)
    session.pop("mfa_pending_identity", None)
    session.pop("mfa_pending_next", None)
    return redirect(url_for("admin_login"))


@app.route("/admin/logout")
def admin_logout():
    session.pop("is_admin", None)
    session.pop("admin_identity", None)
    flash("Logged out.", "success")
    return redirect(url_for("home"))


@app.route("/admin")
@login_required
def admin_dashboard():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("admin/dashboard.html", posts=posts)


@app.route("/admin/posts/new", methods=["GET", "POST"])
@login_required
def admin_post_new():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        is_published = bool(request.form.get("is_published"))
        if not title or not body:
            flash("Title and body are required.", "error")
            return render_template("admin/post_form.html", post=None)
        filename = save_uploaded_image(request.files.get("image"))
        post = Post(title=title, body=body, image_filename=filename, is_published=is_published)
        db.session.add(post)
        db.session.commit()
        flash("Post created.", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin/post_form.html", post=None)


@app.route("/admin/posts/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def admin_post_edit(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        body = request.form.get("body", "").strip()
        is_published = bool(request.form.get("is_published"))
        if not title or not body:
            flash("Title and body are required.", "error")
            return render_template("admin/post_form.html", post=post)
        new_filename = save_uploaded_image(request.files.get("image"))
        if new_filename:
            old_filename = post.image_filename
            post.image_filename = new_filename
            delete_uploaded_image(old_filename)
        post.title = title
        post.body = body
        post.is_published = is_published
        db.session.commit()
        flash("Post updated.", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin/post_form.html", post=post)


@app.route("/admin/posts/<int:post_id>/delete", methods=["POST"])
@login_required
def admin_post_delete(post_id):
    post = Post.query.get_or_404(post_id)
    delete_uploaded_image(post.image_filename)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/mailbox")
@login_required
@owner_required
def admin_mailbox():
    # One row per conversation (thread_key), showing that conversation's
    # most recent message, newest conversation first.
    latest_ids = (
        db.session.query(
            MailboxMessage.thread_key,
            db.func.max(MailboxMessage.id).label("latest_id"),
        )
        .group_by(MailboxMessage.thread_key)
        .subquery()
    )
    threads = (
        MailboxMessage.query.join(
            latest_ids, MailboxMessage.id == latest_ids.c.latest_id
        )
        .order_by(MailboxMessage.created_at.desc())
        .all()
    )
    unread_counts = dict(
        db.session.query(MailboxMessage.thread_key, db.func.count(MailboxMessage.id))
        .filter_by(direction="inbound", is_read=False)
        .group_by(MailboxMessage.thread_key)
        .all()
    )
    return render_template(
        "admin/mailbox.html", threads=threads, unread_counts=unread_counts,
    )


@app.route("/admin/mailbox/<thread_key>")
@login_required
@owner_required
def admin_mailbox_thread(thread_key):
    thread_key = thread_key.lower()
    messages = (
        MailboxMessage.query.filter_by(thread_key=thread_key)
        .order_by(MailboxMessage.created_at.asc())
        .all()
    )
    if not messages:
        abort(404)

    unread = [m for m in messages if m.direction == "inbound" and not m.is_read]
    if unread:
        for m in unread:
            m.is_read = True
        db.session.commit()

    counterpart_name = next(
        (m.from_name for m in reversed(messages) if m.direction == "inbound" and m.from_name),
        None,
    )
    return render_template(
        "admin/mailbox_thread.html",
        messages=messages, thread_key=thread_key,
        counterpart_name=counterpart_name,
    )


@app.route("/admin/mailbox/<thread_key>/reply", methods=["POST"])
@login_required
@owner_required
def admin_mailbox_reply(thread_key):
    thread_key = thread_key.lower()
    if not MailboxMessage.query.filter_by(thread_key=thread_key).first():
        abort(404)
    body = request.form.get("body", "").strip()
    if not body:
        flash("Reply can't be empty.", "error")
        return redirect(url_for("admin_mailbox_thread", thread_key=thread_key))
    subject = request.form.get("subject", "").strip() or "Re: your message"
    _, error = _send_mailbox_reply(thread_key, thread_key, subject, body)
    flash(error, "error") if error else flash("Reply sent.", "success")
    return redirect(url_for("admin_mailbox_thread", thread_key=thread_key))


@app.route("/admin/mailbox/compose", methods=["GET", "POST"])
@login_required
@owner_required
def admin_mailbox_compose():
    if request.method == "POST":
        to_email = request.form.get("to_email", "").strip().lower()
        subject = request.form.get("subject", "").strip()
        body = request.form.get("body", "").strip()
        if not to_email or "@" not in to_email:
            flash("Enter a valid recipient email address.", "error")
        elif not subject or not body:
            flash("Subject and message can't be empty.", "error")
        else:
            _, error = _send_mailbox_reply(to_email, to_email, subject, body)
            if error:
                flash(error, "error")
            else:
                flash("Message sent.", "success")
                return redirect(url_for("admin_mailbox_thread", thread_key=to_email))
    return render_template("admin/mailbox_compose.html")


@app.route("/admin/mailbox/<thread_key>/delete", methods=["POST"])
@login_required
@owner_required
def admin_mailbox_thread_delete(thread_key):
    """Delete an entire conversation (every message with this thread_key)."""
    thread_key = thread_key.lower()
    deleted = MailboxMessage.query.filter_by(thread_key=thread_key).delete()
    db.session.commit()
    if deleted:
        flash("Conversation deleted.", "success")
    else:
        flash("That conversation was already gone.", "error")
    return redirect(url_for("admin_mailbox"))


@app.route("/admin/mailbox/<thread_key>/message/<int:message_id>/delete", methods=["POST"])
@login_required
@owner_required
def admin_mailbox_message_delete(thread_key, message_id):
    """Delete a single message within a conversation, without deleting the
    whole thread. If it was the last message in the thread, go back to the
    Mailbox list instead of a now-empty thread page."""
    thread_key = thread_key.lower()
    message = MailboxMessage.query.filter_by(id=message_id, thread_key=thread_key).first_or_404()
    db.session.delete(message)
    db.session.commit()
    flash("Message deleted.", "success")
    remaining = MailboxMessage.query.filter_by(thread_key=thread_key).first()
    if remaining:
        return redirect(url_for("admin_mailbox_thread", thread_key=thread_key))
    return redirect(url_for("admin_mailbox"))


@app.route("/admin/mailbox/clear-all", methods=["POST"])
@login_required
@owner_required
def admin_mailbox_clear_all():
    """Delete every message in the Mailbox — every conversation, gone.
    Requires typing the confirmation phrase in the form (checked here, not
    just in JS) since this can't be undone."""
    confirm = request.form.get("confirm", "").strip()
    if confirm != "DELETE ALL":
        flash('Type "DELETE ALL" exactly to confirm — nothing was deleted.', "error")
        return redirect(url_for("admin_mailbox"))
    count = MailboxMessage.query.delete()
    db.session.commit()
    flash(f"Deleted {count} message(s) — Mailbox is now empty.", "success")
    return redirect(url_for("admin_mailbox"))


@app.route("/admin/orders")
@login_required
@owner_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("admin/orders.html", orders=orders)


@app.route("/admin/orders/<int:order_id>")
@login_required
@owner_required
def admin_order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template("admin/order_detail.html", order=order, statuses=ORDER_STATUSES)


@app.route("/admin/orders/<int:order_id>/status", methods=["POST"])
@login_required
@owner_required
def admin_order_update_status(order_id):
    order = Order.query.get_or_404(order_id)
    status = request.form.get("status", "").strip()
    if status not in ORDER_STATUSES:
        flash("Invalid status.", "error")
    else:
        order.status = status
        db.session.commit()
        send_order_status_email(order)
        flash("Order status updated.", "success")
    return redirect(url_for("admin_order_detail", order_id=order.id))


@app.route("/admin/orders/<int:order_id>/invoice.pdf")
@login_required
@owner_required
def admin_order_invoice(order_id):
    order = Order.query.get_or_404(order_id)
    return _order_invoice_pdf_response(order)


# --- Manual invoices (admin only) -------------------------------------------
# For anything that isn't a normal product order: a custom shipment, a
# favour, whatever else the owner needs to bill for. Typed in by hand, but
# renders through the same invoice PDF as an automatic Order invoice.

@app.route("/admin/invoices")
@login_required
@owner_required
def admin_invoices():
    invoices = ManualInvoice.query.order_by(ManualInvoice.created_at.desc()).all()
    return render_template("admin/invoices.html", invoices=invoices)


@app.route("/admin/invoices/new", methods=["GET", "POST"])
@login_required
@owner_required
def admin_invoice_new():
    if request.method == "POST":
        customer_name = request.form.get("customer_name", "").strip()
        customer_email = request.form.get("customer_email", "").strip()
        customer_address = request.form.get("customer_address", "").strip()
        issue_date_raw = request.form.get("issue_date", "").strip()
        apply_tax = bool(request.form.get("apply_tax"))
        notes = request.form.get("notes", "").strip()

        descriptions = request.form.getlist("item_description")
        quantities = request.form.getlist("item_quantity")
        unit_prices = request.form.getlist("item_unit_price")

        errors = []
        if not customer_name:
            errors.append("Please enter a bill-to name.")

        issue_date = None
        if not issue_date_raw:
            errors.append("Please choose an invoice date.")
        else:
            try:
                issue_date = datetime.strptime(issue_date_raw, "%Y-%m-%d").date()
            except ValueError:
                errors.append("Please choose a valid invoice date.")

        line_items = []
        for description, qty_raw, price_raw in zip(descriptions, quantities, unit_prices):
            description = description.strip()
            qty_raw = qty_raw.strip()
            price_raw = price_raw.strip()
            if not description and not price_raw:
                continue  # an unused row — quantity defaults to 1 even when untouched
            if not description:
                errors.append("Every line item needs a description.")
                continue
            try:
                quantity = Decimal(qty_raw or "1")
                unit_price = Decimal(price_raw or "0")
            except InvalidOperation:
                errors.append(f'Invalid quantity or price for "{description}".')
                continue
            if quantity <= 0 or unit_price < 0:
                errors.append(f'Quantity and price for "{description}" must be positive.')
                continue
            line_items.append((description, quantity, unit_price))

        if not line_items:
            errors.append("Add at least one line item.")

        if errors:
            for error in errors:
                flash(error, "error")
            return render_template(
                "admin/invoice_form.html", form=request.form,
                today=datetime.utcnow().date().isoformat(),
            )

        invoice = ManualInvoice(
            invoice_number="TEMP",
            customer_name=customer_name,
            customer_email=customer_email or None,
            customer_address=customer_address or None,
            issue_date=issue_date,
            apply_tax=apply_tax,
            notes=notes or None,
        )
        db.session.add(invoice)
        db.session.flush()  # assigns invoice.id so the invoice_number below can use it
        invoice.invoice_number = f"INV-{1000 + invoice.id}"
        for description, quantity, unit_price in line_items:
            db.session.add(ManualInvoiceItem(
                invoice_id=invoice.id, description=description,
                quantity=quantity, unit_price=unit_price,
            ))
        db.session.commit()
        flash(f"Invoice {invoice.invoice_number} created.", "success")
        return redirect(url_for("admin_invoice_detail", invoice_id=invoice.id))

    return render_template(
        "admin/invoice_form.html", form=request.form,
        today=datetime.utcnow().date().isoformat(),
    )


@app.route("/admin/invoices/<int:invoice_id>")
@login_required
@owner_required
def admin_invoice_detail(invoice_id):
    invoice = ManualInvoice.query.get_or_404(invoice_id)
    return render_template("admin/invoice_detail.html", invoice=invoice)


@app.route("/admin/invoices/<int:invoice_id>/pdf")
@login_required
@owner_required
def admin_invoice_pdf(invoice_id):
    invoice = ManualInvoice.query.get_or_404(invoice_id)
    return _manual_invoice_pdf_response(invoice)


@app.route("/admin/invoices/<int:invoice_id>/delete", methods=["POST"])
@login_required
@owner_required
def admin_invoice_delete(invoice_id):
    invoice = ManualInvoice.query.get_or_404(invoice_id)
    db.session.delete(invoice)
    db.session.commit()
    flash("Invoice deleted.", "success")
    return redirect(url_for("admin_invoices"))


@app.route("/admin/pickups")
@login_required
@owner_required
def admin_pickups():
    pickups = PickupRequest.query.order_by(PickupRequest.pickup_date.asc()).all()
    return render_template("admin/pickups.html", pickups=pickups, statuses=PICKUP_STATUSES)


@app.route("/admin/pickups/<int:pickup_id>/status", methods=["POST"])
@login_required
@owner_required
def admin_pickup_update_status(pickup_id):
    pickup = PickupRequest.query.get_or_404(pickup_id)
    status = request.form.get("status", "").strip()
    if status not in PICKUP_STATUSES:
        flash("Invalid status.", "error")
    else:
        pickup.status = status
        db.session.commit()
        send_pickup_status_email(pickup)
        flash("Pickup status updated.", "success")
    return redirect(url_for("admin_pickups"))


@app.route("/admin/pickups/<int:pickup_id>")
@login_required
@owner_required
def admin_pickup_detail(pickup_id):
    pickup = PickupRequest.query.get_or_404(pickup_id)
    return render_template("admin/pickup_detail.html", pickup=pickup, statuses=PICKUP_STATUSES)


@app.route("/admin/pickups/<int:pickup_id>/invoice", methods=["POST"])
@login_required
@owner_required
def admin_pickup_invoice_upload(pickup_id):
    pickup = PickupRequest.query.get_or_404(pickup_id)
    uploaded = request.files.get("invoice")
    if not uploaded or not uploaded.filename:
        flash("Please choose a file to upload.", "error")
        return redirect(url_for("admin_pickup_detail", pickup_id=pickup.id))
    new_filename = save_uploaded_image(
        uploaded, prefix="invoices", allowed_extensions=INVOICE_EXTENSIONS,
    )
    if new_filename:
        delete_uploaded_image(pickup.invoice_filename)
        pickup.invoice_filename = new_filename
        db.session.commit()
        flash("Invoice uploaded — the customer will see it on their My Account page.", "success")
    # If new_filename is None, save_uploaded_image already flashed why.
    return redirect(url_for("admin_pickup_detail", pickup_id=pickup.id))


@app.route("/admin/pickups/<int:pickup_id>/invoice/remove", methods=["POST"])
@login_required
@owner_required
def admin_pickup_invoice_remove(pickup_id):
    pickup = PickupRequest.query.get_or_404(pickup_id)
    delete_uploaded_image(pickup.invoice_filename)
    pickup.invoice_filename = None
    db.session.commit()
    flash("Invoice removed.", "success")
    return redirect(url_for("admin_pickup_detail", pickup_id=pickup.id))


@app.route("/admin/subscribers")
@login_required
@owner_required
def admin_subscribers():
    subscribers = Subscriber.query.order_by(Subscriber.created_at.desc()).all()
    return render_template("admin/subscribers.html", subscribers=subscribers)


@app.route("/admin/subscribers/export.csv")
@login_required
@owner_required
def admin_subscribers_export():
    subscribers = Subscriber.query.order_by(Subscriber.created_at.asc()).all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["name", "email", "address", "phone", "subscribed_at"])
    for subscriber in subscribers:
        writer.writerow([
            subscriber.name or "", subscriber.email, subscriber.address or "",
            subscriber.phone or "", subscriber.created_at.isoformat(),
        ])
    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=subscribers.csv"},
    )


@app.route("/admin/subscribers/<int:subscriber_id>/delete", methods=["POST"])
@login_required
@owner_required
def admin_subscriber_delete(subscriber_id):
    subscriber = Subscriber.query.get_or_404(subscriber_id)
    db.session.delete(subscriber)
    db.session.commit()
    flash("Subscriber removed.", "success")
    return redirect(url_for("admin_subscribers"))


@app.route("/admin/pages")
@login_required
def admin_pages():
    pages = PageContent.query.order_by(PageContent.slug).all()
    return render_template("admin/pages.html", pages=pages)


@app.route("/admin/pages/<slug>/edit", methods=["GET", "POST"])
@login_required
def admin_page_edit(slug):
    page = PageContent.query.get_or_404(slug)
    if request.method == "POST":
        body = request.form.get("body", "").strip()
        if not body:
            flash("Page text can't be empty.", "error")
        else:
            page.body = body
            db.session.commit()
            flash(f'"{page.label}" updated.', "success")
            return redirect(url_for("admin_pages"))
    return render_template("admin/page_form.html", page=page)


@app.route("/admin/products")
@login_required
def admin_products():
    category = request.args.get("category", "").strip()
    query = Product.query
    if category in PRODUCT_CATEGORY_VALUES:
        query = query.filter_by(category=category)
    products = query.order_by(Product.created_at.desc()).all()
    return render_template(
        "admin/products.html", products=products, categories=PRODUCT_CATEGORIES,
        active_category=category,
    )


def _parse_price(raw_price):
    """Returns (price_or_none, error_message_or_none)."""
    raw_price = (raw_price or "").strip()
    if not raw_price:
        return None, None
    try:
        price = float(raw_price)
    except ValueError:
        return None, "Price must be a number (or leave it blank for “contact for pricing”)."
    if price < 0:
        return None, "Price can't be negative."
    return price, None


@app.route("/admin/products/new", methods=["GET", "POST"])
@login_required
def admin_product_new():
    if request.method == "POST":
        category = request.form.get("category", "")
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        is_available = bool(request.form.get("is_available"))
        price, price_error = _parse_price(request.form.get("price"))

        if category not in PRODUCT_CATEGORY_VALUES or not name:
            flash("Please choose a category and enter a name.", "error")
            return render_template(
                "admin/product_form.html", product=None, categories=PRODUCT_CATEGORIES
            )
        if price_error:
            flash(price_error, "error")
            return render_template(
                "admin/product_form.html", product=None, categories=PRODUCT_CATEGORIES
            )

        filename = save_uploaded_image(request.files.get("image"))
        product = Product(
            category=category, name=name, description=description or None,
            price=price, image_filename=filename, is_available=is_available,
        )
        db.session.add(product)
        db.session.commit()
        flash("Product created.", "success")
        return redirect(url_for("admin_products"))

    return render_template("admin/product_form.html", product=None, categories=PRODUCT_CATEGORIES)


@app.route("/admin/products/<int:product_id>/edit", methods=["GET", "POST"])
@login_required
def admin_product_edit(product_id):
    product = Product.query.get_or_404(product_id)
    if request.method == "POST":
        category = request.form.get("category", "")
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        is_available = bool(request.form.get("is_available"))
        price, price_error = _parse_price(request.form.get("price"))

        if category not in PRODUCT_CATEGORY_VALUES or not name:
            flash("Please choose a category and enter a name.", "error")
            return render_template(
                "admin/product_form.html", product=product, categories=PRODUCT_CATEGORIES
            )
        if price_error:
            flash(price_error, "error")
            return render_template(
                "admin/product_form.html", product=product, categories=PRODUCT_CATEGORIES
            )

        new_filename = save_uploaded_image(request.files.get("image"))
        if new_filename:
            old_filename = product.image_filename
            product.image_filename = new_filename
            delete_uploaded_image(old_filename)

        product.category = category
        product.name = name
        product.description = description or None
        product.price = price
        product.is_available = is_available
        db.session.commit()
        flash("Product updated.", "success")
        return redirect(url_for("admin_products"))

    return render_template("admin/product_form.html", product=product, categories=PRODUCT_CATEGORIES)


@app.route("/admin/products/<int:product_id>/delete", methods=["POST"])
@login_required
def admin_product_delete(product_id):
    product = Product.query.get_or_404(product_id)
    # order_item.product_id is nullable — clear any references first so
    # Postgres doesn't raise a FK violation. The order history is preserved
    # because product_name and unit_price are stored as snapshot columns.
    OrderItem.query.filter_by(product_id=product_id).update({"product_id": None})
    delete_uploaded_image(product.image_filename)
    db.session.delete(product)
    db.session.commit()
    flash("Product deleted.", "success")
    return redirect(url_for("admin_products"))


@app.route("/admin/settings", methods=["GET", "POST"])
@login_required
def admin_settings():
    if request.method == "POST":
        uploaded = request.files.get("favicon")
        if not uploaded or not uploaded.filename:
            flash("Please choose an image file to upload.", "error")
            return redirect(url_for("admin_settings"))
        new_filename = save_uploaded_image(
            uploaded, prefix="branding", allowed_extensions=FAVICON_EXTENSIONS,
        )
        if new_filename:
            old_filename = get_setting("favicon_filename")
            set_setting("favicon_filename", new_filename)
            db.session.commit()
            delete_uploaded_image(old_filename)
            flash("Site icon updated.", "success")
        # If new_filename is None, save_uploaded_image already flashed why
        # (bad file type).
        return redirect(url_for("admin_settings"))
    return render_template(
        "admin/settings.html",
        social_platforms=SOCIAL_PLATFORMS,
        mfa_enabled=mfa_is_enabled(session.get("admin_identity", "owner")),
        # Freshly (re)generated backup codes, shown exactly once, right here
        # on Settings — see admin_settings_mfa_setup and
        # admin_settings_mfa_regenerate_backup_codes. Popped from the
        # session so a page reload never shows them twice; the plaintext is
        # never stored anywhere retrievable after this, only its hash.
        new_backup_codes=session.pop("mfa_new_backup_codes", None),
    )


@app.route("/admin/settings/favicon/remove", methods=["POST"])
@login_required
def admin_settings_remove_favicon():
    old_filename = get_setting("favicon_filename")
    if old_filename:
        delete_uploaded_image(old_filename)
        set_setting("favicon_filename", None)
        db.session.commit()
        flash("Site icon removed — back to the default.", "success")
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/social", methods=["POST"])
@login_required
def admin_settings_social():
    for key, _label in SOCIAL_PLATFORMS:
        value = (request.form.get(key) or "").strip()
        set_setting(key, value or None)
    db.session.commit()
    flash("Social media links updated.", "success")
    return redirect(url_for("admin_settings"))


# ---------------------------------------------------------------------------
# Two-factor authentication setup (web admin + mobile app both check the
# Setting rows this writes — see the comment above ADMIN_USERNAME).
# ---------------------------------------------------------------------------

@app.route("/admin/settings/mfa/enable", methods=["POST"])
@login_required
def admin_settings_mfa_enable():
    """Step 1: generate a new secret and send the current account to the
    QR/confirm page. Nothing is active yet — the pending secret isn't
    checked by any login route, only the confirmed one is, and that's only
    set once this account proves it's actually scanned it
    (admin_settings_mfa_setup)."""
    identity = session.get("admin_identity", "owner")
    if mfa_is_enabled(identity):
        return redirect(url_for("admin_settings"))
    secret = pyotp.random_base32()
    set_setting(_mfa_setting_key("mfa_totp_secret_pending", identity), secret)
    return redirect(url_for("admin_settings_mfa_setup"))


def _admin_display_username(identity):
    return ADMIN_ACCOUNTS.get(identity, {}).get("username") or ADMIN_USERNAME


def _admin_account_label(identity):
    return ADMIN_ACCOUNTS.get(identity, {}).get("label") or identity.capitalize()


@app.route("/admin/settings/mfa/setup", methods=["GET", "POST"])
@login_required
def admin_settings_mfa_setup():
    identity = session.get("admin_identity", "owner")
    pending_secret = get_setting(_mfa_setting_key("mfa_totp_secret_pending", identity))
    if not pending_secret:
        flash("Start two-factor setup from Settings first.", "error")
        return redirect(url_for("admin_settings"))
    if request.method == "POST":
        code = request.form.get("code", "")
        if _totp_for_secret(pending_secret).verify((code or "").strip(), valid_window=1):
            set_setting(_mfa_setting_key("mfa_totp_secret", identity), pending_secret)
            set_setting(_mfa_setting_key("mfa_enabled", identity), "1")
            set_setting(_mfa_setting_key("mfa_totp_secret_pending", identity), None)
            session["mfa_new_backup_codes"] = generate_backup_codes(identity)
            flash("Two-factor authentication is on.", "success")
            return redirect(url_for("admin_settings"))
        flash("That code didn't match — double check the time on your phone and try again.", "error")
    # Distinguishing issuer names ("... — Owner" / "... — Admin 2" / "...
    # — Creator") so each configured account shows up as a separate entry
    # in an authenticator app that ends up holding more than one of them.
    provisioning_uri = _totp_for_secret(pending_secret).provisioning_uri(
        name=_admin_display_username(identity),
        issuer_name=f"{COMPANY['name']} — {_admin_account_label(identity)}",
    )
    return render_template(
        "admin/mfa_setup.html", secret=pending_secret, provisioning_uri=provisioning_uri,
    )


@app.route("/admin/settings/mfa/setup/qr.png")
@login_required
def admin_settings_mfa_qr():
    identity = session.get("admin_identity", "owner")
    pending_secret = get_setting(_mfa_setting_key("mfa_totp_secret_pending", identity))
    if not pending_secret:
        abort(404)
    uri = _totp_for_secret(pending_secret).provisioning_uri(
        name=_admin_display_username(identity),
        issuer_name=f"{COMPANY['name']} — {_admin_account_label(identity)}",
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return Response(buf.getvalue(), mimetype="image/png")


@app.route("/admin/settings/mfa/setup/cancel", methods=["POST"])
@login_required
def admin_settings_mfa_setup_cancel():
    set_setting(_mfa_setting_key("mfa_totp_secret_pending", session.get("admin_identity", "owner")), None)
    flash("Two-factor setup cancelled — nothing was turned on.", "success")
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/mfa/backup-codes/regenerate", methods=["POST"])
@login_required
def admin_settings_mfa_regenerate_backup_codes():
    """Regenerates this account's backup codes and sends them straight back
    to Settings — admin_settings() below pops them out of the session and
    shows them once, inline, in the Two-Factor Authentication card (see the
    note above generate_backup_codes about why there's no way to show them
    again after that)."""
    identity = session.get("admin_identity", "owner")
    if not mfa_is_enabled(identity):
        return redirect(url_for("admin_settings"))
    session["mfa_new_backup_codes"] = generate_backup_codes(identity)
    flash("New backup codes generated — your old ones no longer work.", "success")
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/mfa/disable", methods=["POST"])
@login_required
def admin_settings_mfa_disable():
    """Requires the current password again (not just today's already-open
    session) as a speed bump against someone at an unlocked screen turning
    2FA off. Checked against whichever account is currently logged in."""
    identity = session.get("admin_identity", "owner")
    password = request.form.get("password", "")
    expected_password = ADMIN_ACCOUNTS.get(identity, {}).get("password", "")
    if not expected_password or not secrets.compare_digest(password, expected_password):
        flash("Incorrect password — two-factor authentication was not disabled.", "error")
        return redirect(url_for("admin_settings"))
    set_setting(_mfa_setting_key("mfa_enabled", identity), None)
    set_setting(_mfa_setting_key("mfa_totp_secret", identity), None)
    set_setting(_mfa_setting_key("mfa_totp_secret_pending", identity), None)
    set_setting(_mfa_setting_key("mfa_backup_codes", identity), None)
    flash("Two-factor authentication is off.", "success")
    return redirect(url_for("admin_settings"))


# ---------------------------------------------------------------------------
# Backup / Restore
# ---------------------------------------------------------------------------
# Two independent backup types:
#   - Database backup: a JSON export of every table row — portable across
#     Postgres and SQLite, and safe to import on a fresh install.
#   - Files backup: a ZIP of static/uploads/, static/branding/, and static/invoices/ —
#     product images, the favicon, and any admin-uploaded pickup invoices.
#
# Restore works the same way in reverse: upload the file that was downloaded,
# and the server applies it. Database restore is additive for Settings (merges
# by key) and replaces rows for everything else to avoid duplicates.
# ---------------------------------------------------------------------------

def _db_export_json():
    """Serialize every table to a plain Python dict tree, return as JSON bytes."""
    from sqlalchemy import inspect as sa_inspect
    inspector = sa_inspect(db.engine)
    table_names = inspector.get_table_names()
    dump = {}
    with db.engine.connect() as conn:
        for table in table_names:
            rows = conn.execute(text(f'SELECT * FROM "{table}"')).mappings().all()
            dump[table] = [dict(r) for r in rows]
    # datetime/date/Decimal objects aren't JSON-serialisable by default
    import datetime as dt
    def _serial(obj):
        if isinstance(obj, (dt.datetime, dt.date)):
            return obj.isoformat()
        if isinstance(obj, Decimal):
            return str(obj)
        raise TypeError(f"Type {type(obj)} not serialisable")
    return json.dumps(dump, default=_serial, indent=2).encode("utf-8")


def _db_import_json(data_bytes):
    """Import a JSON database dump.  Settings are upserted; all other tables
    are truncated then re-inserted so restoring is idempotent.
    Tables are restored in dependency order (parents before children) and
    foreign-key checks are deferred for the duration of the transaction."""
    dump = json.loads(data_bytes.decode("utf-8"))

    # Build a dependency-ordered list of table names so parent tables are
    # inserted before child tables that reference them via FK.
    from sqlalchemy import inspect as sa_inspect, MetaData
    meta = MetaData()
    meta.reflect(bind=db.engine)

    def _topo_sort(tables_meta):
        """Kahn's algorithm on FK edges → topological order."""
        deps = {t.name: set() for t in tables_meta}
        for t in tables_meta:
            for fk in t.foreign_keys:
                parent = fk.column.table.name
                if parent != t.name:
                    deps[t.name].add(parent)
        ordered, remaining = [], list(deps.keys())
        seen = set()
        # Up to len passes to resolve all deps
        for _ in range(len(remaining) + 1):
            progress = False
            for name in list(remaining):
                if deps[name] <= seen:
                    ordered.append(name)
                    seen.add(name)
                    remaining.remove(name)
                    progress = True
            if not remaining:
                break
            if not progress:
                # Circular FK — just append the rest as-is
                ordered.extend(remaining)
                break
        return ordered

    ordered_tables = _topo_sort(list(meta.tables.values()))

    with db.engine.begin() as conn:
        # Disable FK checks for the session so we can truncate freely.
        # Postgres uses SET CONSTRAINTS, SQLite uses PRAGMA.
        dialect = db.engine.dialect.name
        if dialect == "postgresql":
            conn.execute(text("SET CONSTRAINTS ALL DEFERRED"))
        elif dialect == "sqlite":
            conn.execute(text("PRAGMA foreign_keys = OFF"))

        # Delete in reverse order (children first) to satisfy FKs even
        # when SET CONSTRAINTS DEFERRED isn't fully supported by the driver.
        for table in reversed(ordered_tables):
            if table not in dump or not dump[table]:
                continue
            try:
                conn.execute(text(f'DELETE FROM "{table}"'))
            except Exception:
                pass  # table may not exist yet on a brand-new install

        # Insert in dependency order (parents first)
        for table in ordered_tables:
            rows = dump.get(table)
            if not rows:
                continue
            if table == "setting":
                for row in rows:
                    existing = conn.execute(
                        text(f'SELECT 1 FROM "{table}" WHERE key = :k'),
                        {"k": row["key"]},
                    ).fetchone()
                    if existing:
                        conn.execute(
                            text(f'UPDATE "{table}" SET value = :v WHERE key = :k'),
                            {"v": row["value"], "k": row["key"]},
                        )
                    else:
                        cols = ", ".join(f'"{c}"' for c in row)
                        placeholders = ", ".join(f":{c}" for c in row)
                        conn.execute(
                            text(f'INSERT INTO "{table}" ({cols}) VALUES ({placeholders})'),
                            row,
                        )
            else:
                for row in rows:
                    cols = ", ".join(f'"{c}"' for c in row)
                    placeholders = ", ".join(f":{c}" for c in row)
                    conn.execute(
                        text(f'INSERT INTO "{table}" ({cols}) VALUES ({placeholders})'),
                        row,
                    )

        if dialect == "sqlite":
            conn.execute(text("PRAGMA foreign_keys = ON"))

        # --- Fix up auto-increment sequences (Postgres only) --------------
        # We just inserted rows with explicit "id" values from the backup.
        # Postgres's own id sequence for each table has no idea this
        # happened — it still thinks the next id is wherever it left off
        # before the restore. Left alone, the very next ORM insert (a new
        # order, a new pickup request, etc.) reuses an id that already
        # exists in the freshly-restored table and fails with a duplicate
        # key / unique violation. Setting each sequence to MAX(id)+1 avoids
        # that. SQLite doesn't use sequences this way, so this is skipped
        # there — its rowid-based autoincrement already picks up correctly.
        if dialect == "postgresql":
            for table in ordered_tables:
                if "id" not in meta.tables[table].columns:
                    continue
                try:
                    conn.execute(text(
                        f'SELECT setval('
                        f"pg_get_serial_sequence('\"{table}\"', 'id'), "
                        f'COALESCE((SELECT MAX(id) FROM "{table}"), 0) + 1, false)'
                    ))
                except Exception:
                    # Table has no "id" serial/identity sequence (e.g. a
                    # string primary key like Setting.key) — nothing to fix.
                    pass


@app.route("/admin/settings/fix-sequences", methods=["POST"])
@login_required
def admin_fix_sequences():
    """One-off repair tool: resets every table's Postgres id sequence to
    MAX(id)+1. Use this if a database restore was done before this fix
    existed, and new records (orders, pickups, products, etc.) are failing
    to save with a duplicate-key error. No-op and harmless on SQLite."""
    if db.engine.dialect.name != "postgresql":
        flash("This only applies to Postgres — nothing to fix on this database.", "success")
        return redirect(url_for("admin_settings"))
    try:
        from sqlalchemy import MetaData
        meta = MetaData()
        meta.reflect(bind=db.engine)
        fixed = []
        with db.engine.begin() as conn:
            for table_name, table in meta.tables.items():
                if "id" not in table.columns:
                    continue
                try:
                    conn.execute(text(
                        f'SELECT setval('
                        f"pg_get_serial_sequence('\"{table_name}\"', 'id'), "
                        f'COALESCE((SELECT MAX(id) FROM "{table_name}"), 0) + 1, false)'
                    ))
                    fixed.append(table_name)
                except Exception:
                    pass
        flash(f"Sequences fixed for {len(fixed)} table(s). New records should save normally now.", "success")
    except Exception as exc:
        flash(f"Sequence fix failed: {exc}", "error")
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/backup/database")
@login_required
def admin_backup_database():
    """Download a JSON snapshot of the entire database."""
    try:
        payload = _db_export_json()
    except Exception as exc:
        flash(f"Database backup failed: {exc}", "error")
        return redirect(url_for("admin_settings"))
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return Response(
        payload,
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=rgc-db-backup-{stamp}.json",
            "Content-Length": len(payload),
        },
    )


@app.route("/admin/settings/backup/files")
@login_required
def admin_backup_files():
    """Download a ZIP of all uploaded static files (uploads, branding, invoices)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for subfolder in ("uploads", "branding", "invoices"):
            folder_path = os.path.join(app.static_folder, subfolder)
            if not os.path.isdir(folder_path):
                continue
            for root, _dirs, files in os.walk(folder_path):
                for fname in files:
                    abs_path = os.path.join(root, fname)
                    arc_name = os.path.relpath(abs_path, app.static_folder)
                    zf.write(abs_path, arc_name)
    buf.seek(0)
    payload = buf.read()
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return Response(
        payload,
        mimetype="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=rgc-files-backup-{stamp}.zip",
            "Content-Length": len(payload),
        },
    )


@app.route("/admin/settings/restore/database", methods=["POST"])
@login_required
def admin_restore_database():
    """Restore the database from a previously downloaded JSON backup."""
    uploaded = request.files.get("db_backup")
    if not uploaded or not uploaded.filename:
        flash("Please choose a JSON backup file to upload.", "error")
        return redirect(url_for("admin_settings"))
    if not uploaded.filename.lower().endswith(".json"):
        flash("Database restore expects a .json file (downloaded from Database Backup).", "error")
        return redirect(url_for("admin_settings"))
    data = uploaded.read()
    try:
        _db_import_json(data)
    except Exception as exc:
        flash(f"Database restore failed: {exc}", "error")
        return redirect(url_for("admin_settings"))
    flash(
        "Database restored successfully. If settings look wrong, reload the page.",
        "success",
    )
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/restore/files", methods=["POST"])
@login_required
def admin_restore_files():
    """Restore uploaded files from a previously downloaded ZIP backup."""
    uploaded = request.files.get("files_backup")
    if not uploaded or not uploaded.filename:
        flash("Please choose a ZIP backup file to upload.", "error")
        return redirect(url_for("admin_settings"))
    if not uploaded.filename.lower().endswith(".zip"):
        flash("Files restore expects a .zip file (downloaded from Files Backup).", "error")
        return redirect(url_for("admin_settings"))
    data = uploaded.read()
    try:
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf, "r") as zf:
            for member in zf.namelist():
                # Only allow uploads/, branding/, and invoices/ paths — no path traversal
                norm = os.path.normpath(member)
                if norm.startswith("..") or (
                    not norm.startswith("uploads") and not norm.startswith("branding")
                    and not norm.startswith("invoices")
                ):
                    continue
                dest = os.path.join(app.static_folder, norm)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with zf.open(member) as src, open(dest, "wb") as dst:
                    dst.write(src.read())
    except Exception as exc:
        flash(f"Files restore failed: {exc}", "error")
        return redirect(url_for("admin_settings"))
    flash("Files restored successfully.", "success")
    return redirect(url_for("admin_settings"))


# ---------------------------------------------------------------------------
# Mobile API (JSON, for the companion Android manager app)
#
# Read-only-ish: lets the owner see Orders, Pickup Requests, and the Mailbox
# and update Order/Pickup status from their phone. Auth is a Bearer token
# from /api/v1/login (see api_login_required above), not the browser session
# cookie the rest of /admin/* uses. Mailbox stays read-only here too, same as
# the web admin panel — no reply/compose (see MailboxMessage's docstring).
# ---------------------------------------------------------------------------

def _iso(dt):
    """Naive UTC datetimes (everything in this app uses datetime.utcnow())
    formatted as ISO-8601 with an explicit Z, so the Android app can parse
    them unambiguously as UTC."""
    return (dt.isoformat() + "Z") if dt else None


def _order_to_dict(order, include_items=False):
    data = {
        "id": order.id,
        "order_number": order.order_number,
        "customer_name": order.customer_name,
        "customer_email": order.customer_email,
        "customer_phone": order.customer_phone,
        "shipping_address": order.shipping_address,
        "notes": order.notes,
        "subtotal": str(order.subtotal),
        "tax_amount": str(order.tax_amount) if order.tax_amount is not None else None,
        "total": str(order.total),
        "status": order.status,
        "item_count": len(order.items),
        "created_at": _iso(order.created_at),
        "updated_at": _iso(order.updated_at),
    }
    if include_items:
        data["items"] = [
            {
                "product_name": item.product_name,
                "unit_price": str(item.unit_price),
                "quantity": item.quantity,
                "subtotal": str(item.subtotal),
            }
            for item in order.items
        ]
    return data


def _manual_invoice_to_dict(invoice):
    return {
        "id": invoice.id,
        "invoice_number": invoice.invoice_number,
        "customer_name": invoice.customer_name,
        "customer_email": invoice.customer_email,
        "total": str(invoice.total),
        "created_at": _iso(invoice.created_at),
    }


def _pickup_to_dict(pickup):
    return {
        "id": pickup.id,
        "name": pickup.name,
        "email": pickup.email,
        "phone": pickup.phone,
        "address": pickup.address,
        "pickup_date": pickup.pickup_date.isoformat() if pickup.pickup_date else None,
        "time_window": pickup.time_window,
        "box_count": pickup.box_count,
        "notes": pickup.notes,
        "status": pickup.status,
        "created_at": _iso(pickup.created_at),
    }


def _mailbox_message_to_dict(message):
    return {
        "id": message.id,
        "direction": message.direction,
        "from_name": message.from_name,
        "from_email": message.from_email,
        "to_email": message.to_email,
        "subject": message.subject,
        "body_text": message.body_text,
        "is_read": message.is_read,
        "created_at": _iso(message.created_at),
    }


def _product_to_dict(product):
    return {
        "id": product.id,
        "category": product.category,
        "category_label": product.category_label,
        "name": product.name,
        "description": product.description,
        "price": str(product.price) if product.price is not None else None,
        "image_url": url_for("static", filename=product.image_filename, _external=True)
            if product.image_filename else None,
        "is_available": product.is_available,
        "created_at": _iso(product.created_at),
        "updated_at": _iso(product.updated_at),
    }


def _subscriber_to_dict(subscriber):
    return {
        "id": subscriber.id,
        "email": subscriber.email,
        "name": subscriber.name,
        "address": subscriber.address,
        "phone": subscriber.phone,
        "created_at": _iso(subscriber.created_at),
    }


def _parse_bool_field(raw):
    return (raw or "").strip().lower() in ("1", "true", "on", "yes")


@app.route("/api/v1/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or request.form
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    identity = _match_admin_credentials(username, password)
    if not identity:
        return jsonify(error="Incorrect username or password."), 401
    if mfa_is_enabled(identity):
        # Same TOTP/backup-code setup as the web login (see the Setting
        # rows documented above ADMIN_USERNAME). The app sends this as an
        # optional "totp" field alongside username/password; a live 6-digit
        # authenticator code or an unused backup code both work (see
        # verify_mfa_code). mfa_required=True tells the app "prompt for a
        # code and retry the same request with it filled in" — that's a
        # different situation from a wrong username/password, which is
        # still the plain error above with no mfa_required flag.
        code = (data.get("totp") or "").strip()
        if not verify_mfa_code(identity, code):
            return jsonify(
                error="A verification code is required." if not code else "Incorrect verification code.",
                mfa_required=True,
            ), 401
    # "id" (owner/creator) is what api_login_required reads back into
    # flask.g and api_owner_required checks — see both above.
    token = _mobile_token_serializer.dumps({"u": username, "id": identity})
    return jsonify(
        token=token,
        username=username,
        company_name=COMPANY["name"],
        expires_in_seconds=MOBILE_TOKEN_MAX_AGE_SECONDS,
    )


@app.route("/api/v1/me")
@api_login_required
def api_me():
    return jsonify(
        username=g.admin_username,
        company_name=COMPANY["name"],
        # Kept the same for both accounts rather than trimmed down for the
        # creator: these are just status label lists and quick-reply
        # templates, not customer data, and api_me is the one endpoint
        # every screen calls regardless of role (it's what the
        # owner-only-gated screens use to build their dropdowns) — this
        # response is shared, so narrowing it here would break those
        # screens for the owner too.
        order_statuses=ORDER_STATUSES,
        pickup_statuses=PICKUP_STATUSES,
        product_categories=[{"value": v, "label": l} for v, l in PRODUCT_CATEGORIES],
        quick_replies=[{"label": l, "body": b} for l, b in QUICK_REPLIES],
    )


@app.route("/api/v1/summary")
@api_login_required
@api_owner_required
def api_summary():
    orders_awaiting_payment = Order.query.filter_by(status="Awaiting Payment").count()
    pickups_requested = PickupRequest.query.filter_by(status="Requested").count()
    mailbox_unread_threads = (
        db.session.query(db.func.count(db.func.distinct(MailboxMessage.thread_key)))
        .filter_by(direction="inbound", is_read=False)
        .scalar()
    ) or 0
    return jsonify(
        orders_awaiting_payment=orders_awaiting_payment,
        pickups_requested=pickups_requested,
        mailbox_unread_threads=mailbox_unread_threads,
    )


@app.route("/api/v1/orders")
@api_login_required
@api_owner_required
def api_orders():
    query = Order.query
    status = request.args.get("status", "").strip()
    if status:
        if status not in ORDER_STATUSES:
            return jsonify(error="Invalid status filter."), 400
        query = query.filter_by(status=status)
    orders = query.order_by(Order.created_at.desc()).all()
    return jsonify(
        orders=[_order_to_dict(o) for o in orders],
        statuses=ORDER_STATUSES,
    )


@app.route("/api/v1/orders/<int:order_id>")
@api_login_required
@api_owner_required
def api_order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify(order=_order_to_dict(order, include_items=True))


@app.route("/api/v1/orders/<int:order_id>/status", methods=["POST"])
@api_login_required
@api_owner_required
def api_order_update_status(order_id):
    order = Order.query.get_or_404(order_id)
    data = request.get_json(silent=True) or {}
    status = (data.get("status") or "").strip()
    if status not in ORDER_STATUSES:
        return jsonify(error="Invalid status."), 400
    order.status = status
    db.session.commit()
    send_order_status_email(order)
    return jsonify(order=_order_to_dict(order, include_items=True))


@app.route("/api/v1/orders/<int:order_id>/invoice.pdf")
@api_login_required
@api_owner_required
def api_order_invoice(order_id):
    order = Order.query.get_or_404(order_id)
    response = _order_invoice_pdf_response(order)
    response.headers["Content-Disposition"] = f'attachment; filename="invoice-{order.order_number}.pdf"'
    return response


@app.route("/api/v1/invoices/manual", methods=["POST"])
@api_login_required
@api_owner_required
def api_manual_invoice():
    """Mirrors the web admin's /admin/invoices/new (see ManualInvoice above)
    so the companion Android app's manual-invoice screen creates a real,
    persisted invoice — it shows up in the web admin's Invoices list too,
    same as one entered there. The one thing this endpoint does NOT do is
    send an email: this project has no SMTP-sending code path wired up for
    invoices, so `send_email` is accepted (so older/newer app builds don't
    break) but always comes back as emailed=False."""
    data = request.get_json(silent=True) or {}

    customer_name = (data.get("customer_name") or "").strip()
    customer_email = (data.get("customer_email") or "").strip()
    customer_phone = (data.get("customer_phone") or "").strip() or None
    shipping_address = (data.get("shipping_address") or "").strip() or None

    if not customer_name:
        return jsonify(error="Enter a customer name."), 400
    if not customer_email or "@" not in customer_email:
        return jsonify(error="Enter a valid customer email address."), 400

    raw_items = data.get("items")
    if not isinstance(raw_items, list) or not raw_items:
        return jsonify(error="Add at least one line item."), 400

    line_items = []
    subtotal = Decimal("0.00")
    for raw in raw_items:
        name = (raw.get("name") or "").strip() if isinstance(raw, dict) else ""
        if not name:
            return jsonify(error="Every line item needs a name."), 400
        try:
            quantity = int(raw.get("quantity"))
            if quantity < 1:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify(error=f'"{name}" needs a quantity of at least 1.'), 400
        try:
            unit_price = Decimal(str(raw.get("unit_price"))).quantize(Decimal("0.01"))
            if unit_price < 0:
                raise InvalidOperation
        except (TypeError, ValueError, InvalidOperation):
            return jsonify(error=f'"{name}" has an invalid price.'), 400
        item_subtotal = unit_price * quantity
        subtotal += item_subtotal
        line_items.append((name, Decimal(quantity), unit_price))

    tax_override = None
    raw_tax = data.get("tax_amount")
    if isinstance(raw_tax, str):
        raw_tax = raw_tax.strip()
    if raw_tax not in (None, ""):
        try:
            tax_override = Decimal(str(raw_tax)).quantize(Decimal("0.01"))
            if tax_override < 0:
                raise InvalidOperation
        except (TypeError, ValueError, InvalidOperation):
            return jsonify(error="Tax amount must be a number, or leave it blank."), 400

    invoice = ManualInvoice(
        invoice_number="TEMP",
        customer_name=customer_name,
        customer_email=customer_email,
        customer_phone=customer_phone,
        customer_address=shipping_address,
        issue_date=datetime.utcnow().date(),
        apply_tax=False,
        tax_override=tax_override,
    )
    db.session.add(invoice)
    db.session.flush()
    invoice.invoice_number = f"INV-{1000 + invoice.id}"
    for name, quantity, unit_price in line_items:
        db.session.add(ManualInvoiceItem(
            invoice_id=invoice.id, description=name, quantity=quantity, unit_price=unit_price,
        ))
    db.session.commit()

    bill_to = [invoice.customer_name, invoice.customer_email]
    if invoice.customer_phone:
        bill_to.append(invoice.customer_phone)
    if invoice.customer_address:
        bill_to.extend(line for line in invoice.customer_address.splitlines() if line.strip())
    items = [
        [
            item.description, _format_invoice_quantity(item.quantity),
            f"${item.unit_price:.2f}", f"${item.line_total:.2f}",
        ]
        for item in invoice.items
    ]
    pdf_buffer = render_invoice_pdf(
        invoice_number=invoice.invoice_number,
        issue_date=invoice.issue_date,
        bill_to_lines=bill_to,
        items=items,
        subtotal=invoice.subtotal,
        tax_label=invoice.tax_label,
        tax_amount=(invoice.tax_amount if invoice.has_tax else None),
        total=invoice.total,
    )

    response = Response(
        pdf_buffer.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="invoice-{invoice.invoice_number}.pdf"'},
    )
    response.headers["X-Invoice-Number"] = invoice.invoice_number
    response.headers["X-Invoice-Emailed"] = "false"
    return response


@app.route("/api/v1/invoices")
@api_login_required
@api_owner_required
def api_invoices():
    """Lists manual invoices for the app's Invoices tab — including ones
    created from the web admin at /admin/invoices/new, not just ones the
    app itself created via POST /api/v1/invoices/manual above."""
    invoices = ManualInvoice.query.order_by(ManualInvoice.created_at.desc()).all()
    return jsonify(invoices=[_manual_invoice_to_dict(i) for i in invoices])


@app.route("/api/v1/invoices/<int:invoice_id>/pdf")
@api_login_required
@api_owner_required
def api_invoice_pdf(invoice_id):
    invoice = ManualInvoice.query.get_or_404(invoice_id)
    response = _manual_invoice_pdf_response(invoice)
    response.headers["Content-Disposition"] = f'attachment; filename="invoice-{invoice.invoice_number}.pdf"'
    return response


@app.route("/api/v1/pickups")
@api_login_required
@api_owner_required
def api_pickups():
    query = PickupRequest.query
    status = request.args.get("status", "").strip()
    if status:
        if status not in PICKUP_STATUSES:
            return jsonify(error="Invalid status filter."), 400
        query = query.filter_by(status=status)
    pickups = query.order_by(PickupRequest.pickup_date.asc()).all()
    return jsonify(
        pickups=[_pickup_to_dict(p) for p in pickups],
        statuses=PICKUP_STATUSES,
    )


@app.route("/api/v1/pickups/<int:pickup_id>")
@api_login_required
@api_owner_required
def api_pickup_detail(pickup_id):
    pickup = PickupRequest.query.get_or_404(pickup_id)
    return jsonify(pickup=_pickup_to_dict(pickup))


@app.route("/api/v1/pickups/<int:pickup_id>/status", methods=["POST"])
@api_login_required
@api_owner_required
def api_pickup_update_status(pickup_id):
    pickup = PickupRequest.query.get_or_404(pickup_id)
    data = request.get_json(silent=True) or {}
    status = (data.get("status") or "").strip()
    if status not in PICKUP_STATUSES:
        return jsonify(error="Invalid status."), 400
    pickup.status = status
    db.session.commit()
    send_pickup_status_email(pickup)
    return jsonify(pickup=_pickup_to_dict(pickup))


@app.route("/api/v1/mailbox")
@api_login_required
@api_owner_required
def api_mailbox():
    # Same "one row per conversation, newest first" shape as /admin/mailbox.
    latest_ids = (
        db.session.query(
            MailboxMessage.thread_key,
            db.func.max(MailboxMessage.id).label("latest_id"),
        )
        .group_by(MailboxMessage.thread_key)
        .subquery()
    )
    threads = (
        MailboxMessage.query.join(
            latest_ids, MailboxMessage.id == latest_ids.c.latest_id
        )
        .order_by(MailboxMessage.created_at.desc())
        .all()
    )
    unread_counts = dict(
        db.session.query(MailboxMessage.thread_key, db.func.count(MailboxMessage.id))
        .filter_by(direction="inbound", is_read=False)
        .group_by(MailboxMessage.thread_key)
        .all()
    )
    return jsonify(threads=[
        {
            "thread_key": t.thread_key,
            "from_name": t.from_name,
            "from_email": t.from_email,
            "subject": t.subject,
            "preview": t.preview,
            "unread_count": unread_counts.get(t.thread_key, 0),
            "created_at": _iso(t.created_at),
        }
        for t in threads
    ])


@app.route("/api/v1/mailbox/<thread_key>")
@api_login_required
@api_owner_required
def api_mailbox_thread(thread_key):
    thread_key = thread_key.lower()
    messages = (
        MailboxMessage.query.filter_by(thread_key=thread_key)
        .order_by(MailboxMessage.created_at.asc())
        .all()
    )
    if not messages:
        abort(404)

    # Opening a thread marks it read, same as the web admin panel.
    unread = [m for m in messages if m.direction == "inbound" and not m.is_read]
    if unread:
        for m in unread:
            m.is_read = True
        db.session.commit()

    counterpart_name = next(
        (m.from_name for m in reversed(messages) if m.direction == "inbound" and m.from_name),
        None,
    )
    return jsonify(
        thread_key=thread_key,
        counterpart_name=counterpart_name,
        messages=[_mailbox_message_to_dict(m) for m in messages],
    )


@app.route("/api/v1/mailbox/<thread_key>/reply", methods=["POST"])
@api_login_required
@api_owner_required
def api_mailbox_reply(thread_key):
    thread_key = thread_key.lower()
    if not MailboxMessage.query.filter_by(thread_key=thread_key).first():
        abort(404)
    data = request.get_json(silent=True) or {}
    body = (data.get("body") or "").strip()
    if not body:
        return jsonify(error="Reply can't be empty."), 400
    subject = (data.get("subject") or "").strip() or "Re: your message"
    message, error = _send_mailbox_reply(thread_key, thread_key, subject, body)
    if error:
        return jsonify(error=error), 502
    return jsonify(message=_mailbox_message_to_dict(message))


@app.route("/api/v1/mailbox/compose", methods=["POST"])
@api_login_required
@api_owner_required
def api_mailbox_compose():
    data = request.get_json(silent=True) or {}
    to_email = (data.get("to_email") or "").strip().lower()
    subject = (data.get("subject") or "").strip()
    body = (data.get("body") or "").strip()
    if not to_email or "@" not in to_email:
        return jsonify(error="Enter a valid recipient email address."), 400
    if not subject or not body:
        return jsonify(error="Subject and message can't be empty."), 400
    message, error = _send_mailbox_reply(to_email, to_email, subject, body)
    if error:
        return jsonify(error=error), 502
    return jsonify(thread_key=to_email, message=_mailbox_message_to_dict(message))


@app.route("/api/v1/mailbox/<thread_key>/delete", methods=["POST"])
@api_login_required
@api_owner_required
def api_mailbox_thread_delete(thread_key):
    thread_key = thread_key.lower()
    deleted = MailboxMessage.query.filter_by(thread_key=thread_key).delete()
    db.session.commit()
    return jsonify(ok=True, deleted_count=deleted)


@app.route("/api/v1/mailbox/<thread_key>/message/<int:message_id>/delete", methods=["POST"])
@api_login_required
@api_owner_required
def api_mailbox_message_delete(thread_key, message_id):
    thread_key = thread_key.lower()
    message = MailboxMessage.query.filter_by(id=message_id, thread_key=thread_key).first_or_404()
    db.session.delete(message)
    db.session.commit()
    return jsonify(ok=True)


@app.route("/api/v1/products")
@api_login_required
def api_products():
    query = Product.query
    category = request.args.get("category", "").strip()
    if category:
        if category not in PRODUCT_CATEGORY_VALUES:
            return jsonify(error="Invalid category filter."), 400
        query = query.filter_by(category=category)
    products = query.order_by(Product.created_at.desc()).all()
    return jsonify(
        products=[_product_to_dict(p) for p in products],
        categories=[{"value": v, "label": l} for v, l in PRODUCT_CATEGORIES],
    )


@app.route("/api/v1/products/<int:product_id>")
@api_login_required
def api_product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify(product=_product_to_dict(product))


@app.route("/api/v1/products", methods=["POST"])
@api_login_required
def api_product_create():
    category = request.form.get("category", "")
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    is_available = _parse_bool_field(request.form.get("is_available"))
    price, price_error = _parse_price(request.form.get("price"))

    if category not in PRODUCT_CATEGORY_VALUES or not name:
        return jsonify(error="Please choose a category and enter a name."), 400
    if price_error:
        return jsonify(error=price_error), 400

    filename = save_uploaded_image(request.files.get("image"))
    product = Product(
        category=category, name=name, description=description or None,
        price=price, image_filename=filename, is_available=is_available,
    )
    db.session.add(product)
    db.session.commit()
    return jsonify(product=_product_to_dict(product)), 201


@app.route("/api/v1/products/<int:product_id>/update", methods=["POST"])
@api_login_required
def api_product_update(product_id):
    product = Product.query.get_or_404(product_id)
    category = request.form.get("category", "")
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    is_available = _parse_bool_field(request.form.get("is_available"))
    price, price_error = _parse_price(request.form.get("price"))

    if category not in PRODUCT_CATEGORY_VALUES or not name:
        return jsonify(error="Please choose a category and enter a name."), 400
    if price_error:
        return jsonify(error=price_error), 400

    new_filename = save_uploaded_image(request.files.get("image"))
    if new_filename:
        old_filename = product.image_filename
        product.image_filename = new_filename
        delete_uploaded_image(old_filename)

    product.category = category
    product.name = name
    product.description = description or None
    product.price = price
    product.is_available = is_available
    db.session.commit()
    return jsonify(product=_product_to_dict(product))


@app.route("/api/v1/products/<int:product_id>/delete", methods=["POST"])
@api_login_required
def api_product_delete(product_id):
    product = Product.query.get_or_404(product_id)
    OrderItem.query.filter_by(product_id=product_id).update({"product_id": None})
    delete_uploaded_image(product.image_filename)
    db.session.delete(product)
    db.session.commit()
    return jsonify(ok=True)


@app.route("/api/v1/subscribers")
@api_login_required
@api_owner_required
def api_subscribers():
    subscribers = Subscriber.query.order_by(Subscriber.created_at.desc()).all()
    return jsonify(subscribers=[_subscriber_to_dict(s) for s in subscribers])


@app.route("/api/v1/subscribers/<int:subscriber_id>/delete", methods=["POST"])
@api_login_required
@api_owner_required
def api_subscriber_delete(subscriber_id):
    subscriber = Subscriber.query.get_or_404(subscriber_id)
    db.session.delete(subscriber)
    db.session.commit()
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# Customer / Staff portal routes
# ---------------------------------------------------------------------------

@app.route("/customer/login", methods=["GET", "POST"])
def customer_login():
    if session.get("customer_user_id"):
        return redirect(url_for("customer_portal"))
    if request.method == "POST":
        action = request.form.get("action", "login")

        if action == "register":
            # --- Self-registration ---
            name = request.form.get("reg_name", "").strip()
            email = request.form.get("reg_email", "").strip().lower()
            password = request.form.get("reg_password", "")
            confirm = request.form.get("reg_confirm", "")
            errors = []
            if not name:
                errors.append("Full name is required.")
            if not email or "@" not in email:
                errors.append("A valid email address is required.")
            if len(password) < 8:
                errors.append("Password must be at least 8 characters.")
            if password != confirm:
                errors.append("Passwords do not match.")
            if not errors and CustomerUser.query.filter_by(email=email).first():
                errors.append("An account with that email already exists. Please log in.")
            if errors:
                for e in errors:
                    flash(e, "error")
                return render_template("customer/login.html", tab="register",
                                       reg_name=name, reg_email=email)
            user = CustomerUser(email=email, name=name, role="customer")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            send_registration_confirmation_email(user)
            session["customer_user_id"] = user.id
            session["customer_user_role"] = user.role
            session["customer_email"] = user.email
            flash(f"Welcome, {user.name}! Your account has been created.", "success")
            return redirect(url_for("customer_portal"))

        # --- Normal login ---
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = CustomerUser.query.filter_by(email=email).first()
        if user and user.is_active and user.check_password(password):
            session["customer_user_id"] = user.id
            session["customer_user_role"] = user.role
            session["customer_email"] = user.email
            flash(f"Welcome back, {user.name}!", "success")
            next_url = request.args.get("next")
            # Only allow safe same-site redirects
            if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("customer_portal"))
        if user and not user.is_active:
            flash("Your account is inactive. Please contact us.", "error")
        else:
            flash("Incorrect email or password.", "error")
    return render_template(
        "customer/login.html", tab=request.args.get("tab", "login"),
        reg_email=request.args.get("email", ""),
    )


@app.route("/customer/forgot-password", methods=["GET", "POST"])
def customer_forgot_password():
    if session.get("customer_user_id"):
        return redirect(url_for("customer_portal"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = CustomerUser.query.filter_by(email=email).first() if email else None
        if user and user.is_active:
            if not send_password_reset_email(user):
                # SMTP isn't configured or the send failed -- _send_email
                # already logged the reason. Tell the customer plainly
                # rather than silently pretending it worked.
                flash(
                    "We couldn't send the reset email right now. Please contact us for help.",
                    "error",
                )
                return render_template("customer/forgot_password.html")
        # Same confirmation whether or not the address is registered, so
        # this can't be used to check who has an account.
        flash(
            "If an account exists for that email address, we've sent a link to reset your password.",
            "success",
        )
        return redirect(url_for("customer_login"))
    return render_template("customer/forgot_password.html")


@app.route("/customer/reset-password/<token>", methods=["GET", "POST"])
def customer_reset_password(token):
    if session.get("customer_user_id"):
        return redirect(url_for("customer_portal"))
    user = verify_password_reset_token(token)
    if not user:
        flash("That password reset link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for("customer_forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            user.set_password(password)
            db.session.commit()
            flash("Your password has been reset. Please sign in.", "success")
            return redirect(url_for("customer_login"))
    return render_template("customer/reset_password.html", token=token)


@app.route("/customer/login/google")
def customer_login_google():
    """Step 1 of "Sign in with Google": send the browser to Google's
    consent screen. See the big comment above GOOGLE_CLIENT_ID for the
    overall flow and setup."""
    if session.get("customer_user_id"):
        return redirect(url_for("customer_portal"))
    if not google_signin_enabled():
        abort(404)
    state = secrets.token_urlsafe(24)
    session["google_oauth_state"] = state
    # Preserve ?next=... across the round trip to Google the same way the
    # normal login form does, so "sign in to continue" links still land
    # the customer back where they started.
    next_url = request.args.get("next")
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        session["google_oauth_next"] = next_url
    else:
        session.pop("google_oauth_next", None)
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": url_for("customer_login_google_callback", _external=True),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    return redirect(f"{GOOGLE_OAUTH_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}")


@app.route("/customer/login/google/callback")
def customer_login_google_callback():
    """Step 2: Google sends the browser back here with a one-time `code`
    (or an `error` if the person cancelled/denied consent). Exchanges that
    code for an access token server-to-server, then calls Google's
    userinfo endpoint with it to find out who signed in — see the comment
    above GOOGLE_CLIENT_ID."""
    if not google_signin_enabled():
        abort(404)
    expected_state = session.pop("google_oauth_state", None)
    next_url = session.pop("google_oauth_next", None)
    got_state = request.args.get("state")
    if not expected_state or not got_state or not secrets.compare_digest(expected_state, got_state):
        flash("That sign-in link expired or was invalid. Please try again.", "error")
        return redirect(url_for("customer_login"))
    if request.args.get("error") or not request.args.get("code"):
        flash("Google sign-in was cancelled.", "error")
        return redirect(url_for("customer_login"))

    code = request.args["code"]
    token_data = urllib.parse.urlencode({
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": url_for("customer_login_google_callback", _external=True),
        "grant_type": "authorization_code",
    }).encode()
    try:
        token_req = urllib.request.Request(GOOGLE_OAUTH_TOKEN_URL, data=token_data, method="POST")
        with urllib.request.urlopen(token_req, timeout=10) as resp:
            token_json = json.loads(resp.read().decode())
        access_token = token_json["access_token"]

        userinfo_req = urllib.request.Request(
            GOOGLE_OAUTH_USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"},
        )
        with urllib.request.urlopen(userinfo_req, timeout=10) as resp:
            profile = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError, ValueError, TimeoutError) as exc:
        app.logger.error("Google sign-in failed during token/userinfo exchange: %s", exc)
        flash("Google sign-in didn't work. Please try again or use your email and password.", "error")
        return redirect(url_for("customer_login"))

    email = (profile.get("email") or "").strip().lower()
    if not email or not profile.get("email_verified"):
        flash("That Google account doesn't have a verified email address.", "error")
        return redirect(url_for("customer_login"))
    name = (profile.get("name") or email.split("@")[0]).strip()
    google_id = profile.get("sub")

    user = CustomerUser.query.filter_by(email=email).first()
    if user:
        if not user.is_active:
            flash("Your account is inactive. Please contact us.", "error")
            return redirect(url_for("customer_login"))
        if not user.google_id:
            user.google_id = google_id  # link the Google account to the existing email/password one
            db.session.commit()
    else:
        user = CustomerUser(email=email, name=name, role="customer", google_id=google_id)
        user.set_password(secrets.token_urlsafe(32))  # unusable random password; "forgot password" can replace it later
        user.needs_profile_details = True
        db.session.add(user)
        db.session.commit()
        send_registration_confirmation_email(user)

    session["customer_user_id"] = user.id
    session["customer_user_role"] = user.role
    session["customer_email"] = user.email
    flash(f"Welcome, {user.name}!", "success")
    if user.needs_profile_details:
        return redirect(url_for("customer_complete_profile"))
    if next_url:
        return redirect(next_url)
    return redirect(url_for("customer_portal"))


@app.route("/customer/complete-profile", methods=["GET", "POST"])
@customer_login_required
def customer_complete_profile():
    """One-time gate for a brand-new Google sign-up: we only got a name
    and email from Google, so before they can use the rest of the site we
    ask for the phone number and address every other part of this app
    assumes a customer has on file (pickups, orders, etc). Accounts that
    registered the normal way never see this — see needs_profile_details
    on CustomerUser and enforce_customer_page_restrictions."""
    user = CustomerUser.query.get(session["customer_user_id"])
    if not user.needs_profile_details:
        return redirect(url_for("customer_portal"))
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        if not phone or not address:
            flash("Please provide both a phone number and an address.", "error")
        else:
            user.phone = phone
            user.address = address
            user.needs_profile_details = False
            db.session.commit()
            flash("Thanks! Your profile is all set.", "success")
            return redirect(url_for("customer_portal"))
    return render_template("customer/complete_profile.html", user=user)


@app.route("/customer/profile", methods=["POST"])
@customer_login_required
def customer_profile_update():
    user = CustomerUser.query.get(session["customer_user_id"])
    name = request.form.get("name", "").strip()
    phone = request.form.get("phone", "").strip()
    address = request.form.get("address", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()
    if not name:
        flash("Name cannot be empty.", "error")
    else:
        user.name = name
        user.phone = phone or None
        user.address = address or None
        if new_password:
            if len(new_password) < 8:
                flash("New password must be at least 8 characters.", "error")
                return redirect(url_for("customer_portal", tab="profile"))
            if new_password != confirm_password:
                flash("Passwords do not match.", "error")
                return redirect(url_for("customer_portal", tab="profile"))
            user.set_password(new_password)
        db.session.commit()
        flash("Profile updated successfully.", "success")
    return redirect(url_for("customer_portal", tab="profile"))


@app.route("/customer/logout")
def customer_logout():
    session.pop("customer_user_id", None)
    session.pop("customer_user_role", None)
    flash("You've been logged out.", "success")
    return redirect(url_for("home"))


@app.route("/customer/portal")
@customer_login_required
def customer_portal():
    user = CustomerUser.query.get(session["customer_user_id"])
    # Show the customer their own orders (matched by email)
    orders = Order.query.filter_by(customer_email=user.email).order_by(
        Order.created_at.desc()
    ).limit(20).all()
    # Show their pickup requests (matched by email)
    pickups = PickupRequest.query.filter_by(email=user.email).order_by(
        PickupRequest.created_at.desc()
    ).limit(10).all()
    return render_template("customer/portal.html", user=user, orders=orders, pickups=pickups)


@app.route("/customer/pickup/<int:pickup_id>/invoice")
@customer_login_required
def customer_pickup_invoice(pickup_id):
    """Serve the admin-uploaded invoice PDF for a pickup, but only to the
    customer whose email matches the pickup — never exposed as a raw static
    file so that guessing a UUID doesn't leak someone else's invoice."""
    user = CustomerUser.query.get(session["customer_user_id"])
    pickup = PickupRequest.query.get_or_404(pickup_id)
    # Use the session email as the authoritative identity — it survives DB
    # restores where row IDs change but the email stays the same.
    session_email = (session.get("customer_email") or (user.email if user else "")).lower().strip()
    pickup_email = (pickup.email or "").lower().strip()
    if not session_email or session_email != pickup_email:
        abort(403)
    if not pickup.invoice_filename:
        flash("No invoice has been uploaded for this pickup yet. Please contact us if you need one.", "error")
        return redirect(url_for("customer_portal", tab="pickups"))
    file_path = os.path.join(app.static_folder, pickup.invoice_filename)
    if not os.path.isfile(file_path):
        flash("The invoice file could not be found. It may have been lost during a server restore — please contact us and we'll re-upload it.", "error")
        return redirect(url_for("customer_portal", tab="pickups"))
    # Derive a tidy download filename: RGC-Invoice-<date>.pdf (or whatever ext)
    ext = pickup.invoice_filename.rsplit(".", 1)[-1].lower()
    date_str = pickup.pickup_date.strftime("%Y%m%d") if pickup.pickup_date else "invoice"
    download_name = f"RGC-Invoice-{date_str}.{ext}"
    from flask import send_file
    return send_file(file_path, as_attachment=True, download_name=download_name)


# ---------------------------------------------------------------------------
# Admin routes: customer/staff user management
# ---------------------------------------------------------------------------

@app.route("/admin/users")
@login_required
@owner_required
def admin_users():
    users = CustomerUser.query.order_by(CustomerUser.created_at.desc()).all()
    return render_template(
        "admin/users.html", users=users,
        total_pages=len(CUSTOMER_TOGGLEABLE_PAGES),
    )


@app.route("/admin/users/new", methods=["GET", "POST"])
@login_required
@owner_required
def admin_user_new():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        page_keys = request.form.getlist("pages")
        if not email or not name or not password:
            flash("Email, name, and password are required.", "error")
        elif CustomerUser.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
        else:
            user = CustomerUser(email=email, name=name, role="customer")
            user.set_password(password)
            user.set_allowed_page_keys(page_keys)
            db.session.add(user)
            db.session.commit()
            flash(f"Account created for {name}.", "success")
            return redirect(url_for("admin_users"))
    return render_template(
        "admin/user_form.html", user=None, pages=CUSTOMER_TOGGLEABLE_PAGES,
        allowed_page_keys=CUSTOMER_TOGGLEABLE_PAGE_KEYS,
    )


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@owner_required
def admin_user_edit(user_id):
    user = CustomerUser.query.get_or_404(user_id)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        is_active = request.form.get("is_active") == "1"
        new_password = request.form.get("password", "").strip()
        page_keys = request.form.getlist("pages")
        if not email or not name:
            flash("Email and name are required.", "error")
        else:
            conflict = CustomerUser.query.filter_by(email=email).first()
            if conflict and conflict.id != user_id:
                flash("Another account already uses that email.", "error")
            else:
                user.name = name
                user.email = email
                user.is_active = is_active
                user.set_allowed_page_keys(page_keys)
                if new_password:
                    user.set_password(new_password)
                db.session.commit()
                flash("Account updated.", "success")
                return redirect(url_for("admin_users"))
    return render_template(
        "admin/user_form.html", user=user, pages=CUSTOMER_TOGGLEABLE_PAGES,
        allowed_page_keys=user.get_allowed_page_keys(),
    )


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@owner_required
def admin_user_delete(user_id):
    user = CustomerUser.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"Account for {user.name} deleted.", "success")
    return redirect(url_for("admin_users"))


@app.errorhandler(404)
def page_not_found(e):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found."), 404
    return render_template("404.html"), 404


if __name__ == "__main__":
    if ADMIN_PASSWORD == "changeme123":
        print("WARNING: using the default admin password. Set the ADMIN_PASSWORD "
              "environment variable before deploying this publicly.")
    if app.secret_key == "rgc-dev-secret-key-change-me":
        print("WARNING: using the default SECRET_KEY. Set a real SECRET_KEY "
              "environment variable (and keep it the same across restarts) "
              "before deploying this publicly.")
    app.run(debug=True, host="0.0.0.0", port=5000)
