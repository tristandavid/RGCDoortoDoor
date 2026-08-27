import csv
import hashlib
import io
import json
import os
import secrets
import smtplib
import string
import threading
import time
import urllib.request
import uuid
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

# --- A second, restricted login for whoever maintains the site (developer/
# technical support), separate from the owner's account above -------------
# Unset by default (both env vars blank) — this login doesn't exist at all
# until you set BOTH CREATOR_USERNAME and CREATOR_PASSWORD. There's no
# insecure default like ADMIN_PASSWORD's "changeme123" here on purpose: a
# second admin door should never be open unless someone deliberately opened
# it.
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


def _match_admin_credentials(username, password):
    """Checks `username`/`password` against both configured admin logins
    and returns the identity string ("owner" or "creator") of whichever one
    matched, or None if neither did. That identity is what everything else
    in this file keys off of: session["admin_identity"] / the "id" claim in
    the mobile token (see admin_login/api_login below), which account's MFA
    Setting rows apply (see verify_mfa_code and friends), and which routes
    are allowed (see owner_required/api_owner_required)."""
    if secrets.compare_digest(username, ADMIN_USERNAME) and secrets.compare_digest(password, ADMIN_PASSWORD):
        return "owner"
    if (
        CREATOR_USERNAME and CREATOR_PASSWORD
        and secrets.compare_digest(username, CREATOR_USERNAME)
        and secrets.compare_digest(password, CREATOR_PASSWORD)
    ):
        return "creator"
    return None


# Identities allowed past owner_required/api_owner_required, i.e. allowed to
# touch Orders/Invoices/Mailbox/Pickups/Subscribers. Only "owner" by
# default; add "creator" here if you'd rather that account have full access
# instead of the technical-only slice described above.
ADMIN_ROLES_FULL_ACCESS = {"owner"}

# --- Two-factor authentication (TOTP), optional -----------------------------
# Off by default — nothing changes for either account until it turns MFA on
# from its own Admin > Site Settings. Once enabled for an account it's
# required on BOTH the web login (/admin/login) and the mobile app login
# (/api/v1/login) for that account specifically.
#
# State lives in the Setting key/value table (see the Setting model), not an
# env var like ADMIN_PASSWORD, because it needs to be turned on/off — and the
# secret regenerated — from the admin UI without a server restart or
# redeploy. Every key below is namespaced by admin identity ("owner" or
# "creator" — see _match_admin_credentials) so the two accounts each enroll
# their own authenticator app and never see each other's codes:
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
# LOCKOUT RECOVERY: there's no "forgot your code" flow for either account.
# If one of them loses their authenticator app AND their backup codes, the
# only way back in is direct database access — connect to the DB (see
# deploy/) and run, e.g. for the owner:
#   UPDATE setting SET value = '0' WHERE key = 'mfa_enabled:owner';
# (substitute 'mfa_enabled:creator' for the other account; or just delete
# the row). That's the exact same trust model as forgetting ADMIN_PASSWORD
# or CREATOR_PASSWORD, just one row over.

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

# Canned one-tap replies shown as quick-reply buttons in the Mailbox (web
# admin and the mobile app). These only ever pre-fill the reply box -- they
# are never sent without the owner reviewing/editing and tapping Send, same
# as a manually typed reply.
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
    ("📅", "Pickups", "admin_pickups", {"admin_pickups"}),
    ("📧", "Subscribers", "admin_subscribers", {"admin_subscribers"}),
    ("👥", "Users", "admin_users",
     {"admin_users", "admin_user_new", "admin_user_edit"}),
    ("🛍️", "Products", "admin_products",
     {"admin_products", "admin_product_new", "admin_product_edit"}),
    ("📄", "Pages", "admin_pages", {"admin_pages", "admin_page_edit"}),
    ("⚙️", "Settings", "admin_settings",
     {"admin_settings", "admin_settings_mfa_setup", "admin_settings_mfa_backup_codes"}),
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
        "admin_sections": visible_admin_sections if is_admin_logged_in else ADMIN_SECTIONS,
        "admin_section": admin_section,
        "current_customer": current_customer,
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
    value = db.Column(db.String(500), nullable=True)


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
# Customer / Staff user accounts
# ---------------------------------------------------------------------------

CUSTOMER_USER_ROLES = ["customer", "staff", "admin"]

# Pages customers can access when logged in as a customer.
# Staff and admin can see everything. Customers only see these endpoints.
CUSTOMER_ALLOWED_ENDPOINTS = {
    "home", "about_us", "contact_us", "rates", "updates", "update_detail",
    "track", "sari_sari", "empty_box_sales", "packaging_items",
    "cart_view", "cart_add", "cart_update", "cart_remove",
    "checkout", "order_confirmation", "order_confirmation_invoice",
    "book_a_pickup", "privacy_policy", "terms_and_conditions",
    "newsletter_signup", "healthz",
    # customer portal endpoints
    "customer_portal", "customer_logout", "customer_login",
    # static files, etc.
    "static",
}


class CustomerUser(db.Model):
    """A site-registered user account (customer, staff, or admin role).

    Separate from the env-var admin credentials (ADMIN_USERNAME/ADMIN_PASSWORD)
    — those are the back-office owner/creator logins that manage the admin
    panel. CustomerUser accounts are for the public-facing portal: customers
    can track their orders and view their purchase history; staff can also
    see the admin panel; admin role gets full admin access.

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
        return {"customer": "Customer", "staff": "Staff", "admin": "Admin"}.get(self.role, self.role.title())


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


with app.app_context():
    db.create_all()
    _ensure_column("order", "tax_amount", "NUMERIC(10, 2)")
    _ensure_column("subscriber", "name", "VARCHAR(200)")
    _ensure_column("subscriber", "address", "VARCHAR(300)")
    _ensure_column("subscriber", "phone", "VARCHAR(50)")
    _ensure_column("manual_invoice", "customer_phone", "VARCHAR(50)")
    _ensure_column("manual_invoice", "tax_override", "NUMERIC(10, 2)")
    # CustomerUser columns (safe if table already existed without them)
    _ensure_column("customer_user", "is_active", "BOOLEAN DEFAULT TRUE")
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
    """Requires any logged-in customer/staff/admin user (via the customer
    portal session). Staff/admin users are always allowed through. Customer
    users are checked against CUSTOMER_ALLOWED_ENDPOINTS for the current route.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        user_id = session.get("customer_user_id")
        if not user_id:
            flash("Please log in to continue.", "error")
            return redirect(url_for("customer_login", next=request.path))
        user = CustomerUser.query.get(user_id)
        if not user or not user.is_active:
            session.pop("customer_user_id", None)
            flash("Your account is inactive. Please contact us.", "error")
            return redirect(url_for("customer_login"))
        return view(*args, **kwargs)
    return wrapped


@app.before_request
def enforce_customer_page_restrictions():
    """If a customer-role user (not staff/admin) tries to access a page
    outside CUSTOMER_ALLOWED_ENDPOINTS, redirect them to their portal.
    This runs on every request so there's no way to slip through via a
    direct URL.
    """
    user_id = session.get("customer_user_id")
    if not user_id:
        return  # not logged in as a customer user — no restriction
    # Don't enforce on static assets or the admin backend (admin has its
    # own separate session check)
    endpoint = request.endpoint
    if not endpoint or endpoint == "static":
        return
    user = CustomerUser.query.get(user_id)
    if not user or not user.is_active:
        return
    if user.role == "customer" and endpoint not in CUSTOMER_ALLOWED_ENDPOINTS:
        flash("You don't have permission to view that page.", "error")
        return redirect(url_for("customer_portal"))
    # Staff/admin roles have no page restriction on the public site.
    # (Admin panel access is controlled separately by the admin session.)


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
    return render_template("contact_us.html", intro_text=get_page_content("contact-intro"))


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
            return render_template(
                "book_a_pickup.html", time_windows=PICKUP_TIME_WINDOWS, form=request.form,
            )

        pickup = PickupRequest(
            name=name, email=email, phone=phone, address=address,
            pickup_date=pickup_date, time_window=time_window,
            box_count=box_count, notes=notes or None,
        )
        db.session.add(pickup)
        db.session.commit()

        send_pickup_request_email(pickup)
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
        db.session.commit()

        flash(
            f"Thanks {name}! Your pickup request for {pickup_date.strftime('%B %d, %Y')} "
            f"has been received — we'll confirm the details with you shortly.", "success",
        )
        return redirect(url_for("book_a_pickup"))

    return render_template("book_a_pickup.html", time_windows=PICKUP_TIME_WINDOWS, form={})


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
        db.session.commit()
        session[CART_SESSION_KEY] = {}

        _send_order_emails(order)

        return redirect(url_for("order_confirmation", order_number=order.order_number))

    return render_template(
        "checkout.html", items=items, subtotal=subtotal, tax=tax, total=total, hst_rate=HST_RATE,
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
        counterpart_name=counterpart_name, quick_replies=QUICK_REPLIES,
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
    return render_template("admin/mailbox_compose.html", quick_replies=QUICK_REPLIES)


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
        flash("Pickup status updated.", "success")
    return redirect(url_for("admin_pickups"))


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
    return ADMIN_USERNAME if identity == "owner" else CREATOR_USERNAME


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
            return redirect(url_for("admin_settings_mfa_backup_codes"))
        flash("That code didn't match — double check the time on your phone and try again.", "error")
    # Distinguishing issuer names ("... — Owner" / "... — Creator") so the
    # two accounts show up as separate entries in an authenticator app that
    # ends up holding both.
    provisioning_uri = _totp_for_secret(pending_secret).provisioning_uri(
        name=_admin_display_username(identity),
        issuer_name=f"{COMPANY['name']} — {identity.capitalize()}",
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
        issuer_name=f"{COMPANY['name']} — {identity.capitalize()}",
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


@app.route("/admin/settings/mfa/backup-codes")
@login_required
def admin_settings_mfa_backup_codes():
    """Shows freshly generated backup codes exactly once, right after
    they're created (by admin_settings_mfa_setup or
    admin_settings_mfa_regenerate_backup_codes, which stash them in the
    session just for this one view). Reloading this page after that
    session value is gone just bounces back to Settings — the plaintext
    codes are never stored anywhere retrievable, only their hashes."""
    codes = session.pop("mfa_new_backup_codes", None)
    if not codes:
        flash("Backup codes are only shown once, right after they're generated.", "error")
        return redirect(url_for("admin_settings"))
    return render_template("admin/mfa_backup_codes.html", codes=codes)


@app.route("/admin/settings/mfa/backup-codes/regenerate", methods=["POST"])
@login_required
def admin_settings_mfa_regenerate_backup_codes():
    identity = session.get("admin_identity", "owner")
    if not mfa_is_enabled(identity):
        return redirect(url_for("admin_settings"))
    session["mfa_new_backup_codes"] = generate_backup_codes(identity)
    flash("New backup codes generated — your old ones no longer work.", "success")
    return redirect(url_for("admin_settings_mfa_backup_codes"))


@app.route("/admin/settings/mfa/disable", methods=["POST"])
@login_required
def admin_settings_mfa_disable():
    """Requires the current password again (not just today's already-open
    session) as a speed bump against someone at an unlocked screen turning
    2FA off. Checked against whichever account (owner or creator) is
    currently logged in."""
    identity = session.get("admin_identity", "owner")
    password = request.form.get("password", "")
    expected_password = ADMIN_PASSWORD if identity == "owner" else CREATOR_PASSWORD
    if not secrets.compare_digest(password, expected_password):
        flash("Incorrect password — two-factor authentication was not disabled.", "error")
        return redirect(url_for("admin_settings"))
    set_setting(_mfa_setting_key("mfa_enabled", identity), None)
    set_setting(_mfa_setting_key("mfa_totp_secret", identity), None)
    set_setting(_mfa_setting_key("mfa_totp_secret_pending", identity), None)
    set_setting(_mfa_setting_key("mfa_backup_codes", identity), None)
    flash("Two-factor authentication is off.", "success")
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
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = CustomerUser.query.filter_by(email=email).first()
        if user and user.is_active and user.check_password(password):
            session["customer_user_id"] = user.id
            session["customer_user_role"] = user.role
            flash(f"Welcome back, {user.name}!", "success")
            next_url = request.args.get("next")
            # Only allow safe same-site redirects
            if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("customer_portal"))
        flash("Incorrect email or password.", "error")
    return render_template("customer/login.html")


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


# ---------------------------------------------------------------------------
# Admin routes: customer/staff user management
# ---------------------------------------------------------------------------

@app.route("/admin/users")
@login_required
@owner_required
def admin_users():
    users = CustomerUser.query.order_by(CustomerUser.created_at.desc()).all()
    return render_template("admin/users.html", users=users, roles=CUSTOMER_USER_ROLES)


@app.route("/admin/users/new", methods=["GET", "POST"])
@login_required
@owner_required
def admin_user_new():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "customer")
        if not email or not name or not password:
            flash("Email, name, and password are required.", "error")
        elif role not in CUSTOMER_USER_ROLES:
            flash("Invalid role.", "error")
        elif CustomerUser.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
        else:
            user = CustomerUser(email=email, name=name, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash(f"Account created for {name}.", "success")
            return redirect(url_for("admin_users"))
    return render_template("admin/user_form.html", user=None, roles=CUSTOMER_USER_ROLES)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@owner_required
def admin_user_edit(user_id):
    user = CustomerUser.query.get_or_404(user_id)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", "customer")
        is_active = request.form.get("is_active") == "1"
        new_password = request.form.get("password", "").strip()
        if not email or not name:
            flash("Email and name are required.", "error")
        elif role not in CUSTOMER_USER_ROLES:
            flash("Invalid role.", "error")
        else:
            conflict = CustomerUser.query.filter_by(email=email).first()
            if conflict and conflict.id != user_id:
                flash("Another account already uses that email.", "error")
            else:
                user.name = name
                user.email = email
                user.role = role
                user.is_active = is_active
                if new_password:
                    user.set_password(new_password)
                db.session.commit()
                flash("Account updated.", "success")
                return redirect(url_for("admin_users"))
    return render_template("admin/user_form.html", user=user, roles=CUSTOMER_USER_ROLES)


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
