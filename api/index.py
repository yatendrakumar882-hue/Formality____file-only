
import os
import re
import ssl
import time
import json
import html
import hmac
import smtplib
import logging
import threading

from pathlib import Path
from datetime import timedelta
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, formatdate

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    jsonify,
    session,
    Response,
    stream_with_context,
)

from jinja2 import TemplateNotFound


# =====================================================
# FLASK CONFIGURATION
# =====================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

# Vercel WSGI handler
handler = app

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =====================================================
# SECURITY / ENVIRONMENT
# =====================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

# Dedicated stable secret is required.
app.secret_key = SESSION_SECRET or None

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    MAX_CONTENT_LENGTH=1_000_000,
)


# =====================================================
# SMTP SETTINGS
# =====================================================

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2

# SAME ORIGINAL SENDING SPEED
SEND_DELAY_SECONDS = 0.1

_pacing_lock = threading.Lock()
_last_send_started = 0.0


# =====================================================
# EMAIL VALIDATION
# =====================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def clean(value, limit=250):
    """Remove header-breaking characters and limit input size."""
    value = str(value or "")
    value = value.replace("\r", " ").replace("\n", " ")
    return value.strip()[:limit]


def valid_email(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    return (
        len(value) <= 254
        and bool(EMAIL_RE.fullmatch(value))
    )


def logged_in():
    return session.get("authenticated") is True


def error(message, status=400):
    return jsonify({
        "success": False,
        "message": message,
    }), status


def event_line(data):
    return json.dumps(
        data,
        ensure_ascii=False,
    ) + "\n"


# =====================================================
# HTML TO PLAIN TEXT
# =====================================================

class PlainTextExtractor(HTMLParser):

    BLOCK_TAGS = {
        "p", "div", "br", "li", "ul", "ol",
        "h1", "h2", "h3", "h4", "h5", "h6",
        "tr", "table", "blockquote",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "li":
            self.parts.append("\n- ")
        elif tag.lower() in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag.lower() in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        self.parts.append(data)

    def get_text(self):
        value = "".join(self.parts)
        value = html.unescape(value)
        value = re.sub(r"[ \t]+", " ", value)
        value = re.sub(r" *\n *", "\n", value)
        value = re.sub(r"\n{3,}", "\n\n", value)
        return value.strip()


def html_to_text(value):
    parser = PlainTextExtractor()

    try:
        parser.feed(str(value or ""))
        parser.close()
        return parser.get_text()
    except Exception:
        logger.exception("HTML-to-text conversion failed")
        return re.sub(r"<[^>]*>", " ", str(value or "")).strip()


# =====================================================
# RECIPIENT NORMALIZATION
# =====================================================

def normalize_recipient(item):

    if isinstance(item, str):
        item = {"email": item}

    if not isinstance(item, dict):
        return None

    address = str(
        item.get("email", "")
    ).strip().lower()

    if not valid_email(address):
        return None

    recipient = {
        "email": address,
    }

    for key in (
        "name",
        "hi",
        "hello",
        "thanks",
        "ref_code",
    ):
        recipient[key] = clean(
            item.get(key, ""),
            150,
        )

    return recipient


# =====================================================
# PERSONALIZATION
# =====================================================

def personalize(value, recipient):

    result = str(value or "")

    replacements = {
        "{{hi}}": recipient.get("hi") or "Hi",
        "{{hello}}": recipient.get("hello") or "Hello",
        "{{thanks}}": recipient.get("thanks") or "Thank you",
        "{{name}}": recipient.get("name") or "there",
        "{{email}}": recipient.get("email", ""),
        "{{ref_code}}": recipient.get("ref_code") or "",
    }

    for key, replacement in replacements.items():
        result = result.replace(key, replacement)

    return result


# =====================================================
# GLOBAL SEND PACING
# =====================================================

def wait_for_send_slot():

    global _last_send_started

    with _pacing_lock:

        now = time.monotonic()

        remaining = SEND_DELAY_SECONDS - (
            now - _last_send_started
        )

        if remaining > 0:
            time.sleep(remaining)

        _last_send_started = time.monotonic()


# =====================================================
# BUILD EMAIL
# =====================================================

def build_message(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    msg = EmailMessage()

    final_subject = clean(
        personalize(subject, recipient),
        250,
    )

    final_sender_name = clean(
        sender_name,
        150,
    )

    msg["Subject"] = final_subject
    msg["From"] = formataddr((
        final_sender_name,
        gmail,
    ))

    msg["To"] = recipient["email"]
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()

    content = personalize(body, recipient)

    if is_html:

        plain = html_to_text(content)

        msg.set_content(
            plain or "Please view this message in an HTML-capable email client."
        )

        msg.add_alternative(
            content,
            subtype="html",
        )

    else:
        msg.set_content(content)

    return msg


# =====================================================
# SEND ONE EMAIL
# =====================================================

def send_one(
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    message = build_message(
        gmail,
        sender_name,
        subject,
        body,
        is_html,
        recipient,
    )

    # Keep original sending interval.
    wait_for_send_slot()

    password = re.sub(
        r"\s+",
        "",
        app_password,
    )

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT,
    ) as smtp:

        smtp.ehlo()
        smtp.login(gmail, password)

        refused = smtp.send_message(
            message,
            from_addr=gmail,
            to_addrs=[recipient["email"]],
        )

        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)

    return True


# =====================================================
# LOGIN
# =====================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if logged_in():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template(
            "login.html",
            error=None,
        )

    if not LOGIN_PASSWORD:
        logger.error("LOGIN_PASSWORD is missing.")

        return render_template(
            "login.html",
            error="LOGIN_PASSWORD is missing in Vercel settings.",
        ), 503

    if not SESSION_SECRET:
        logger.error("SESSION_SECRET is missing.")

        return render_template(
            "login.html",
            error="SESSION_SECRET is missing in Vercel settings.",
        ), 503

    submitted = str(
        request.form.get("password", "")
    )

    if not hmac.compare_digest(
        submitted,
        LOGIN_PASSWORD,
    ):
        return render_template(
            "login.html",
            error="Incorrect password.",
        ), 401

    session.clear()
    session.permanent = True
    session["authenticated"] = True

    return redirect(url_for("home"))


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout", methods=["GET", "POST"])
def logout():

    session.clear()

    return redirect(url_for("login"))


# =====================================================
# HOME
# =====================================================

@app.route("/")
def home():

    if not logged_in():
        return redirect(url_for("login"))

    try:
        return render_template("index.html")

    except TemplateNotFound:

        logger.exception("index.html template missing")

        return (
            "templates/index.html was not found.",
            500,
        )


# =====================================================
# HEALTH CHECK
# =====================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "smtp": "Gmail SMTP SSL",
        "max_recipients": MAX_RECIPIENTS,
        "max_parallel_sends": MAX_PARALLEL_SENDS,
        "send_delay_seconds": SEND_DELAY_SECONDS,
        "login_password_configured": bool(LOGIN_PASSWORD),
        "session_secret_configured": bool(SESSION_SECRET),
    })


# =====================================================
# FAVICON / SERVICE WORKER
# =====================================================

@app.route("/favicon.ico")
def favicon():
    return Response("", status=204)


@app.route("/sw.js")
def service_worker():
    return Response(
        "",
        mimetype="application/javascript",
    )


# =====================================================
# SEND BATCH
# =====================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():

    if not logged_in():

        return jsonify({
            "success": False,
            "message": "Please log in again.",
            "login_required": True,
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error("Invalid JSON request.")

    sender_name = clean(
        data.get("sender_name", ""),
        150,
    )

    gmail = clean(
        data.get("gmail", ""),
        254,
    ).lower()

    password = str(
        data.get("app_password", "")
    ).strip()

    subject = clean(
        data.get("subject", ""),
        250,
    )

    body = str(
        data.get("body", "")
    )

    is_html = data.get("is_html") is True
    incoming = data.get("recipients", [])

    if (
        not sender_name
        or not valid_email(gmail)
        or not gmail.endswith("@gmail.com")
    ):
        return error(
            "Enter a valid Gmail sender address and name."
        )

    if not password or not subject or not body.strip():
        return error(
            "App Password, subject and body are required."
        )

    if len(body) > 100_000:
        return error("Email body is too large.")

    if not isinstance(incoming, list):
        return error("Recipients must be a list.")

    if data.get("consent_confirmed") is not True:
        return error(
            "Confirm that recipients agreed to receive these emails."
        )

    recipients = []
    seen = set()
    invalid = 0
    duplicates = 0

    for item in incoming:

        recipient = normalize_recipient(item)

        if not recipient:
            invalid += 1
            continue

        address = recipient["email"]

        if address in seen:
            duplicates += 1
            continue

        seen.add(address)
        recipients.append(recipient)

    if not recipients:
        return error("No valid recipients found.")

    if len(recipients) > MAX_RECIPIENTS:
        return error(
            f"Maximum {MAX_RECIPIENTS} unique recipients per batch."
        )

    # -------------------------------------------------
    # STREAMING PROGRESS
    # -------------------------------------------------

    def generate():

        total = len(recipients)
        sent = 0
        failed = 0

        yield event_line({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total,
            "invalid_skipped": invalid,
            "duplicates_skipped": duplicates,
        })

        executor = ThreadPoolExecutor(
            max_workers=min(MAX_PARALLEL_SENDS, total)
        )

        try:

            jobs = {
                executor.submit(
                    send_one,
                    gmail,
                    password,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    recipient,
                ): recipient
                for recipient in recipients
            }

            for future in as_completed(jobs):

                recipient = jobs[future]

                try:

                    future.result()
                    sent += 1

                    item = {
                        "type": "progress",
                        "recipient": recipient["email"],
                        "result": "sent",
                    }

                except smtplib.SMTPAuthenticationError:

                    failed += 1

                    item = {
                        "type": "progress",
                        "recipient": recipient["email"],
                        "result": "failed",
                        "error": (
                            "Gmail authentication failed. "
                            "Check Gmail App Password."
                        ),
                    }

                except smtplib.SMTPRecipientsRefused:

                    failed += 1

                    item = {
                        "type": "progress",
                        "recipient": recipient["email"],
                        "result": "failed",
                        "error": "Gmail refused this recipient.",
                    }

                except smtplib.SMTPResponseException as exc:

                    failed += 1

                    detail = (
                        exc.smtp_error.decode(
                            "utf-8",
                            "replace",
                        )
                        if isinstance(exc.smtp_error, bytes)
                        else str(exc.smtp_error)
                    )

                    item = {
                        "type": "progress",
                        "recipient": recipient["email"],
                        "result": "failed",
                        "error": (
                            f"SMTP error {exc.smtp_code}: "
                            f"{detail[:200]}"
                        ),
                    }

                except (
                    smtplib.SMTPException,
                    TimeoutError,
                    OSError,
                ) as exc:

                    failed += 1

                    item = {
                        "type": "progress",
                        "recipient": recipient["email"],
                        "result": "failed",
                        "error": (
                            f"SMTP/network error: {str(exc)[:200]}"
                        ),
                    }

                except Exception as exc:

                    failed += 1

                    logger.exception(
                        "Unexpected email sending error"
                    )

                    item = {
                        "type": "progress",
                        "recipient": recipient["email"],
                        "result": "failed",
                        "error": (
                            f"Unexpected error: {type(exc).__name__}"
                        ),
                    }

                item.update({
                    "total": total,
                    "sent": sent,
                    "failed": failed,
                    "remaining": total - sent - failed,
                })

                yield event_line(item)

        finally:
            # Wait for already-submitted tasks.
            executor.shutdown(wait=True)

        yield event_line({
            "type": "complete",
            "success": failed == 0,
            "message": (
                "SMTP sending attempts finished. "
                "SMTP acceptance does not confirm Inbox delivery."
            ),
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0,
            "invalid_skipped": invalid,
            "duplicates_skipped": duplicates,
        })

    response = Response(
        stream_with_context(generate()),
        content_type="application/x-ndjson; charset=utf-8",
    )

    response.headers["Cache-Control"] = (
        "no-store, no-cache, no-transform"
    )

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Accel-Buffering"] = "no"

    return response


# =====================================================
# ERROR HANDLERS
# =====================================================

@app.errorhandler(413)
def request_too_large(exc):
    return error("Request is too large.", 413)


@app.errorhandler(404)
def not_found(exc):
    return jsonify({
        "success": False,
        "message": "Page not found.",
    }), 404


@app.errorhandler(500)
def internal_error(exc):

    logger.exception("Application internal server error")

    return jsonify({
        "success": False,
        "message": "Internal server error. Check Vercel Runtime Logs.",
    }), 500


# =====================================================
# LOCAL DEVELOPMENT
# =====================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )
