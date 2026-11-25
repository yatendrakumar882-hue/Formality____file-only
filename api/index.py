
import os
import re
import json
import html
import ssl
import time
import secrets
import smtplib
import urllib.parse
import urllib.request

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    Response,
    stream_with_context,
)

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.policy import SMTP
from email.utils import formataddr, formatdate, make_msgid


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

# Vercel Python entry point
handler = app


# =========================================================
# ENVIRONMENT VARIABLES
# =========================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()

if len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "SESSION_SECRET must be configured in Vercel "
        "and should contain at least 32 characters."
    )

if not LOGIN_PASSWORD:
    raise RuntimeError(
        "LOGIN_PASSWORD is not configured in Vercel."
    )

if bool(TURNSTILE_SITE_KEY) != bool(TURNSTILE_SECRET_KEY):
    raise RuntimeError(
        "Configure both Turnstile keys or leave both empty."
    )

TURNSTILE_ENABLED = bool(
    TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY
)

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=1_500_000,
)


# =========================================================
# MAIL SETTINGS
# =========================================================

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2
SEND_DELAY_SECONDS = 1.8

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    if not value or len(value) > 254:
        return False

    return bool(EMAIL_RE.fullmatch(value))


def normalize_email(value):
    return str(value or "").strip().lower()


def clean_header(value, max_length=998):
    """
    Prevent newline characters from being inserted into headers.
    """
    value = str(value or "")
    value = value.replace("\r", " ").replace("\n", " ")
    return value.strip()[:max_length]


def authenticated():
    return session.get("authenticated") is True


# =========================================================
# PERSONALIZATION
# =========================================================

PLACEHOLDERS = (
    "{{hi}}",
    "{{hello}}",
    "{{thanks}}",
    "{{name}}",
    "{{email}}",
    "{{ref_code}}",
)


def personalize_template(template, recipient, html_mode=False):
    result = str(template or "")

    values = {
        "{{hi}}": recipient.get("hi", ""),
        "{{hello}}": recipient.get("hello", ""),
        "{{thanks}}": recipient.get("thanks", ""),
        "{{name}}": recipient.get("name", ""),
        "{{email}}": recipient.get("email", ""),
        "{{ref_code}}": recipient.get("ref_code", ""),
    }

    for placeholder, value in values.items():
        value = str(value or "")

        if html_mode:
            value = html.escape(value)

        result = result.replace(placeholder, value)

    return result


# =========================================================
# HTML TO PLAIN TEXT
# =========================================================

def html_to_plain_text(content):
    text = str(content or "")

    text = re.sub(
        r"<\s*br\s*/?\s*>",
        "\n",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"</\s*(p|div|tr|h[1-6])\s*>",
        "\n\n",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text,
    )

    replacements = {
        "&nbsp;": " ",
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&#39;": "'",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    return html.unescape(text).strip()


# =========================================================
# CLOUDFLARE TURNSTILE
# =========================================================

def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_ENABLED:
        return True, None

    if not token:
        return False, "Cloudflare verification is required."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(
                response.read().decode("utf-8")
            )

        if result.get("success") is True:
            return True, None

        return False, "Cloudflare verification failed."

    except Exception:
        app.logger.exception("Turnstile verification error")
        return False, "Unable to verify Cloudflare."


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template(
            "login.html",
            error=None,
            turnstile_site_key=TURNSTILE_SITE_KEY,
        )

    password = str(request.form.get("password", ""))

    if not secrets.compare_digest(password, LOGIN_PASSWORD):
        return (
            render_template(
                "login.html",
                error="Incorrect password.",
                turnstile_site_key=TURNSTILE_SITE_KEY,
            ),
            401,
        )

    session.clear()
    session.permanent = True
    session["authenticated"] = True

    return redirect(url_for("home"))


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    if not authenticated():
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


# =========================================================
# EMAIL MESSAGE BUILDER
# =========================================================

def build_message(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):
    gmail = normalize_email(gmail)
    recipient = normalize_email(recipient)

    sender_name = clean_header(sender_name, 200)
    subject = clean_header(subject, 998)

    body = str(body or "").replace("\x00", "")

    if is_html:
        message = MIMEMultipart(
            "alternative",
            policy=SMTP,
        )

        # Plain-text version
        message.attach(
            MIMEText(
                html_to_plain_text(body),
                "plain",
                "utf-8",
            )
        )

        # HTML version
        message.attach(
            MIMEText(
                body,
                "html",
                "utf-8",
                policy=SMTP,
            )
        )

    else:
        message = MIMEText(
            body,
            "plain",
            "utf-8",
            policy=SMTP,
        )

    # Use the authenticated Gmail address.
    message["Subject"] = subject
    message["From"] = formataddr((sender_name, gmail))
    message["To"] = recipient
    message["Date"] = formatdate(localtime=False, usegmt=True)

    # Unique message ID for this message.
    domain = gmail.split("@", 1)[1]

    message["Message-ID"] = make_msgid(
        domain=domain
    )

    return message


# =========================================================
# RECIPIENT NORMALIZATION
# =========================================================

def normalize_recipient(item):
    if isinstance(item, str):
        return {
            "email": normalize_email(item),
            "name": "",
            "hi": "",
            "hello": "",
            "thanks": "",
            "ref_code": "",
        }

    if not isinstance(item, dict):
        return None

    def clean_value(value, limit):
        value = str(value or "")
        value = value.replace("\r", " ")
        value = value.replace("\n", " ")
        return value.strip()[:limit]

    return {
        "email": normalize_email(item.get("email", "")),
        "name": clean_value(item.get("name", ""), 200),
        "hi": clean_value(item.get("hi", ""), 100),
        "hello": clean_value(item.get("hello", ""), 100),
        "thanks": clean_value(item.get("thanks", ""), 100),
        "ref_code": clean_value(item.get("ref_code", ""), 200),
    }


# =========================================================
# SEND ONE EMAIL
# =========================================================

def send_one_email(
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipient_data,
):
    recipient = normalize_email(
        recipient_data.get("email", "")
    )

    clean_password = re.sub(
        r"\s+",
        "",
        str(app_password or ""),
    )

    personalized_subject = personalize_template(
        subject,
        recipient_data,
        html_mode=False,
    )

    personalized_body = personalize_template(
        body,
        recipient_data,
        html_mode=is_html,
    )

    if SEND_DELAY_SECONDS > 0:
        time.sleep(SEND_DELAY_SECONDS)

    message = build_message(
        gmail=gmail,
        sender_name=sender_name,
        subject=personalized_subject,
        body=personalized_body,
        is_html=is_html,
        recipient=recipient,
    )

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=SMTP_TIMEOUT,
        ) as server:

            server.ehlo()
            server.login(gmail, clean_password)

            refused = server.sendmail(
                gmail,
                [recipient],
                message.as_string(),
            )

            if refused:
                return {
                    "email": recipient,
                    "result": "failed",
                    "error": "SMTP refused this recipient.",
                }

        return {
            "email": recipient,
            "result": "sent",
            "detail": "SMTP accepted the message.",
        }

    except smtplib.SMTPAuthenticationError:
        return {
            "email": recipient,
            "result": "failed",
            "error": "Gmail authentication failed. Check your App Password.",
        }

    except smtplib.SMTPRecipientsRefused:
        return {
            "email": recipient,
            "result": "failed",
            "error": "SMTP rejected the recipient address.",
        }

    except smtplib.SMTPDataError as exc:
        return {
            "email": recipient,
            "result": "failed",
            "error": f"SMTP rejected the message (code {exc.smtp_code}).",
        }

    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        # No automatic retry: after a connection interruption,
        # it may be unclear whether the recipient already received it.
        app.logger.warning(
            "SMTP error for %s: %s",
            recipient,
            str(exc)[:200],
        )

        return {
            "email": recipient,
            "result": "failed",
            "error": "SMTP connection or delivery error. Check before retrying.",
        }

    except Exception:
        app.logger.exception(
            "Unexpected email error for %s",
            recipient,
        )

        return {
            "email": recipient,
            "result": "failed",
            "error": "Unexpected sending error.",
        }


# =========================================================
# NDJSON HELPERS
# =========================================================

def ndjson(event):
    return (
        json.dumps(
            event,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )


def progress_event(
    email_address,
    result,
    total,
    sent,
    failed,
    error=None,
):
    event = {
        "type": "progress",
        "email": email_address,
        "result": result,
        "total": total,
        "sent": sent,
        "failed": failed,
        "remaining": total - sent - failed,
    }

    if error:
        event["error"] = str(error)[:500]

    return ndjson(event)


# =========================================================
# BATCH EMAIL SENDING
# =========================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({
            "success": False,
            "message": "Please sign in again.",
            "login_required": True,
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Invalid JSON request.",
        }), 400

    sender_name = clean_header(
        data.get("sender_name", ""),
        200,
    )

    gmail = clean_header(
        data.get("gmail", ""),
        254,
    ).lower()

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = clean_header(
        data.get("subject", ""),
        998,
    )

    body = str(
        data.get("body", "")
    )

    is_html = data.get("is_html", False) is True

    recipients = data.get("recipients", [])

    turnstile_token = str(
        data.get("turnstile_token", "")
    ).strip()

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not sender_name:
        return jsonify({
            "success": False,
            "message": "Sender name is required.",
        }), 400

    if not valid_email(gmail):
        return jsonify({
            "success": False,
            "message": "Enter a valid Gmail address.",
        }), 400

    if not gmail.endswith("@gmail.com"):
        return jsonify({
            "success": False,
            "message": "Please use a Gmail address with Gmail SMTP.",
        }), 400

    if not app_password:
        return jsonify({
            "success": False,
            "message": "Google App Password is required.",
        }), 400

    if not subject:
        return jsonify({
            "success": False,
            "message": "Email subject is required.",
        }), 400

    if not body.strip():
        return jsonify({
            "success": False,
            "message": "Email message is required.",
        }), 400

    if len(body) > 100_000:
        return jsonify({
            "success": False,
            "message": "Message body is too large.",
        }), 400

    if not isinstance(recipients, list):
        return jsonify({
            "success": False,
            "message": "Invalid recipient list.",
        }), 400

    # -----------------------------------------------------
    # CLEAN AND DEDUPLICATE RECIPIENTS
    # -----------------------------------------------------

    clean_recipients = []
    seen = set()

    for item in recipients:
        recipient = normalize_recipient(item)

        if not recipient:
            continue

        email_address = recipient["email"]

        if not valid_email(email_address):
            continue

        if email_address in seen:
            continue

        seen.add(email_address)
        clean_recipients.append(recipient)

    if not clean_recipients:
        return jsonify({
            "success": False,
            "message": "No valid recipients found.",
        }), 400

    if len(clean_recipients) > MAX_RECIPIENTS:
        return jsonify({
            "success": False,
            "message": f"Maximum {MAX_RECIPIENTS} recipients per batch.",
        }), 400

    # -----------------------------------------------------
    # OPTIONAL TURNSTILE CHECK
    # -----------------------------------------------------

    if TURNSTILE_ENABLED:
        forwarded_for = request.headers.get(
            "X-Forwarded-For",
            "",
        )

        remote_ip = (
            forwarded_for.split(",", 1)[0].strip()
            if forwarded_for
            else request.remote_addr
        )

        verified, verify_error = verify_turnstile(
            turnstile_token,
            remote_ip,
        )

        if not verified:
            return jsonify({
                "success": False,
                "message": verify_error,
            }), 403

    # -----------------------------------------------------
    # STREAMING PROGRESS
    # -----------------------------------------------------

    @stream_with_context
    def generate():
        total = len(clean_recipients)

        sent_count = 0
        failed_count = 0

        yield ndjson({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total,
            "parallel": MAX_PARALLEL_SENDS,
            "delay": SEND_DELAY_SECONDS,
        })

        with ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        ) as executor:

            future_map = {}

            for recipient_data in clean_recipients:
                future = executor.submit(
                    send_one_email,
                    gmail,
                    app_password,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    recipient_data,
                )

                future_map[future] = recipient_data

            for future in as_completed(future_map):
                recipient_data = future_map[future]
                email_address = recipient_data["email"]

                try:
                    result = future.result()

                except Exception:
                    app.logger.exception(
                        "Unexpected worker failure for %s",
                        email_address,
                    )

                    result = {
                        "result": "failed",
                        "error": "Unexpected sending worker error.",
                    }

                if result.get("result") == "sent":
                    sent_count += 1

                    yield progress_event(
                        email_address=email_address,
                        result="sent",
                        total=total,
                        sent=sent_count,
                        failed=failed_count,
                    )

                else:
                    failed_count += 1

                    yield progress_event(
                        email_address=email_address,
                        result="failed",
                        total=total,
                        sent=sent_count,
                        failed=failed_count,
                        error=result.get(
                            "error",
                            "SMTP sending failed.",
                        ),
                    )

        yield ndjson({
            "type": "complete",
            "success": failed_count == 0,
            "message": "Sending process completed.",
            "total": total,
            "sent": sent_count,
            "failed": failed_count,
            "remaining": total - sent_count - failed_count,
            "delivery_note": (
                "Sent means SMTP accepted the message; "
                "it does not confirm Inbox placement."
            ),
        })

    response = Response(
        generate(),
        content_type="application/x-ndjson; charset=utf-8",
    )

    response.headers["Cache-Control"] = (
        "no-cache, no-store, must-revalidate, no-transform"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["X-Content-Type-Options"] = "nosniff"

    return response


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "YATENDRA Mail Console",
        "mailer": "Gmail SMTP",
        "parallel_sends": MAX_PARALLEL_SENDS,
        "send_delay_seconds": SEND_DELAY_SECONDS,
        "max_recipients": MAX_RECIPIENTS,
        "turnstile_enabled": TURNSTILE_ENABLED,
        "placeholders": list(PLACEHOLDERS),
    })


# =========================================================
# FAVICON
# =========================================================

@app.route("/favicon.ico")
def favicon():
    return "", 204


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )
