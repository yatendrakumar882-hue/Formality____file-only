
import os
import re
import json
import time
import html
import ssl
import secrets
import smtplib
import logging
import urllib.parse
import urllib.request

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid

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


# =========================================================
# APP CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

# Vercel Python handler
handler = app

logging.basicConfig(level=logging.INFO)


# =========================================================
# ENVIRONMENT VARIABLES
# =========================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

TURNSTILE_SITE_KEY = os.environ.get(
    "TURNSTILE_SITE_KEY", ""
).strip()

TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY", ""
).strip()

if len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "SESSION_SECRET must be set and contain at least 32 characters."
    )

if not LOGIN_PASSWORD:
    raise RuntimeError(
        "LOGIN_PASSWORD is missing from Vercel Environment Variables."
    )

if bool(TURNSTILE_SITE_KEY) != bool(TURNSTILE_SECRET_KEY):
    raise RuntimeError(
        "Set both Turnstile keys or remove both."
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

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2
SEND_DELAY_SECONDS = 1.8


# =========================================================
# HELPERS
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    return (
        len(value) <= 254
        and bool(EMAIL_RE.fullmatch(value))
    )


def clean_header(value, limit=998):
    value = str(value or "")
    value = value.replace("\r", " ").replace("\n", " ")
    return value.strip()[:limit]


def is_logged_in():
    return session.get("authenticated") is True


def json_error(message, status=400):
    return jsonify({
        "success": False,
        "message": message,
    }), status


def ndjson(event):
    return (
        json.dumps(event, ensure_ascii=False)
        + "\n"
    )


# =========================================================
# TURNSTILE VERIFICATION
# =========================================================

def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_ENABLED:
        return True, None

    if not token:
        return False, "Cloudflare verification is required. Complete the captcha."

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
            "Content-Type": "application/x-www-form-urlencoded"
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            result = json.loads(
                response.read().decode("utf-8")
            )

        if result.get("success") is True:
            return True, None

        logging.warning(
            "Turnstile rejected token. Error codes: %s",
            result.get("error-codes", []),
        )

        return False, "Cloudflare rejected the verification. Check your Site Key, Secret Key and domain."

    except Exception:
        logging.exception("Turnstile verification request failed")
        return False, "Cloudflare verification service could not be reached."


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_logged_in():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template(
            "login.html",
            error=None,
        )

    password = request.form.get("password", "")

    if not secrets.compare_digest(
        str(password),
        str(LOGIN_PASSWORD),
    ):
        return render_template(
            "login.html",
            error="Incorrect password. Please check LOGIN_PASSWORD in Vercel.",
        ), 401

    session.clear()
    session.permanent = True
    session["authenticated"] = True

    return redirect(url_for("home"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():
    if not is_logged_in():
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
        turnstile_enabled=TURNSTILE_ENABLED,
    )


# =========================================================
# RECIPIENT NORMALIZATION
# =========================================================

def normalize_recipient(item):
    if isinstance(item, str):
        return {
            "email": item.strip().lower(),
            "name": "",
            "hi": "",
            "hello": "",
            "thanks": "",
            "ref_code": "",
        }

    if not isinstance(item, dict):
        return None

    def safe_value(value, limit=200):
        return str(value or "").replace(
            "\r", " "
        ).replace(
            "\n", " "
        ).strip()[:limit]

    return {
        "email": str(item.get("email", "")).strip().lower(),
        "name": safe_value(item.get("name")),
        "hi": safe_value(item.get("hi"), 100),
        "hello": safe_value(item.get("hello"), 100),
        "thanks": safe_value(item.get("thanks"), 100),
        "ref_code": safe_value(item.get("ref_code")),
    }


def clean_recipients(items):
    output = []
    seen = set()

    for item in items:
        recipient = normalize_recipient(item)

        if not recipient:
            continue

        address = recipient["email"]

        if not valid_email(address):
            continue

        if address in seen:
            continue

        seen.add(address)
        output.append(recipient)

        if len(output) >= MAX_RECIPIENTS:
            break

    return output


# =========================================================
# PERSONALIZATION
# =========================================================

def personalize(value, recipient, html_mode=False):
    replacements = {
        "{{hi}}": recipient.get("hi", ""),
        "{{hello}}": recipient.get("hello", ""),
        "{{thanks}}": recipient.get("thanks", ""),
        "{{name}}": recipient.get("name", ""),
        "{{email}}": recipient.get("email", ""),
        "{{ref_code}}": recipient.get("ref_code", ""),
    }

    result = str(value or "")

    for placeholder, replacement in replacements.items():
        replacement = str(replacement or "")

        if html_mode:
            replacement = html.escape(replacement)

        result = result.replace(
            placeholder,
            replacement,
        )

    return result


# =========================================================
# HTML TO TEXT
# =========================================================

def html_to_text(value):
    text = str(value or "")

    text = re.sub(
        r"<\s*br\s*/?\s*>",
        "\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"</\s*(p|div|tr|h[1-6])\s*>",
        "\n\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text,
    )

    return html.unescape(text).strip()


# =========================================================
# EMAIL MESSAGE
# =========================================================

def build_message(
    gmail,
    sender_name,
    recipient,
    subject,
    body,
    is_html,
):
    gmail = gmail.strip().lower()
    recipient = recipient.strip().lower()

    sender_name = clean_header(sender_name, 200)
    subject = clean_header(subject, 998)

    if is_html:
        message = MIMEMultipart("alternative")

        message.attach(
            MIMEText(
                html_to_text(body),
                "plain",
                "utf-8",
            )
        )

        message.attach(
            MIMEText(
                body,
                "html",
                "utf-8",
            )
        )
    else:
        message = MIMEText(
            body,
            "plain",
            "utf-8",
        )

    message["Subject"] = subject
    message["From"] = formataddr((sender_name, gmail))
    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    return message


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
    recipient = recipient_data["email"]

    personalized_subject = personalize(
        subject,
        recipient_data,
    )

    personalized_body = personalize(
        body,
        recipient_data,
        html_mode=is_html,
    )

    if SEND_DELAY_SECONDS:
        time.sleep(SEND_DELAY_SECONDS)

    message = build_message(
        gmail=gmail,
        sender_name=sender_name,
        recipient=recipient,
        subject=personalized_subject,
        body=personalized_body,
        is_html=is_html,
    )

    context = ssl.create_default_context()

    app_password = re.sub(
        r"\s+",
        "",
        str(app_password),
    )

    try:
        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=SMTP_TIMEOUT,
        ) as server:

            server.ehlo()
            server.login(gmail, app_password)

            refused = server.sendmail(
                gmail,
                [recipient],
                message.as_string(),
            )

            if refused:
                return {
                    "result": "failed",
                    "error": "SMTP refused the recipient.",
                }

        return {
            "result": "sent",
            "error": None,
        }

    except smtplib.SMTPAuthenticationError:
        logging.exception("Gmail authentication failed")
        return {
            "result": "failed",
            "error": "Gmail authentication failed. Check your Gmail App Password.",
        }

    except smtplib.SMTPRecipientsRefused:
        return {
            "result": "failed",
            "error": "Recipient address was refused by SMTP.",
        }

    except smtplib.SMTPDataError as exc:
        return {
            "result": "failed",
            "error": f"SMTP rejected the message. Code: {exc.smtp_code}",
        }

    except (smtplib.SMTPException, OSError, TimeoutError):
        logging.exception("SMTP sending error for %s", recipient)
        return {
            "result": "failed",
            "error": "SMTP connection or sending error. Check Gmail and recipient status before retrying.",
        }

    except Exception:
        logging.exception("Unexpected sending error")
        return {
            "result": "failed",
            "error": "Unexpected sending error.",
        }


# =========================================================
# BATCH SEND API
# =========================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not is_logged_in():
        return json_error(
            "Your login session expired. Please sign in again.",
            401,
        )

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return json_error("Invalid request data.")

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

    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True

    recipients_input = data.get("recipients", [])

    consent_confirmed = (
        data.get("consent_confirmed") is True
    )

    turnstile_token = str(
        data.get("turnstile_token", "")
    ).strip()

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not sender_name:
        return json_error("Enter Sender Name.")

    if not valid_email(gmail) or not gmail.endswith("@gmail.com"):
        return json_error("Enter a valid Gmail address.")

    if not app_password:
        return json_error("Enter your Gmail App Password.")

    if not subject:
        return json_error("Enter Email Subject.")

    if not body.strip():
        return json_error("Enter Message Body.")

    if len(body) > 100_000:
        return json_error("Message body is too large.")

    if not consent_confirmed:
        return json_error(
            "Confirm that recipients agreed to receive your email."
        )

    if not isinstance(recipients_input, list):
        return json_error("Recipient list is invalid.")

    recipients = clean_recipients(recipients_input)

    if not recipients:
        return json_error("No valid recipient addresses found.")

    if len(recipients_input) > MAX_RECIPIENTS:
        # Reject oversized requests rather than silently sending a partial list.
        if len(recipients) >= MAX_RECIPIENTS:
            return json_error(
                f"Maximum {MAX_RECIPIENTS} recipients per batch."
            )

    # -----------------------------------------------------
    # TURNSTILE
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

        verified, error_message = verify_turnstile(
            turnstile_token,
            remote_ip,
        )

        if not verified:
            return json_error(error_message, 403)

    # -----------------------------------------------------
    # STREAMING RESPONSE
    # -----------------------------------------------------

    @stream_with_context
    def generate():
        total = len(recipients)
        sent = 0
        failed = 0

        yield ndjson({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total,
        })

        with ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        ) as executor:

            futures = {
                executor.submit(
                    send_one_email,
                    gmail,
                    app_password,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    recipient,
                ): recipient["email"]
                for recipient in recipients
            }

            for future in as_completed(futures):
                address = futures[future]

                try:
                    result = future.result()
                except Exception:
                    logging.exception(
                        "Email worker failed for %s",
                        address,
                    )
                    result = {
                        "result": "failed",
                        "error": "Unexpected worker error.",
                    }

                if result["result"] == "sent":
                    sent += 1
                else:
                    failed += 1

                yield ndjson({
                    "type": "progress",
                    "email": address,
                    "result": result["result"],
                    "error": result.get("error"),
                    "total": total,
                    "sent": sent,
                    "failed": failed,
                    "remaining": total - sent - failed,
                })

        yield ndjson({
            "type": "complete",
            "success": failed == 0,
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": total - sent - failed,
            "message": "Sending process completed.",
            "delivery_note": (
                "Sent means Gmail SMTP accepted the message. "
                "It does not confirm Inbox placement."
            ),
        })

    response = Response(
        generate(),
        content_type="application/x-ndjson; charset=utf-8",
    )

    response.headers["Cache-Control"] = (
        "no-cache, no-store, no-transform"
    )
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
        "service": "Secure Mail Console",
        "smtp": SMTP_HOST,
        "max_recipients": MAX_RECIPIENTS,
        "parallel_sends": MAX_PARALLEL_SENDS,
        "turnstile_enabled": TURNSTILE_ENABLED,
    })


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )
