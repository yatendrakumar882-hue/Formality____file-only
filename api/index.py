from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    Response,
    stream_with_context,
)
import smtplib
import ssl
import re
import os
import json
import time
import secrets
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

handler = app


# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is not configured.")

if not LOGIN_PASSWORD:
    raise RuntimeError("LOGIN_PASSWORD is not configured.")

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 4
SEND_DELAY_SECONDS = 1.8

MAX_RETRIES = 2
RETRY_DELAY_SECONDS = 2.0


EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


# -------------------------------------------------------------------
# Authentication
# -------------------------------------------------------------------

def authenticated():
    return session.get("authenticated") is True


@app.before_request
def require_login():
    allowed = {
        "login",
        "health",
        "static",
    }

    if request.endpoint in allowed:
        return None

    if authenticated():
        return None

    if request.path.startswith("/api/") or request.path == "/send-batch":
        return jsonify({
            "error": "Login required.",
            "login_required": True,
        }), 401

    return redirect(url_for("login"))


# -------------------------------------------------------------------
# Security / helpers
# -------------------------------------------------------------------

def clean_header(value):
    """
    Prevent CR/LF header injection.
    """
    if value is None:
        return ""

    return str(value).replace("\r", " ").replace("\n", " ").strip()


def valid_email(value):
    if not value:
        return False

    value = value.strip()

    if len(value) > 254:
        return False

    return bool(EMAIL_RE.fullmatch(value))


def normalize_recipients(raw):
    """
    Accept either:
      ["a@example.com", "b@example.com"]

    or:
      [
        {"email": "a@example.com", "name": "John"},
        {"email": "b@example.com"}
      ]

    Invalid and duplicate addresses are removed.
    """

    if not isinstance(raw, list):
        return []

    result = []
    seen = set()

    for item in raw:
        if isinstance(item, dict):
            email = str(item.get("email", "")).strip().lower()
            name = str(item.get("name", "")).strip()
            ref_code = str(item.get("ref_code", "")).strip()
        else:
            email = str(item).strip().lower()
            name = ""
            ref_code = ""

        if not valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)

        result.append({
            "email": email,
            "name": name,
            "ref_code": ref_code,
        })

        if len(result) >= MAX_RECIPIENTS:
            break

    return result


def html_to_plain_text(html):
    if not html:
        return ""

    text = re.sub(
        r"(?is)<(script|style).*?>.*?</\1>",
        "",
        html,
    )

    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p\s*>", "\n\n", text)
    text = re.sub(r"(?i)</div\s*>", "\n", text)
    text = re.sub(r"(?s)<[^>]+>", "", text)

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

    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def expand_spintax(text):
    """
    Supports simple {one|two|three} syntax.

    This is intended for legitimate personalization/variation,
    not for bypassing spam filters.
    """
    if not text:
        return ""

    pattern = re.compile(r"\{([^{}|]+(?:\|[^{}|]+)+)\}")

    def replace(match):
        options = [
            option.strip()
            for option in match.group(1).split("|")
            if option.strip()
        ]

        if not options:
            return match.group(0)

        return secrets.choice(options)

    previous = None
    current = text

    for _ in range(10):
        if current == previous:
            break

        previous = current
        current = pattern.sub(replace, current)

    return current


def personalize(text, recipient):
    if not text:
        return ""

    name = recipient.get("name", "").strip()
    email = recipient.get("email", "").strip()
    ref_code = recipient.get("ref_code", "").strip()

    first_name = name.split()[0] if name else ""

    replacements = {
        "{{name}}": name,
        "{{email}}": email,
        "{{ref_code}}": ref_code,
        "{{hi}}": f"Hi {first_name}".strip(),
        "{{hello}}": f"Hello {first_name}".strip(),
        "{{thanks}}": f"Thanks {first_name}".strip(),
    }

    result = text

    for key, value in replacements.items():
        result = result.replace(key, value)

    return result


# -------------------------------------------------------------------
# Turnstile
# -------------------------------------------------------------------

def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return False, "TURNSTILE_SECRET_KEY is not configured."

    if not token:
        return False, "Cloudflare verification is required."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")

    try:
        request_obj = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=encoded,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Secure-Mail-Console/1.0",
            },
            method="POST",
        )

        with urllib.request.urlopen(
            request_obj,
            timeout=10,
        ) as response:
            data = json.loads(
                response.read().decode("utf-8")
            )

        if data.get("success") is True:
            return True, ""

        return False, "Cloudflare verification failed."

    except Exception:
        return False, "Unable to verify Cloudflare."


# -------------------------------------------------------------------
# Email creation
# -------------------------------------------------------------------

def build_message(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):
    sender_name = clean_header(sender_name)
    subject = clean_header(subject)
    gmail = clean_header(gmail)
    recipient_email = clean_header(recipient["email"])

    final_body = personalize(body, recipient)
    final_body = expand_spintax(final_body)

    plain_body = (
        html_to_plain_text(final_body)
        if is_html
        else final_body
    )

    if is_html:
        message = MIMEMultipart("alternative")

        message.attach(
            MIMEText(
                plain_body,
                "plain",
                "utf-8",
            )
        )

        message.attach(
            MIMEText(
                final_body,
                "html",
                "utf-8",
            )
        )
    else:
        message = MIMEText(
            final_body,
            "plain",
            "utf-8",
        )

    message["Subject"] = subject
    message["From"] = formataddr(
        (sender_name, gmail)
    )
    message["To"] = recipient_email
    message["Date"] = formatdate(
        localtime=True
    )
    message["Message-ID"] = make_msgid()

    return message


# -------------------------------------------------------------------
# SMTP
# -------------------------------------------------------------------

def send_one_email(
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):
    email = recipient["email"]

    last_error = "Unknown SMTP error."

    for attempt in range(MAX_RETRIES + 1):
        server = None

        try:
            if attempt > 0:
                time.sleep(
                    RETRY_DELAY_SECONDS * attempt
                )

            # Preserve the requested pacing.
            time.sleep(SEND_DELAY_SECONDS)

            context = ssl.create_default_context()

            server = smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                context=context,
                timeout=SMTP_TIMEOUT,
            )

            server.ehlo()

            server.login(
                gmail,
                app_password,
            )

            message = build_message(
                gmail=gmail,
                sender_name=sender_name,
                subject=subject,
                body=body,
                is_html=is_html,
                recipient=recipient,
            )

            refused = server.sendmail(
                gmail,
                [email],
                message.as_string(),
            )

            if refused:
                return {
                    "email": email,
                    "result": "failed",
                    "error": "Recipient was refused by SMTP.",
                }

            return {
                "email": email,
                "result": "sent",
            }

        except smtplib.SMTPAuthenticationError:
            return {
                "email": email,
                "result": "failed",
                "error": (
                    "Gmail authentication failed. "
                    "Check the Gmail address and App Password."
                ),
            }

        except (
            smtplib.SMTPServerDisconnected,
            smtplib.SMTPConnectError,
            TimeoutError,
            OSError,
        ) as exc:
            last_error = str(exc) or "Temporary SMTP connection error."

            if attempt < MAX_RETRIES:
                continue

        except smtplib.SMTPException as exc:
            last_error = str(exc) or "SMTP error."

            if attempt < MAX_RETRIES:
                continue

        except Exception as exc:
            last_error = str(exc) or "Unexpected sending error."

            if attempt < MAX_RETRIES:
                continue

        finally:
            if server is not None:
                try:
                    server.quit()
                except Exception:
                    try:
                        server.close()
                    except Exception:
                        pass

    return {
        "email": email,
        "result": "failed",
        "error": last_error,
    }


# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        password = request.form.get(
            "password",
            "",
        )

        if secrets.compare_digest(
            password,
            LOGIN_PASSWORD,
        ):
            session.clear()
            session.permanent = True
            session["authenticated"] = True

            return redirect(url_for("home"))

        error = "Invalid password."

    return render_template(
        "login.html",
        error=error,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "Secure Mail Console",
        "smtp": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "max_recipients": MAX_RECIPIENTS,
        "parallel": MAX_PARALLEL_SENDS,
        "delay_seconds": SEND_DELAY_SECONDS,
        "turnstile_configured": bool(
            TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY
        ),
    })


@app.route("/send-batch", methods=["POST"])
def send_batch():
    data = request.get_json(
        silent=True
    ) or {}

    sender_name = str(
        data.get("sender_name", "")
    ).strip()

    gmail = str(
        data.get("gmail", "")
    ).strip().lower()

    app_password = str(
        data.get("app_password", "")
    ).replace(" ", "").strip()

    subject = str(
        data.get("subject", "")
    ).strip()

    body = str(
        data.get("body", "")
    )

    is_html = bool(
        data.get("is_html", False)
    )

    recipients = normalize_recipients(
        data.get("recipients", [])
    )

    turnstile_token = str(
        data.get("turnstile_token", "")
    ).strip()

    if not sender_name:
        return jsonify({
            "error": "Sender Name is required."
        }), 400

    if not valid_email(gmail):
        return jsonify({
            "error": "Please enter a valid Gmail address."
        }), 400

    if not app_password:
        return jsonify({
            "error": "Google App Password is required."
        }), 400

    if not subject:
        return jsonify({
            "error": "Subject is required."
        }), 400

    if not body.strip():
        return jsonify({
            "error": "Message body is required."
        }), 400

    if not recipients:
        return jsonify({
            "error": "No valid recipients were provided."
        }), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "error": (
                f"Maximum {MAX_RECIPIENTS} recipients "
                "are allowed per batch."
            )
        }), 400

    remote_ip = (
        request.headers.get("X-Forwarded-For", "")
        .split(",")[0]
        .strip()
        or request.remote_addr
    )

    turnstile_ok, turnstile_error = verify_turnstile(
        turnstile_token,
        remote_ip,
    )

    if not turnstile_ok:
        return jsonify({
            "error": turnstile_error
        }), 400

    total = len(recipients)

    def generate():
        sent = 0
        failed = 0
        completed = 0

        start_event = {
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total,
            "parallel": MAX_PARALLEL_SENDS,
            "delay": SEND_DELAY_SECONDS,
        }

        yield (
            json.dumps(
                start_event
            ) + "\n"
        )

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
                ): recipient
                for recipient in recipients
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:
                    recipient = futures[future]

                    result = {
                        "email": recipient["email"],
                        "result": "failed",
                        "error": str(exc),
                    }

                completed += 1

                if result.get("result") == "sent":
                    sent += 1
                else:
                    failed += 1

                progress_event = {
                    "type": "progress",
                    "email": result.get("email", ""),
                    "result": result.get("result", "failed"),
                    "error": result.get("error", ""),
                    "sent": sent,
                    "failed": failed,
                    "completed": completed,
                    "remaining": total - completed,
                    "total": total,
                }

                yield (
                    json.dumps(
                        progress_event
                    ) + "\n"
                )

        complete_event = {
            "type": "complete",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0,
        }

        yield (
            json.dumps(
                complete_event
            ) + "\n"
        )

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache, no-store",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )
