# api/index.py

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

import os
import re
import ssl
import json
import time
import secrets
import smtplib
import urllib.request
import urllib.parse
import html as html_lib

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


# ============================================================
# FLASK APP
# ============================================================

app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
    static_url_path="/static",
)


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()

UNSUBSCRIBE_BASE_URL = (
    os.environ.get("UNSUBSCRIBE_BASE_URL", "")
    .strip()
    .rstrip("/")
)


if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is not configured.")


app.secret_key = SESSION_SECRET


# ============================================================
# SESSION SECURITY
# ============================================================

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# ============================================================
# SMTP SETTINGS
# ============================================================

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

# Keep sending speed/settings
MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 4
SEND_DELAY_SECONDS = 1.8

SMTP_RETRIES = 2


# ============================================================
# EMAIL VALIDATION
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?)+$"
)


def valid_email(value):
    if not value:
        return False

    value = value.strip()

    if len(value) > 254:
        return False

    return bool(EMAIL_RE.fullmatch(value))


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_header(value):
    """
    Prevent CR/LF header injection.
    """
    if value is None:
        return ""

    return (
        str(value)
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


def html_to_plain_text(value):
    """
    Basic HTML -> plain text conversion.
    """
    if not value:
        return ""

    text = str(value)

    text = re.sub(
        r"(?is)<(script|style).*?>.*?</\1>",
        "",
        text,
    )

    text = re.sub(
        r"(?i)<br\s*/?>",
        "\n",
        text,
    )

    text = re.sub(
        r"(?i)</p\s*>",
        "\n\n",
        text,
    )

    text = re.sub(
        r"(?i)</div\s*>",
        "\n",
        text,
    )

    text = re.sub(
        r"(?s)<[^>]+>",
        "",
        text,
    )

    text = html_lib.unescape(text)

    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


# ============================================================
# SIMPLE SPINTAX
# ============================================================

def expand_spintax(text):
    """
    Supports simple:
        {Hello|Hi|Greetings}

    This is ordinary content variation only.
    """

    if not text:
        return ""

    pattern = re.compile(r"\{([^{}|]+(?:\|[^{}|]+)+)\}")

    max_rounds = 20

    for _ in range(max_rounds):
        match = pattern.search(text)

        if not match:
            break

        options = match.group(1).split("|")

        if not options:
            break

        selected = secrets.choice(options).strip()

        text = (
            text[:match.start()]
            + selected
            + text[match.end():]
        )

    return text


# ============================================================
# PERSONALIZATION
# ============================================================

def first_name_from_email(email):
    """
    Used only when {{name}} is requested and no better name
    is available.
    """

    local_part = email.split("@", 1)[0]

    local_part = re.sub(
        r"[^A-Za-z0-9._-]+",
        " ",
        local_part,
    )

    local_part = re.sub(
        r"[._-]+",
        " ",
        local_part,
    )

    local_part = local_part.strip()

    if not local_part:
        return ""

    return local_part.split()[0]


def personalize_text(text, recipient):
    if not text:
        return ""

    email = recipient.strip().lower()
    name = first_name_from_email(email)

    replacements = {
        "{{email}}": email,
        "{{name}}": name,
        "{{hi}}": "Hi",
        "{{hello}}": "Hello",
        "{{thanks}}": "Thanks",
    }

    result = str(text)

    for key, value in replacements.items():
        result = result.replace(key, value)

    return result


# ============================================================
# UNSUBSCRIBE
# ============================================================

def build_unsubscribe_url(recipient):
    """
    Builds:

    https://your-domain.com/unsubscribe?email=user@example.com
    """

    if not UNSUBSCRIBE_BASE_URL:
        return ""

    encoded_email = urllib.parse.quote(
        recipient.strip().lower(),
        safe="",
    )

    separator = (
        "&"
        if "?" in UNSUBSCRIBE_BASE_URL
        else "?"
    )

    return (
        f"{UNSUBSCRIBE_BASE_URL}"
        f"{separator}email={encoded_email}"
    )


def add_unsubscribe_footer(
    plain_body,
    html_body,
    recipient,
):
    """
    Adds a clear unsubscribe link to the email.

    If UNSUBSCRIBE_BASE_URL is not configured,
    the original body is returned unchanged.
    """

    unsubscribe_url = build_unsubscribe_url(recipient)

    if not unsubscribe_url:
        return plain_body, html_body

    # ----------------------------
    # Plain text footer
    # ----------------------------

    plain_footer = (
        "\n\n"
        "----------------------------------------\n"
        "Unsubscribe:\n"
        f"{unsubscribe_url}\n"
        "----------------------------------------"
    )

    final_plain = (
        plain_body.rstrip()
        + plain_footer
    )

    # ----------------------------
    # HTML footer
    # ----------------------------

    safe_url = html_lib.escape(
        unsubscribe_url,
        quote=True,
    )

    html_footer = f"""
<hr>
<p style="font-size:12px;color:#666;">
If you no longer want to receive these emails,
<a href="{safe_url}">unsubscribe here</a>.
</p>
"""

    final_html = (
        html_body.rstrip()
        + html_footer
    )

    return final_plain, final_html


# ============================================================
# TURNSTILE
# ============================================================

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

    data = urllib.parse.urlencode(payload).encode(
        "utf-8"
    )

    try:
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data,
            headers={
                "Content-Type":
                    "application/x-www-form-urlencoded",
                "User-Agent":
                    "USA-Safe-Email-Console/1.0",
            },
            method="POST",
        )

        with urllib.request.urlopen(
            req,
            timeout=10,
        ) as response:

            raw = response.read().decode(
                "utf-8",
                errors="replace",
            )

        result = json.loads(raw)

        if result.get("success") is True:
            return True, None

        return False, "Cloudflare verification failed."

    except Exception:
        return False, "Unable to verify Cloudflare."


# ============================================================
# AUTH
# ============================================================

def authenticated():
    return session.get("authenticated") is True


@app.before_request
def require_login():

    allowed_endpoints = {
        "login",
        "health",
        "static",
        "unsubscribe",
    }

    if request.endpoint in allowed_endpoints:
        return None

    if authenticated():
        return None

    if request.path.startswith("/api/"):
        return jsonify(
            {
                "ok": False,
                "message": "Login required.",
                "login_required": True,
            }
        ), 401

    if request.path == "/send-batch":
        return jsonify(
            {
                "ok": False,
                "message": "Login required.",
                "login_required": True,
            }
        ), 401

    return redirect(
        url_for("login")
    )


# ============================================================
# MESSAGE BUILDING
# ============================================================

def build_message(
    gmail,
    sender_name,
    subject,
    plain_body,
    html_body,
    recipient,
):
    """
    Builds a standards-based multipart/alternative message.
    """

    message = MIMEMultipart("alternative")

    message["Subject"] = clean_header(subject)

    message["From"] = formataddr(
        (
            clean_header(sender_name),
            clean_header(gmail),
        )
    )

    message["To"] = clean_header(recipient)

    message["Date"] = formatdate(
        localtime=True
    )

    message["Message-ID"] = make_msgid()

    message["MIME-Version"] = "1.0"

    # Helpful standard unsubscribe headers.
    unsubscribe_url = build_unsubscribe_url(
        recipient
    )

    if unsubscribe_url:
        message["List-Unsubscribe"] = (
            f"<{unsubscribe_url}>"
        )

        message["List-Unsubscribe-Post"] = (
            "List-Unsubscribe=One-Click"
        )

    message.attach(
        MIMEText(
            plain_body,
            "plain",
            "utf-8",
        )
    )

    message.attach(
        MIMEText(
            html_body,
            "html",
            "utf-8",
        )
    )

    return message


# ============================================================
# SMTP SEND
# ============================================================

def send_one_email(
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):
    """
    Send one email through authenticated Gmail SMTP.
    """

    recipient = recipient.strip().lower()

    if not valid_email(recipient):
        return {
            "email": recipient,
            "result": "failed",
            "error": "Invalid recipient email.",
        }

    # ----------------------------
    # Personalize
    # ----------------------------

    personalized_body = personalize_text(
        body,
        recipient,
    )

    # ----------------------------
    # Spintax
    # ----------------------------

    personalized_body = expand_spintax(
        personalized_body
    )

    # ----------------------------
    # Prepare HTML/plain
    # ----------------------------

    if is_html:
        html_body = personalized_body

        plain_body = html_to_plain_text(
            personalized_body
        )

    else:
        plain_body = personalized_body

        escaped = html_lib.escape(
            personalized_body
        )

        html_body = (
            escaped
            .replace("\n", "<br>\n")
        )

    # ----------------------------
    # Unsubscribe footer
    # ----------------------------

    plain_body, html_body = add_unsubscribe_footer(
        plain_body,
        html_body,
        recipient,
    )

    # ----------------------------
    # Message
    # ----------------------------

    message = build_message(
        gmail=gmail,
        sender_name=sender_name,
        subject=subject,
        plain_body=plain_body,
        html_body=html_body,
        recipient=recipient,
    )

    last_error = None

    # ----------------------------
    # SMTP retries
    # ----------------------------

    for attempt in range(
        SMTP_RETRIES + 1
    ):

        server = None

        try:
            context = ssl.create_default_context()

            server = smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                context=context,
                timeout=SMTP_TIMEOUT,
            )

            server.login(
                gmail,
                app_password,
            )

            server.sendmail(
                gmail,
                [recipient],
                message.as_string(),
            )

            return {
                "email": recipient,
                "result": "sent",
            }

        except (
            smtplib.SMTPAuthenticationError
        ) as exc:

            return {
                "email": recipient,
                "result": "failed",
                "error": (
                    "Gmail authentication failed. "
                    "Check Gmail address and App Password."
                ),
            }

        except (
            smtplib.SMTPConnectError,
            smtplib.SMTPServerDisconnected,
            TimeoutError,
            OSError,
        ) as exc:

            last_error = str(exc)

            if attempt < SMTP_RETRIES:
                time.sleep(
                    1.5 * (attempt + 1)
                )
                continue

            return {
                "email": recipient,
                "result": "failed",
                "error": (
                    last_error
                    or "SMTP connection failed."
                ),
            }

        except smtplib.SMTPException as exc:

            last_error = str(exc)

            if attempt < SMTP_RETRIES:
                time.sleep(
                    1.5 * (attempt + 1)
                )
                continue

            return {
                "email": recipient,
                "result": "failed",
                "error": (
                    last_error
                    or "SMTP error."
                ),
            }

        except Exception as exc:

            return {
                "email": recipient,
                "result": "failed",
                "error": str(exc),
            }

        finally:

            if server is not None:
                try:
                    server.quit()
                except Exception:
                    try:
                        server.close()
                    except Exception:
                        pass


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"],
)
def login():

    if authenticated():
        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        password = (
            request.form.get(
                "password",
                "",
            )
            .strip()
        )

        turnstile_token = (
            request.form.get(
                "cf-turnstile-response",
                "",
            )
            or request.form.get(
                "turnstile_token",
                "",
            )
            .strip()
        )

        # ----------------------------
        # Turnstile
        # ----------------------------

        if TURNSTILE_SECRET_KEY:

            remote_ip = (
                request.headers.get(
                    "X-Forwarded-For",
                    request.remote_addr,
                )
                or ""
            )

            remote_ip = (
                remote_ip
                .split(",")[0]
                .strip()
            )

            ok, error = verify_turnstile(
                turnstile_token,
                remote_ip,
            )

            if not ok:
                return render_template(
                    "login.html",
                    error=error,
                    turnstile_site_key=(
                        TURNSTILE_SITE_KEY
                    ),
                )

        # ----------------------------
        # Password
        # ----------------------------

        if not LOGIN_PASSWORD:
            return render_template(
                "login.html",
                error=(
                    "LOGIN_PASSWORD is not configured."
                ),
                turnstile_site_key=(
                    TURNSTILE_SITE_KEY
                ),
            )

        if not secrets.compare_digest(
            password,
            LOGIN_PASSWORD,
        ):
            return render_template(
                "login.html",
                error="Invalid password.",
                turnstile_site_key=(
                    TURNSTILE_SITE_KEY
                ),
            )

        # ----------------------------
        # Successful login
        # ----------------------------

        session.clear()

        session.permanent = True

        session["authenticated"] = True

        return redirect(
            url_for("home")
        )

    return render_template(
        "login.html",
        error=None,
        turnstile_site_key=(
            TURNSTILE_SITE_KEY
        ),
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route(
    "/logout",
    methods=["GET"],
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# HOME
# ============================================================

@app.route(
    "/",
    methods=["GET"],
)
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# UNSUBSCRIBE
# ============================================================

@app.route(
    "/unsubscribe",
    methods=["GET", "POST"],
)
def unsubscribe():

    email = ""

    if request.method == "POST":

        email = (
            request.form.get(
                "email",
                "",
            )
            or request.args.get(
                "email",
                "",
            )
        ).strip().lower()

    else:

        email = (
            request.args.get(
                "email",
                "",
            )
            .strip()
            .lower()
        )

    if email and not valid_email(email):

        return (
            """
            <!doctype html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Unsubscribe</title>
            </head>
            <body>
                <h2>Invalid email address.</h2>
                <p>Please use a valid email address.</p>
            </body>
            </html>
            """,
            400,
        )

    if email:

        safe_email = html_lib.escape(
            email
        )

        return f"""
        <!doctype html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport"
                  content="width=device-width,initial-scale=1">
            <title>Unsubscribe</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 620px;
                    margin: 60px auto;
                    padding: 20px;
                    line-height: 1.6;
                }}

                .box {{
                    border: 1px solid #ddd;
                    border-radius: 12px;
                    padding: 25px;
                }}

                h2 {{
                    margin-top: 0;
                }}
            </style>
        </head>

        <body>

            <div class="box">

                <h2>Unsubscribe</h2>

                <p>
                    You requested to unsubscribe:
                </p>

                <p>
                    <strong>{safe_email}</strong>
                </p>

                <p>
                    Your unsubscribe request has been received.
                </p>

                <p>
                    If this application is connected to a
                    persistent suppression database, that address
                    should be marked as unsubscribed there.
                </p>

            </div>

        </body>
        </html>
        """

    return """
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport"
              content="width=device-width,initial-scale=1">
        <title>Unsubscribe</title>
    </head>

    <body style="
        font-family:Arial,sans-serif;
        max-width:620px;
        margin:60px auto;
        padding:20px;
    ">

        <h2>Unsubscribe</h2>

        <form method="post">

            <label>
                Email address
            </label>

            <br><br>

            <input
                type="email"
                name="email"
                required
                style="
                    width:100%;
                    padding:12px;
                    box-sizing:border-box;
                "
            >

            <br><br>

            <button
                type="submit"
                style="
                    padding:12px 20px;
                    cursor:pointer;
                "
            >
                Unsubscribe
            </button>

        </form>

    </body>
    </html>
    """


# ============================================================
# SEND BATCH
# ============================================================

@app.route(
    "/send-batch",
    methods=["POST"],
)
def send_batch():

    # ========================================================
    # BASIC FORM VALUES
    # ========================================================

    gmail = (
        request.form.get(
            "gmail",
            "",
        )
        .strip()
        .lower()
    )

    sender_name = (
        request.form.get(
            "sender_name",
            "",
        )
        .strip()
    )

    app_password = (
        request.form.get(
            "app_password",
            "",
        )
        .strip()
    )

    subject = (
        request.form.get(
            "subject",
            "",
        )
        .strip()
    )

    body = (
        request.form.get(
            "body",
            "",
        )
        or ""
    )

    recipients_raw = (
        request.form.get(
            "recipients",
            "",
        )
        or ""
    )

    # Support alternate field names if the existing UI uses them.
    if not recipients_raw:

        recipients_raw = (
            request.form.get(
                "emails",
                "",
            )
            or request.form.get(
                "recipient_list",
                "",
            )
        )

    # ========================================================
    # HTML MODE
    # ========================================================

    is_html_raw = (
        request.form.get(
            "is_html",
            "",
        )
        or request.form.get(
            "html",
            "",
        )
    )

    is_html = str(
        is_html_raw
    ).lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    # ========================================================
    # TURNSTILE
    # ========================================================

    turnstile_token = (
        request.form.get(
            "cf-turnstile-response",
            "",
        )
        or request.form.get(
            "turnstile_token",
            "",
        )
    ).strip()

    if TURNSTILE_SECRET_KEY:

        remote_ip = (
            request.headers.get(
                "X-Forwarded-For",
                request.remote_addr,
            )
            or ""
        )

        remote_ip = (
            remote_ip
            .split(",")[0]
            .strip()
        )

        ok, error = verify_turnstile(
            turnstile_token,
            remote_ip,
        )

        if not ok:
            return jsonify(
                {
                    "ok": False,
                    "message": error,
                }
            ), 400

    # ========================================================
    # VALIDATION
    # ========================================================

    if not sender_name:
        return jsonify(
            {
                "ok": False,
                "message": "Sender Name is required.",
            }
        ), 400

    if not valid_email(gmail):
        return jsonify(
            {
                "ok": False,
                "message": "Please enter a valid Gmail address.",
            }
        ), 400

    if not app_password:
        return jsonify(
            {
                "ok": False,
                "message": "Google App Password is required.",
            }
        ), 400

    if not subject:
        return jsonify(
            {
                "ok": False,
                "message": "Subject is required.",
            }
        ), 400

    if not body.strip():
        return jsonify(
            {
                "ok": False,
                "message": "Email body is required.",
            }
        ), 400

    # ========================================================
    # RECIPIENT PARSING
    # ========================================================

    raw_items = re.split(
        r"[\s,;]+",
        recipients_raw,
    )

    clean_recipients = []

    seen = set()

    for item in raw_items:

        email = item.strip().lower()

        if not email:
            continue

        if not valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)

        clean_recipients.append(email)

        if len(clean_recipients) >= MAX_RECIPIENTS:
            break

    if not clean_recipients:
        return jsonify(
            {
                "ok": False,
                "message": (
                    "No valid recipient emails were found."
                ),
            }
        ), 400

    # ========================================================
    # STREAMING SEND
    # ========================================================

    def generate():

        total = len(clean_recipients)

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
                start_event,
                ensure_ascii=False,
            )
            + "\n"
        )

        # ====================================================
        # Thread pool
        # ====================================================

        with ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        ) as executor:

            future_map = {}

            for recipient in clean_recipients:

                future = executor.submit(
                    send_one_email,
                    gmail,
                    app_password,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    recipient,
                )

                future_map[future] = recipient

            # =================================================
            # Process completed messages
            # =================================================

            for future in as_completed(
                future_map
            ):

                recipient = future_map[future]

                try:
                    result = future.result()

                except Exception as exc:

                    result = {
                        "email": recipient,
                        "result": "failed",
                        "error": str(exc),
                    }

                completed += 1

                if result.get("result") == "sent":
                    sent += 1
                else:
                    failed += 1

                remaining = (
                    total - completed
                )

                progress_event = {
                    "type": "progress",
                    "email": recipient,
                    "result": result.get(
                        "result",
                        "failed",
                    ),
                    "error": result.get(
                        "error"
                    ),
                    "sent": sent,
                    "failed": failed,
                    "completed": completed,
                    "total": total,
                    "remaining": remaining,
                }

                yield (
                    json.dumps(
                        progress_event,
                        ensure_ascii=False,
                    )
                    + "\n"
                )

                # Controlled pacing between completion
                # notifications/tasks.
                if remaining > 0:
                    time.sleep(
                        SEND_DELAY_SECONDS
                    )

        # ====================================================
        # Complete
        # ====================================================

        complete_event = {
            "type": "complete",
            "ok": failed == 0,
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0,
        }

        yield (
            json.dumps(
                complete_event,
                ensure_ascii=False,
            )
            + "\n"
        )

    return Response(
        stream_with_context(
            generate()
        ),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ============================================================
# HEALTH
# ============================================================

@app.route(
    "/health",
    methods=["GET"],
)
def health():

    return jsonify(
        {
            "ok": True,
            "service": "USA Safe Email Console",
            "smtp": SMTP_HOST,
            "smtp_port": SMTP_PORT,
            "max_recipients": MAX_RECIPIENTS,
            "parallel": MAX_PARALLEL_SENDS,
            "delay": SEND_DELAY_SECONDS,
            "turnstile_configured": bool(
                TURNSTILE_SECRET_KEY
            ),
            "unsubscribe_configured": bool(
                UNSUBSCRIBE_BASE_URL
            ),
        }
    )


# ============================================================
# VERCEL HANDLER
# ============================================================

handler = app


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                "5000",
            )
        ),
        debug=False,
    )
