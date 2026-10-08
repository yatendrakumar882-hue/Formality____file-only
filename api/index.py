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
import json
import secrets
import ssl
import smtplib
import time

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
    static_url_path="/static",
)


# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# SMTP
# ---------------------------------------------------------

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 30

MAX_RECIPIENTS = 25
SEND_DELAY_SECONDS = 2.0
MAX_RETRIES = 2


EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def authenticated():
    return session.get("authenticated") is True


def clean_header(value):
    """
    Prevent CR/LF header injection.
    """
    if value is None:
        return ""

    return str(value).replace("\r", " ").replace("\n", " ").strip()


def valid_email(email):
    if not email:
        return False

    email = email.strip().lower()

    if len(email) > 254:
        return False

    return bool(EMAIL_RE.fullmatch(email))


def parse_recipients(value):
    """
    Accept comma/newline/semicolon separated recipients.
    Remove duplicates and invalid addresses.
    """

    if not value:
        return []

    if isinstance(value, list):
        raw_items = value
    else:
        raw_items = re.split(r"[,;\n\r]+", str(value))

    result = []
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
        result.append(email)

        if len(result) >= MAX_RECIPIENTS:
            break

    return result


def expand_spintax(text):
    """
    Simple {one|two|three} spintax support.
    """

    if not text:
        return ""

    pattern = re.compile(r"\{([^{}]+)\}")

    def replace(match):
        options = match.group(1).split("|")

        if len(options) <= 1:
            return match.group(0)

        return secrets.choice(options).strip()

    previous = None
    current = text

    while current != previous:
        previous = current
        current = pattern.sub(replace, current)

    return current


def build_message(
    sender_email,
    sender_name,
    recipient,
    subject,
    body,
    is_html=False,
):
    sender_email = clean_header(sender_email)
    sender_name = clean_header(sender_name)
    recipient = clean_header(recipient)
    subject = clean_header(subject)

    final_body = expand_spintax(body)

    # multipart/alternative gives clients both HTML and plain text.
    message = MIMEMultipart("alternative")

    message["Subject"] = subject
    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()
    message["MIME-Version"] = "1.0"

    if is_html:
        html_body = final_body

        plain_body = re.sub(
            r"<br\s*/?>",
            "\n",
            html_body,
            flags=re.IGNORECASE,
        )

        plain_body = re.sub(
            r"<[^>]+>",
            "",
            plain_body,
        )

        message.attach(
            MIMEText(plain_body, "plain", "utf-8")
        )

        message.attach(
            MIMEText(html_body, "html", "utf-8")
        )

    else:
        message.attach(
            MIMEText(final_body, "plain", "utf-8")
        )

    return message


def create_smtp_connection(gmail, app_password):
    context = ssl.create_default_context()

    server = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT,
    )

    server.login(gmail, app_password)

    return server


def send_one_email(
    gmail,
    app_password,
    sender_name,
    recipient,
    subject,
    body,
    is_html,
):
    server = None

    try:
        server = create_smtp_connection(
            gmail,
            app_password,
        )

        message = build_message(
            sender_email=gmail,
            sender_name=sender_name,
            recipient=recipient,
            subject=subject,
            body=body,
            is_html=is_html,
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

    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


def send_with_retry(
    gmail,
    app_password,
    sender_name,
    recipient,
    subject,
    body,
    is_html,
):
    last_error = "Unknown error"

    for attempt in range(MAX_RETRIES + 1):
        try:
            return send_one_email(
                gmail,
                app_password,
                sender_name,
                recipient,
                subject,
                body,
                is_html,
            )

        except smtplib.SMTPAuthenticationError:
            raise

        except Exception as exc:
            last_error = str(exc)

            if attempt < MAX_RETRIES:
                time.sleep(1.5)

    return {
        "email": recipient,
        "result": "failed",
        "error": last_error,
    }


# ---------------------------------------------------------
# TURNSTILE
# ---------------------------------------------------------

def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return True, None

    if not token:
        return False, "Cloudflare verification is required."

    try:
        import urllib.request
        import urllib.parse

        data = {
            "secret": TURNSTILE_SECRET_KEY,
            "response": token,
        }

        if remote_ip:
            data["remoteip"] = remote_ip

        encoded = urllib.parse.urlencode(data).encode("utf-8")

        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=encoded,
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(
                response.read().decode("utf-8")
            )

        if result.get("success") is True:
            return True, None

        return False, "Cloudflare verification failed."

    except Exception:
        return False, "Unable to verify Cloudflare."


# ---------------------------------------------------------
# LOGIN PROTECTION
# ---------------------------------------------------------

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

    if request.path.startswith("/send-batch"):
        return jsonify({
            "ok": False,
            "login_required": True,
            "message": "Please login first.",
        }), 401

    return redirect(url_for("login"))


# ---------------------------------------------------------
# HEALTH
# ---------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "USA Safe Email Console",
        "smtp": "Gmail SMTP",
        "status": "ok",
    })


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if authenticated():
        return redirect(url_for("index"))

    if request.method == "POST":

        password = request.form.get(
            "password",
            "",
        )

        turnstile_token = request.form.get(
            "cf-turnstile-response",
            "",
        )

        remote_ip = (
            request.headers.get("X-Forwarded-For", "")
            .split(",")[0]
            .strip()
        )

        if not remote_ip:
            remote_ip = request.remote_addr

        turnstile_ok, turnstile_error = verify_turnstile(
            turnstile_token,
            remote_ip,
        )

        if not turnstile_ok:
            return render_template(
                "login.html",
                error=turnstile_error,
                turnstile_site_key=TURNSTILE_SITE_KEY,
            ), 403

        if not secrets.compare_digest(
            password,
            LOGIN_PASSWORD,
        ):
            return render_template(
                "login.html",
                error="Invalid password.",
                turnstile_site_key=TURNSTILE_SITE_KEY,
            ), 401

        session.clear()
        session.permanent = True
        session["authenticated"] = True

        return redirect(url_for("index"))

    return render_template(
        "login.html",
        error=None,
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------
# MAIN APP
# ---------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


# ---------------------------------------------------------
# SEND BATCH
# ---------------------------------------------------------

@app.route("/send-batch", methods=["POST"])
def send_batch():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "ok": False,
            "message": "Invalid JSON request.",
        }), 400

    sender_name = clean_header(
        data.get("sender_name", "")
    )

    gmail = clean_header(
        data.get("sender_email", "")
    ).lower()

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = clean_header(
        data.get("subject", "")
    )

    body = str(
        data.get("body", "")
    )

    is_html = bool(
        data.get("is_html", False)
    )

    recipients = parse_recipients(
        data.get("recipients", "")
    )

    turnstile_token = data.get(
        "turnstile_token",
        "",
    )

    # -----------------------------
    # Validation
    # -----------------------------

    if not sender_name:
        return jsonify({
            "ok": False,
            "message": "Sender Name is required.",
        }), 400

    if not valid_email(gmail):
        return jsonify({
            "ok": False,
            "message": "Please enter a valid Gmail address.",
        }), 400

    if not gmail.endswith("@gmail.com"):
        return jsonify({
            "ok": False,
            "message": "Please use a Gmail address.",
        }), 400

    if not app_password:
        return jsonify({
            "ok": False,
            "message": "Google App Password is required.",
        }), 400

    if not subject:
        return jsonify({
            "ok": False,
            "message": "Subject is required.",
        }), 400

    if not body.strip():
        return jsonify({
            "ok": False,
            "message": "Email body is required.",
        }), 400

    if not recipients:
        return jsonify({
            "ok": False,
            "message": "No valid recipients were found.",
        }), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "ok": False,
            "message": (
                f"Maximum {MAX_RECIPIENTS} recipients "
                "are allowed per batch."
            ),
        }), 400

    # -----------------------------
    # Turnstile
    # -----------------------------

    remote_ip = (
        request.headers.get(
            "X-Forwarded-For",
            "",
        )
        .split(",")[0]
        .strip()
    )

    if not remote_ip:
        remote_ip = request.remote_addr

    turnstile_ok, turnstile_error = verify_turnstile(
        turnstile_token,
        remote_ip,
    )

    if not turnstile_ok:
        return jsonify({
            "ok": False,
            "message": turnstile_error,
        }), 403

    # -----------------------------
    # Streaming response
    # -----------------------------

    def generate():

        total = len(recipients)
        sent = 0
        failed = 0

        yield json.dumps({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total,
            "parallel": 1,
            "delay": SEND_DELAY_SECONDS,
        }) + "\n"

        for index, recipient in enumerate(recipients):

            try:

                result = send_with_retry(
                    gmail=gmail,
                    app_password=app_password,
                    sender_name=sender_name,
                    recipient=recipient,
                    subject=subject,
                    body=body,
                    is_html=is_html,
                )

                if result["result"] == "sent":
                    sent += 1

                    event = {
                        "type": "progress",
                        "email": recipient,
                        "result": "sent",
                        "sent": sent,
                        "failed": failed,
                        "remaining": total - sent - failed,
                    }

                else:
                    failed += 1

                    event = {
                        "type": "progress",
                        "email": recipient,
                        "result": "failed",
                        "error": result.get(
                            "error",
                            "Unknown error",
                        ),
                        "sent": sent,
                        "failed": failed,
                        "remaining": total - sent - failed,
                    }

            except smtplib.SMTPAuthenticationError:
                failed += 1

                event = {
                    "type": "progress",
                    "email": recipient,
                    "result": "failed",
                    "error": (
                        "Gmail authentication failed. "
                        "Check Gmail address and App Password."
                    ),
                    "sent": sent,
                    "failed": failed,
                    "remaining": total - sent - failed,
                }

            except Exception as exc:
                failed += 1

                event = {
                    "type": "progress",
                    "email": recipient,
                    "result": "failed",
                    "error": str(exc),
                    "sent": sent,
                    "failed": failed,
                    "remaining": total - sent - failed,
                }

            yield json.dumps(event) + "\n"

            if index < total - 1:
                time.sleep(SEND_DELAY_SECONDS)

        yield json.dumps({
            "type": "complete",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0,
        }) + "\n"

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------
# VERCEL WSGI HANDLER
# ---------------------------------------------------------

handler = app
