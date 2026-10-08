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
import time
import ssl
import smtplib
import secrets
import urllib.request
import urllib.parse

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


# ============================================================
# APP
# ============================================================

app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
    static_url_path="/static",
)


# ============================================================
# REQUIRED ENVIRONMENT VARIABLES
# ============================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()


if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is not configured.")

if not LOGIN_PASSWORD:
    raise RuntimeError("LOGIN_PASSWORD is not configured.")


app.secret_key = SESSION_SECRET


# ============================================================
# SESSION / SECURITY
# ============================================================

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# ============================================================
# GMAIL SMTP
# ============================================================

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 30

# Conservative sending.
# Do not increase this aggressively.
SEND_DELAY_SECONDS = 2.0

# Maximum recipients per request.
MAX_RECIPIENTS = 25

# Maximum retries for temporary SMTP errors.
MAX_RETRIES = 2

# Retry delays.
RETRY_DELAYS = [3, 8]


# ============================================================
# VALIDATION
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def is_valid_email(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    if len(value) > 254:
        return False

    return bool(EMAIL_RE.fullmatch(value))


def clean_header(value):
    """
    Prevent CR/LF header injection.
    """
    if value is None:
        return ""

    value = str(value)

    return value.replace("\r", " ").replace("\n", " ").strip()


def normalize_gmail(value):
    """
    Only accept a normal Gmail address.
    """
    value = clean_header(value).lower()

    if not is_valid_email(value):
        return None

    if not value.endswith("@gmail.com"):
        return None

    return value


def normalize_app_password(value):
    """
    Google App Passwords are commonly displayed with spaces.
    Remove whitespace before SMTP authentication.
    """
    if value is None:
        return ""

    return re.sub(r"\s+", "", str(value)).strip()


def parse_recipients(raw):
    """
    Accept comma, semicolon or newline separated addresses.
    Deduplicate while preserving order.
    """
    if not raw:
        return []

    pieces = re.split(r"[,;\n\r]+", str(raw))

    result = []
    seen = set()

    for item in pieces:
        email = item.strip().lower()

        if not email:
            continue

        if not is_valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)
        result.append(email)

        if len(result) >= MAX_RECIPIENTS:
            break

    return result


# ============================================================
# LOGIN
# ============================================================

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

    if request.path.startswith("/send-batch"):
        return jsonify(
            {
                "ok": False,
                "message": "Login required.",
                "login_required": True,
            }
        ), 401

    return redirect(url_for("login"))


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

    encoded = urllib.parse.urlencode(payload).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "USA-Safe-Email-Console/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read().decode("utf-8", errors="replace")

        data = json.loads(raw)

        if data.get("success") is True:
            return True, None

        return False, "Cloudflare verification failed."

    except Exception:
        return False, "Unable to verify Cloudflare."


# ============================================================
# EMAIL BUILDING
# ============================================================

def build_message(
    sender_email,
    sender_name,
    subject,
    body,
    recipient,
    is_html=False,
):
    """
    Builds a standards-compliant message.

    For HTML messages, also creates a plain-text alternative.
    """

    sender_email = normalize_gmail(sender_email)

    sender_name = clean_header(sender_name)
    subject = clean_header(subject)
    recipient = clean_header(recipient)

    if is_html:
        message = MIMEMultipart("alternative")

        # Basic plain-text fallback.
        plain_body = re.sub(r"<[^>]+>", " ", body or "")
        plain_body = re.sub(r"\s+", " ", plain_body).strip()

        message.attach(
            MIMEText(
                plain_body,
                "plain",
                "utf-8",
            )
        )

        message.attach(
            MIMEText(
                body or "",
                "html",
                "utf-8",
            )
        )

    else:
        message = MIMEText(
            body or "",
            "plain",
            "utf-8",
        )

    message["Subject"] = str(
        Header(subject, "utf-8")
    )

    message["From"] = formataddr(
        (
            str(Header(sender_name, "utf-8")),
            sender_email,
        )
    )

    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    return message


# ============================================================
# SMTP HELPERS
# ============================================================

def create_smtp_connection(sender_email, app_password):
    context = ssl.create_default_context()

    server = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        timeout=SMTP_TIMEOUT,
        context=context,
    )

    server.ehlo()
    server.login(
        sender_email,
        app_password,
    )

    return server


def is_temporary_smtp_error(exc):
    """
    Temporary SMTP responses commonly include:
    421, 450, 451, 452
    """

    code = getattr(exc, "smtp_code", None)

    if code in {421, 450, 451, 452}:
        return True

    text = str(exc).lower()

    temporary_words = (
        "temporarily",
        "try again",
        "rate limit",
        "too many",
        "timeout",
        "timed out",
        "connection reset",
        "connection closed",
        "service not available",
    )

    return any(word in text for word in temporary_words)


def send_one_using_connection(
    server,
    sender_email,
    sender_name,
    subject,
    body,
    recipient,
    is_html,
):
    message = build_message(
        sender_email=sender_email,
        sender_name=sender_name,
        subject=subject,
        body=body,
        recipient=recipient,
        is_html=is_html,
    )

    refused = server.sendmail(
        sender_email,
        [recipient],
        message.as_string(),
    )

    # sendmail() returns a dict for refused recipients.
    if refused:
        return False, str(refused)

    return True, None


# ============================================================
# JSON STREAM HELPERS
# ============================================================

def stream_json(data):
    return json.dumps(
        data,
        ensure_ascii=False,
    ) + "\n"


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():
    return jsonify(
        {
            "ok": True,
            "service": "USA Safe Email Console",
        }
    )


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if authenticated():
        return redirect(url_for("index"))

    error = None

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
            or request.remote_addr
        )

        # Verify Turnstile when configured.
        if TURNSTILE_SECRET_KEY:

            valid_turnstile, turnstile_error = verify_turnstile(
                turnstile_token,
                remote_ip,
            )

            if not valid_turnstile:
                error = turnstile_error

        if error is None:

            if secrets.compare_digest(
                password,
                LOGIN_PASSWORD,
            ):
                session.clear()
                session.permanent = True
                session["authenticated"] = True

                return redirect(url_for("index"))

            error = "Incorrect password."

    return render_template(
        "login.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
        error=error,
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# MAIN PAGE
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
# SEND BATCH
# ============================================================

@app.route(
    "/send-batch",
    methods=["POST"],
)
def send_batch():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify(
            {
                "ok": False,
                "message": "Invalid request.",
            }
        ), 400

    sender_name = clean_header(
        data.get("sender_name", "")
    )

    sender_email = normalize_gmail(
        data.get("sender_email", "")
    )

    app_password = normalize_app_password(
        data.get("app_password", "")
    )

    subject = clean_header(
        data.get("subject", "")
    )

    body = str(
        data.get("body", "")
    ).strip()

    recipients_raw = data.get(
        "recipients",
        "",
    )

    is_html = bool(
        data.get("is_html", False)
    )

    turnstile_token = str(
        data.get(
            "turnstile_token",
            "",
        )
    ).strip()

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    if not sender_name:
        return jsonify(
            {
                "ok": False,
                "message": "Sender Name is required.",
            }
        ), 400

    if not sender_email:
        return jsonify(
            {
                "ok": False,
                "message": "A valid Gmail address is required.",
            }
        ), 400

    if not app_password:
        return jsonify(
            {
                "ok": False,
                "message": "Google App Password is required.",
            }
        ), 400

    if len(app_password) < 8:
        return jsonify(
            {
                "ok": False,
                "message": "The App Password appears invalid.",
            }
        ), 400

    if not subject:
        return jsonify(
            {
                "ok": False,
                "message": "Subject is required.",
            }
        ), 400

    if not body:
        return jsonify(
            {
                "ok": False,
                "message": "Message body is required.",
            }
        ), 400

    recipients = parse_recipients(
        recipients_raw
    )

    if not recipients:
        return jsonify(
            {
                "ok": False,
                "message": "No valid recipients were found.",
            }
        ), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify(
            {
                "ok": False,
                "message": f"Maximum {MAX_RECIPIENTS} recipients are allowed.",
            }
        ), 400

    # --------------------------------------------------------
    # TURNSTILE
    # --------------------------------------------------------

    if TURNSTILE_SECRET_KEY:

        remote_ip = (
            request.headers.get("X-Forwarded-For", "")
            .split(",")[0]
            .strip()
            or request.remote_addr
        )

        valid_turnstile, turnstile_error = verify_turnstile(
            turnstile_token,
            remote_ip,
        )

        if not valid_turnstile:
            return jsonify(
                {
                    "ok": False,
                    "message": turnstile_error,
                }
            ), 400

    # --------------------------------------------------------
    # STREAMING SEND
    # --------------------------------------------------------

    def generate():

        total = len(recipients)
        sent = 0
        failed = 0

        server = None

        yield stream_json(
            {
                "type": "start",
                "total": total,
                "sent": 0,
                "failed": 0,
                "remaining": total,
                "mode": "single-smtp-connection",
            }
        )

        try:

            # ------------------------------------------------
            # ONE SMTP CONNECTION
            # ------------------------------------------------

            try:
                server = create_smtp_connection(
                    sender_email,
                    app_password,
                )

            except smtplib.SMTPAuthenticationError:
                yield stream_json(
                    {
                        "type": "fatal",
                        "message": (
                            "Gmail authentication failed. "
                            "Check the Gmail address, 2-Step Verification "
                            "and Google App Password."
                        ),
                    }
                )
                return

            except Exception as exc:
                yield stream_json(
                    {
                        "type": "fatal",
                        "message": (
                            "Could not connect to Gmail SMTP: "
                            + str(exc)
                        ),
                    }
                )
                return

            # ------------------------------------------------
            # SEND ONE BY ONE
            # ------------------------------------------------

            for index, recipient in enumerate(
                recipients,
                start=1,
            ):

                success = False
                error_message = None

                for attempt in range(
                    MAX_RETRIES + 1
                ):

                    try:

                        success, error_message = (
                            send_one_using_connection(
                                server=server,
                                sender_email=sender_email,
                                sender_name=sender_name,
                                subject=subject,
                                body=body,
                                recipient=recipient,
                                is_html=is_html,
                            )
                        )

                        if success:
                            break

                        # Refused recipient.
                        break

                    except smtplib.SMTPServerDisconnected as exc:

                        error_message = str(exc)

                        if attempt >= MAX_RETRIES:
                            break

                        # Reconnect once after temporary disconnect.
                        try:
                            if server is not None:
                                try:
                                    server.quit()
                                except Exception:
                                    pass

                            server = create_smtp_connection(
                                sender_email,
                                app_password,
                            )

                        except Exception as reconnect_exc:
                            error_message = str(
                                reconnect_exc
                            )

                            if attempt >= MAX_RETRIES:
                                break

                        time.sleep(
                            RETRY_DELAYS[
                                min(
                                    attempt,
                                    len(RETRY_DELAYS) - 1,
                                )
                            ]
                        )

                    except smtplib.SMTPResponseException as exc:

                        error_message = (
                            f"SMTP {exc.smtp_code}: "
                            f"{exc.smtp_error}"
                        )

                        if not is_temporary_smtp_error(exc):
                            break

                        if attempt >= MAX_RETRIES:
                            break

                        time.sleep(
                            RETRY_DELAYS[
                                min(
                                    attempt,
                                    len(RETRY_DELAYS) - 1,
                                )
                            ]
                        )

                    except (
                        smtplib.SMTPConnectError,
                        TimeoutError,
                        ConnectionError,
                    ) as exc:

                        error_message = str(exc)

                        if attempt >= MAX_RETRIES:
                            break

                        time.sleep(
                            RETRY_DELAYS[
                                min(
                                    attempt,
                                    len(RETRY_DELAYS) - 1,
                                )
                            ]
                        )

                    except Exception as exc:

                        error_message = str(exc)
                        break

                # ------------------------------------------------
                # COUNTERS
                # ------------------------------------------------

                if success:
                    sent += 1
                    result = "sent"
                else:
                    failed += 1
                    result = "failed"

                remaining = total - sent - failed

                yield stream_json(
                    {
                        "type": "progress",
                        "index": index,
                        "total": total,
                        "email": recipient,
                        "result": result,
                        "error": error_message,
                        "sent": sent,
                        "failed": failed,
                        "remaining": remaining,
                    }
                )

                # ------------------------------------------------
                # CONTROLLED PACING
                # ------------------------------------------------

                if index < total:
                    time.sleep(
                        SEND_DELAY_SECONDS
                    )

            # ----------------------------------------------------
            # COMPLETE
            # ----------------------------------------------------

            yield stream_json(
                {
                    "type": "complete",
                    "total": total,
                    "sent": sent,
                    "failed": failed,
                    "remaining": 0,
                }
            )

        except Exception as exc:

            yield stream_json(
                {
                    "type": "fatal",
                    "message": str(exc),
                    "sent": sent,
                    "failed": failed,
                    "remaining": total - sent - failed,
                }
            )

        finally:

            if server is not None:
                try:
                    server.quit()
                except Exception:
                    try:
                        server.close()
                    except Exception:
                        pass

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ============================================================
# VERCEL HANDLER
# ============================================================

handler = app
