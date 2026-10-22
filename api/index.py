
import os
import re
import ssl
import json
import hmac
import html
import time
import smtplib
import urllib.parse
import urllib.request
from pathlib import Path
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, formatdate

from flask import Flask, request, render_template, redirect, url_for, jsonify, session, Response

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)
handler = app

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()

if len(SESSION_SECRET) < 32:
    raise RuntimeError("Set SESSION_SECRET to a random secret of at least 32 characters.")
if not LOGIN_PASSWORD:
    raise RuntimeError("Set LOGIN_PASSWORD in Vercel.")

app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    MAX_CONTENT_LENGTH=1_000_000,
)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20
MAX_RECIPIENTS = 25
SEND_DELAY_SECONDS = 0

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def clean(value, limit=250):
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def valid_email(value):
    return (
        isinstance(value, str)
        and len(value.strip()) <= 254
        and bool(EMAIL_RE.fullmatch(value.strip()))
    )


def logged_in():
    return session.get("authenticated") is True


def error(message, status=400):
    return jsonify({"success": False, "message": message}), status


def event_line(data):
    return json.dumps(data, ensure_ascii=False) + "\n"


def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return False, "TURNSTILE_SECRET_KEY is not configured."
    if not token:
        return False, "Complete the verification first."

    fields = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }
    if remote_ip:
        fields["remoteip"] = remote_ip

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=urllib.parse.urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))
        if result.get("success") is True:
            return True, None
        return False, "Verification failed. Refresh and try again."
    except Exception:
        return False, "Verification service unavailable. Please try again."


def html_to_text(value):
    value = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", value)
    value = re.sub(r"(?i)</\s*(p|div|li|h[1-6])\s*>", "\n", value)
    value = re.sub(r"<[^>]*>", " ", value)
    value = html.unescape(value)
    return re.sub(r"\n{3,}", "\n\n", value).strip()


def normalize_recipient(item):
    if isinstance(item, str):
        item = {"email": item}
    if not isinstance(item, dict):
        return None

    address = str(item.get("email", "")).strip().lower()
    if not valid_email(address):
        return None

    return {
        "email": address,
        "name": clean(item.get("name", ""), 150),
        "hi": clean(item.get("hi", ""), 100),
        "hello": clean(item.get("hello", ""), 100),
        "thanks": clean(item.get("thanks", ""), 100),
        "ref_code": clean(item.get("ref_code", ""), 100),
    }


def personalize(value, recipient):
    result = str(value or "")
    for key in ("hi", "hello", "thanks", "name", "email", "ref_code"):
        result = result.replace(
            "{{" + key + "}}", recipient.get(key, "")
        )
    return result


def send_one(gmail, app_password, sender_name, subject, body, is_html, recipient):
    if SEND_DELAY_SECONDS:
        time.sleep(SEND_DELAY_SECONDS)

    message = EmailMessage()
    message["Subject"] = clean(personalize(subject, recipient), 250)
    message["From"] = formataddr((clean(sender_name), gmail))
    message["To"] = recipient["email"]
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    personalized_body = personalize(body, recipient)

    if is_html:
        message.set_content(
            html_to_text(personalized_body)
            or "Please view this email in an HTML-capable email client."
        )
        message.add_alternative(personalized_body, subtype="html")
    else:
        message.set_content(personalized_body)

    password = re.sub(r"\s+", "", app_password)
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        SMTP_HOST, SMTP_PORT, context=context, timeout=SMTP_TIMEOUT
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


@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template("login.html", error=None)

    password = str(request.form.get("password", ""))
    if not hmac.compare_digest(password, LOGIN_PASSWORD):
        return render_template(
            "login.html", error="Incorrect password."
        ), 401

    session.clear()
    session.permanent = True
    session["authenticated"] = True
    return redirect(url_for("home"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def home():
    if not logged_in():
        return redirect(url_for("login"))
    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "smtp": "Gmail SMTP",
        "max_recipients": MAX_RECIPIENTS,
        "send_delay_seconds": SEND_DELAY_SECONDS,
    })


@app.route("/favicon.ico")
def favicon():
    return Response("", status=204)


@app.route("/sw.js")
def service_worker():
    return Response("", mimetype="application/javascript")


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

    sender_name = clean(data.get("sender_name", ""))
    gmail = clean(data.get("gmail", ""), 254).lower()
    app_password = str(data.get("app_password", "")).strip()
    subject = clean(data.get("subject", ""), 250)
    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True
    incoming = data.get("recipients", [])

    if not sender_name:
        return error("Sender name is required.")
    if not valid_email(gmail) or not gmail.endswith("@gmail.com"):
        return error("Use a valid @gmail.com sender address.")
    if not app_password or not subject or not body.strip():
        return error("App Password, subject and body are required.")
    if len(body) > 100_000:
        return error("Email body is too large.")
    if not isinstance(incoming, list):
        return error("Recipients must be a list.")
    if data.get("consent_confirmed") is not True:
        return error("Confirm that recipients have permission to receive this email.")

    recipients, seen = [], set()
    invalid = 0

    for item in incoming:
        recipient = normalize_recipient(item)
        if recipient is None:
            invalid += 1
            continue
        if recipient["email"] not in seen:
            seen.add(recipient["email"])
            recipients.append(recipient)

    if not recipients:
        return error("No valid recipients found.")
    if len(recipients) > MAX_RECIPIENTS:
        return error(f"Maximum {MAX_RECIPIENTS} unique recipients per batch.")

    verified, reason = verify_turnstile(
        str(data.get("turnstile_token", "")).strip(),
        request.remote_addr,
    )
    if not verified:
        return error(reason or "Verification failed.", 403)

    def generate():
        total = len(recipients)
        sent = failed = 0

        yield event_line({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total,
            "invalid_skipped": invalid,
        })

        for recipient in recipients:
            try:
                send_one(
                    gmail, app_password, sender_name,
                    subject, body, is_html, recipient,
                )
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
                    "error": "Gmail login failed. Check the address and App Password.",
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
                item = {
                    "type": "progress",
                    "recipient": recipient["email"],
                    "result": "failed",
                    "error": f"SMTP error {exc.smtp_code}: {str(exc.smtp_error)[:200]}",
                }

            except (smtplib.SMTPException, TimeoutError, OSError) as exc:
                failed += 1
                item = {
                    "type": "progress",
                    "recipient": recipient["email"],
                    "result": "failed",
                    "error": f"SMTP/network error: {str(exc)[:200]}",
                }

            except Exception:
                failed += 1
                item = {
                    "type": "progress",
                    "recipient": recipient["email"],
                    "result": "failed",
                    "error": "Unexpected error. Check Vercel logs.",
                }

            item.update({
                "total": total,
                "sent": sent,
                "failed": failed,
                "remaining": total - sent - failed,
            })
            yield event_line(item)

        yield event_line({
            "type": "complete",
            "success": failed == 0,
            "message": "Sending attempt finished. SMTP acceptance does not prove Inbox delivery.",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0,
        })

    response = Response(
        generate(),
        content_type="application/x-ndjson; charset=utf-8",
    )
    response.headers["Cache-Control"] = "no-store, no-cache, no-transform"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Accel-Buffering"] = "no"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
