import os
import json
import re
import time
import hmac
import secrets
import hashlib
import sqlite3
import threading
import mimetypes
from datetime import datetime

import pandas as pd
import requests

from dotenv import load_dotenv

from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    flash,
    send_from_directory,
    Response,
)

from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

app = Flask(__name__)

# Railway / Cloudflare terminate HTTPS in front of Flask.
# ProxyFix lets Flask correctly understand the original public scheme/host.
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
)

APP_BUILD = "2026-09-22-private-dashboard-v1"

app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "change-me"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
    ),
)

DB = os.getenv(
    "DB_PATH",
    "leads.db"
)

# Keep uploaded campaign files and downloaded WhatsApp media beside the DB.
# When Railway uses DB_PATH=/data/leads.db, these folders become persistent:
# /data/uploads and /data/media.
DB_DIR = os.path.dirname(os.path.abspath(DB))

UPLOAD_DIR = os.getenv(
    "UPLOAD_DIR",
    os.path.join(DB_DIR, "uploads")
)

MEDIA_DIR = os.getenv(
    "MEDIA_DIR",
    os.path.join(DB_DIR, "media")
)

os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(MEDIA_DIR, exist_ok=True)


# ============================================================
# WHATSAPP CONFIGURATION
# ============================================================

WA_TOKEN = os.getenv(
    "WHATSAPP_ACCESS_TOKEN",
    ""
)

WA_PHONE_ID = os.getenv(
    "WHATSAPP_PHONE_NUMBER_ID",
    ""
)

WA_VERIFY_TOKEN = os.getenv(
    "WHATSAPP_VERIFY_TOKEN",
    ""
)

WA_TEMPLATE_LANGUAGE = os.getenv(
    "WHATSAPP_TEMPLATE_LANGUAGE",
    "en_US"
)

# Meta App Secret is used to validate incoming webhook POST requests.
# Keep it in an environment variable. If it is not set, webhook POSTs
# still work, but signature validation is skipped.
META_APP_SECRET = os.getenv(
    "META_APP_SECRET",
    ""
)


# ============================================================
# PRIVATE DASHBOARD AUTHENTICATION
# ============================================================

DASHBOARD_USER = os.getenv(
    "DASHBOARD_USER",
    ""
)

DASHBOARD_PASSWORD = os.getenv(
    "DASHBOARD_PASSWORD",
    ""
)


def dashboard_auth_ok():

    auth = request.authorization

    if not auth:
        return False

    username = auth.username or ""
    password = auth.password or ""

    return (
        secrets.compare_digest(
            username,
            DASHBOARD_USER
        )
        and
        secrets.compare_digest(
            password,
            DASHBOARD_PASSWORD
        )
    )


@app.before_request
def protect_private_dashboard():
    """
    Protect the dashboard and every dashboard API route with HTTP Basic Auth.

    These routes intentionally remain public:
      - /webhook   Meta webhook verification + incoming events
      - /health    deployment health check
      - /privacy   public privacy page
      - /robots.txt search-engine exclusion instructions

    The WhatsApp webhook is separately protected by:
      1) WHATSAPP_VERIFY_TOKEN for Meta's GET verification request.
      2) META_APP_SECRET signature validation for POST events when configured.
    """

    public_paths = {
        "/webhook",
        "/health",
        "/privacy",
        "/robots.txt",
    }

    if request.path in public_paths:
        return None

    # Never accidentally expose the dashboard if credentials were forgotten.
    if not DASHBOARD_USER or not DASHBOARD_PASSWORD:
        return Response(
            "Private dashboard authentication is not configured.",
            status=503,
            content_type="text/plain; charset=utf-8",
        )

    if dashboard_auth_ok():
        return None

    return Response(
        "Authentication required.",
        status=401,
        headers={
            "WWW-Authenticate":
                'Basic realm="Dubai Realty Select Private Dashboard", charset="UTF-8"'
        },
        content_type="text/plain; charset=utf-8",
    )


@app.after_request
def add_security_headers(response):

    # Prevent search engines and link previews from indexing dashboard URLs.
    response.headers["X-Robots-Tag"] = (
        "noindex, nofollow, noarchive, nosnippet"
    )

    # Basic browser hardening.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"

    # Private pages should not be cached by browsers/proxies.
    if request.path not in {
        "/privacy",
        "/robots.txt",
    }:
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, max-age=0"
        )
        response.headers["Pragma"] = "no-cache"

    return response


# ============================================================
# CAMPAIGN STATE
# ============================================================

campaign_running = False
campaign_paused = False

campaign_lock = threading.Lock()


# ============================================================
# HELPERS
# ============================================================

def now():
    return datetime.utcnow().isoformat(
        timespec="seconds"
    )


def db():

    conn = sqlite3.connect(
        DB,
        timeout=30
    )

    conn.row_factory = sqlite3.Row

    return conn


def normalize_phone(value):

    if value is None:
        return ""

    s = str(value).strip()

    if s.endswith(".0"):
        s = s[:-2]

    for character in [
        " ",
        "-",
        "(",
        ")",
        ".",
    ]:
        s = s.replace(
            character,
            ""
        )

    if not s:
        return ""

    if s.startswith("00"):
        s = "+" + s[2:]

    elif s.startswith("+"):
        pass

    elif (
        s.startswith("0")
        and len(s) >= 9
    ):
        s = "+971" + s[1:]

    elif s.startswith("971"):
        s = "+" + s

    elif s.isdigit():
        s = "+" + s

    return s


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    conn = db()

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS contacts(

            id INTEGER PRIMARY KEY,

            phone TEXT UNIQUE NOT NULL,

            name TEXT,

            opt_in INTEGER DEFAULT 0,

            status TEXT DEFAULT 'new',

            last_message TEXT,

            ai_summary TEXT,

            ai_score INTEGER DEFAULT 0,

            budget TEXT,

            area TEXT,

            property_type TEXT,

            purpose TEXT,

            created_at TEXT,

            updated_at TEXT
        );


        CREATE TABLE IF NOT EXISTS messages(

            id INTEGER PRIMARY KEY,

            phone TEXT NOT NULL,

            direction TEXT NOT NULL,

            body TEXT,

            wa_message_id TEXT,

            created_at TEXT
        );


        CREATE TABLE IF NOT EXISTS settings(

            key TEXT PRIMARY KEY,

            value TEXT
        );


        CREATE TABLE IF NOT EXISTS deal_sends(

            id INTEGER PRIMARY KEY,

            phone TEXT NOT NULL,

            deal_hash TEXT NOT NULL,

            sent_at TEXT NOT NULL,

            UNIQUE(
                phone,
                deal_hash
            )
        );


        CREATE TABLE IF NOT EXISTS campaign_queue(

            id INTEGER PRIMARY KEY,

            phone TEXT NOT NULL,

            name TEXT,

            delay_seconds INTEGER DEFAULT 60,

            template_name TEXT,

            status TEXT DEFAULT 'pending',

            queued_at TEXT,

            sent_at TEXT,

            error TEXT,

            UNIQUE(
                phone,
                template_name
            )
        );

        CREATE TABLE IF NOT EXISTS campaign_history(
            id INTEGER PRIMARY KEY,
            phone TEXT NOT NULL,
            template_name TEXT NOT NULL,
            sent_at TEXT NOT NULL,
            UNIQUE(phone, template_name)
        );

        CREATE TABLE IF NOT EXISTS contact_history(
            phone TEXT PRIMARY KEY,
            opted_out INTEGER DEFAULT 0,
            updated_at TEXT
        );
        """
    )

    conn.commit()


    # ========================================================
    # CONTACT MIGRATION
    # ========================================================

    contact_columns = {
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(contacts)"
        ).fetchall()
    }


    if "unread_count" not in contact_columns:

        conn.execute(
            """
            ALTER TABLE contacts
            ADD COLUMN unread_count INTEGER DEFAULT 0
            """
        )


    if "last_reply_at" not in contact_columns:

        conn.execute(
            """
            ALTER TABLE contacts
            ADD COLUMN last_reply_at TEXT
            """
        )


    if "delay_seconds" not in contact_columns:

        conn.execute(
            """
            ALTER TABLE contacts
            ADD COLUMN delay_seconds INTEGER DEFAULT 60
            """
        )


    # ========================================================
    # MESSAGE MIGRATION
    # ========================================================

    message_columns = {
        row["name"]
        for row in conn.execute(
            "PRAGMA table_info(messages)"
        ).fetchall()
    }


    if "delivery_status" not in message_columns:

        conn.execute(
            """
            ALTER TABLE messages
            ADD COLUMN delivery_status TEXT
            """
        )


    if "status_error" not in message_columns:

        conn.execute(
            """
            ALTER TABLE messages
            ADD COLUMN status_error TEXT
            """
        )


    if "updated_at" not in message_columns:

        conn.execute(
            """
            ALTER TABLE messages
            ADD COLUMN updated_at TEXT
            """
        )

    for column_name, column_type in [
        ("media_type", "TEXT"),
        ("media_id", "TEXT"),
        ("media_path", "TEXT"),
        ("media_filename", "TEXT"),
        ("media_mime_type", "TEXT"),
        ("media_error", "TEXT"),
    ]:
        if column_name not in message_columns:
            conn.execute(
                f"ALTER TABLE messages ADD COLUMN {column_name} {column_type}"
            )


    defaults = {

        "deal_title":
            "",

        "deal_text":
            "",

        "deal_auto_send":
            "0",

        "intro_template":
            "dubai_property_interest"
    }


    for key, value in defaults.items():

        conn.execute(
            """
            INSERT OR IGNORE INTO settings(
                key,
                value
            )

            VALUES(
                ?,
                ?
            )
            """,
            (
                key,
                value
            )
        )


    # ========================================================
    # RECOVER ORPHANED CONVERSATIONS
    # ========================================================
    # Older versions replaced the contacts table during a new import.
    # The messages themselves were preserved, but those conversations
    # disappeared from the dashboard because the UI lists contacts.
    # Re-create any missing contact from message history so every saved
    # conversation becomes visible again after restart.
    orphan_phones = conn.execute(
        """
        SELECT DISTINCT m.phone
        FROM messages m
        LEFT JOIN contacts c ON c.phone = m.phone
        WHERE c.phone IS NULL
          AND m.phone IS NOT NULL
          AND TRIM(m.phone) != ''
        """
    ).fetchall()

    recovered_count = 0

    for orphan in orphan_phones:
        phone = orphan["phone"]

        latest = conn.execute(
            """
            SELECT body, direction, created_at
            FROM messages
            WHERE phone=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (phone,)
        ).fetchone()

        latest_in = conn.execute(
            """
            SELECT body, created_at
            FROM messages
            WHERE phone=? AND direction='in'
            ORDER BY id DESC
            LIMIT 1
            """,
            (phone,)
        ).fetchone()

        hist = conn.execute(
            "SELECT opted_out FROM contact_history WHERE phone=?",
            (phone,)
        ).fetchone()

        if latest_in:
            body_lower = (latest_in["body"] or "").strip().lower()
            has_no_word = bool(re.search(r"\bno\b", body_lower))
            opt_out_words = [
                "stop", "unsubscribe", "remove me", "not interested",
                "no updates", "don't message", "do not message"
            ]
            interested_words = [
                "yes", "yes, send me deals", "yes send me deals",
                "send me deals", "send deals", "interested",
                "send details", "send me details", "more details"
            ]

            if has_no_word or any(x in body_lower for x in opt_out_words):
                status = "opt_out"
                opt_in = 0
            elif any(x in body_lower for x in interested_words):
                status = "interested"
                opt_in = 1
            elif hist and hist["opted_out"]:
                # A later non-opt-out message reactivates someone who
                # previously said No / Not Interested.
                status = "interested"
                opt_in = 1
            else:
                status = "replied"
                opt_in = 0
        elif hist and hist["opted_out"]:
            status = "opt_out"
            opt_in = 0
        else:
            status = "new"
            opt_in = 0

        last_message = latest["body"] if latest else None
        last_reply_at = latest_in["created_at"] if latest_in else None
        created_at = latest["created_at"] if latest else now()

        conn.execute(
            """
            INSERT OR IGNORE INTO contacts(
                phone, name, opt_in, status, last_message,
                created_at, updated_at, unread_count, last_reply_at, delay_seconds
            )
            VALUES(?, '', ?, ?, ?, ?, ?, 0, ?, 60)
            """,
            (
                phone, opt_in, status, last_message,
                created_at, now(), last_reply_at
            )
        )
        recovered_count += 1

    conn.commit()
    conn.close()

    if recovered_count:
        print(f"RECOVERED CONVERSATIONS: {recovered_count} contact(s) restored from message history")


# ============================================================
# SETTINGS
# ============================================================

def get_setting(
    key,
    default=""
):

    conn = db()

    row = conn.execute(
        """
        SELECT value
        FROM settings
        WHERE key=?
        """,
        (
            key,
        )
    ).fetchone()

    conn.close()

    if row:
        return row["value"]

    return default


def set_setting(
    key,
    value
):

    conn = db()

    conn.execute(
        """
        INSERT INTO settings(
            key,
            value
        )

        VALUES(
            ?,
            ?
        )

        ON CONFLICT(key)

        DO UPDATE SET
            value=excluded.value
        """,
        (
            key,
            str(value)
        )
    )

    conn.commit()
    conn.close()


# ============================================================
# DISTRESS DEAL
# ============================================================

def current_deal():

    return {

        "title":
            get_setting(
                "deal_title",
                ""
            ),

        "text":
            get_setting(
                "deal_text",
                ""
            ),

        "auto_send":
            get_setting(
                "deal_auto_send",
                "0"
            ) == "1"
    }


def make_deal_hash(text):

    return hashlib.sha256(
        text
        .strip()
        .encode(
            "utf-8"
        )
    ).hexdigest()


def already_sent_current_deal(
    phone,
    text
):

    if not text.strip():
        return False

    phone = normalize_phone(
        phone
    )

    deal_hash = make_deal_hash(
        text
    )

    conn = db()

    row = conn.execute(
        """
        SELECT id
        FROM deal_sends
        WHERE
            phone=?
            AND deal_hash=?
        LIMIT 1
        """,
        (
            phone,
            deal_hash
        )
    ).fetchone()

    conn.close()

    return bool(row)


def mark_deal_sent(
    phone,
    text
):

    conn = db()

    conn.execute(
        """
        INSERT OR IGNORE INTO deal_sends(
            phone,
            deal_hash,
            sent_at
        )

        VALUES(
            ?,
            ?,
            ?
        )
        """,
        (
            normalize_phone(phone),
            make_deal_hash(text),
            now()
        )
    )

    conn.commit()
    conn.close()


# ============================================================
# CHECK CONTACT STATUS
# ============================================================

def get_contact_status(phone):

    phone = normalize_phone(
        phone
    )

    conn = db()

    row = conn.execute(
        """
        SELECT
            status,
            opt_in
        FROM contacts
        WHERE phone=?
        """,
        (
            phone,
        )
    ).fetchone()

    conn.close()

    return row


def contact_is_opted_out(phone):

    row = get_contact_status(
        phone
    )

    if not row:
        return False

    return row["status"] == "opt_out"


# ============================================================
# SAVE OUTGOING MESSAGE
# ============================================================

def save_outgoing_message(
    phone,
    body,
    result,
    delivery_status="accepted"
):

    message_id = ""

    if isinstance(
        result,
        dict
    ):

        messages = result.get(
            "messages",
            []
        )

        if messages:

            message_id = (
                messages[0]
                .get(
                    "id",
                    ""
                )
            )


    conn = db()

    conn.execute(
        """
        INSERT INTO messages(

            phone,
            direction,
            body,
            wa_message_id,
            delivery_status,
            created_at,
            updated_at

        )

        VALUES(
            ?,
            'out',
            ?,
            ?,
            ?,
            ?,
            ?
        )
        """,
        (
            phone,
            body,
            message_id,
            delivery_status,
            now(),
            now()
        )
    )

    conn.commit()
    conn.close()


# ============================================================
# WHATSAPP MEDIA DOWNLOAD
# ============================================================

def download_whatsapp_media(media_id, msg_type="file", filename_hint=""):
    """Download WhatsApp media and return metadata.

    Important: metadata (especially media_id) is returned even when the
    actual download fails, so the UI can retry the download later.
    """
    result = {
        "media_type": msg_type,
        "media_id": media_id or "",
        "media_path": None,
        "media_filename": secure_filename(filename_hint or "") or None,
        "media_mime_type": None,
        "media_error": None,
    }

    if not media_id:
        result["media_error"] = "Missing WhatsApp media ID."
        return result

    if not WA_TOKEN:
        result["media_error"] = "WHATSAPP_ACCESS_TOKEN is not configured."
        return result

    headers = {"Authorization": f"Bearer {WA_TOKEN}"}

    try:
        meta_response = requests.get(
            f"https://graph.facebook.com/v23.0/{media_id}",
            headers=headers,
            timeout=20
        )
        if not meta_response.ok:
            result["media_error"] = (
                f"Media metadata request failed: {meta_response.status_code} "
                f"{meta_response.text[:500]}"
            )
            print("MEDIA META ERROR:", result["media_error"])
            return result

        meta = meta_response.json()
        media_url = meta.get("url")
        mime_type = meta.get("mime_type") or "application/octet-stream"
        result["media_mime_type"] = mime_type

        if not media_url:
            result["media_error"] = "Meta returned no media URL."
            print("MEDIA META ERROR:", result["media_error"])
            return result

        media_response = requests.get(
            media_url,
            headers=headers,
            timeout=60
        )
        if not media_response.ok:
            result["media_error"] = (
                f"Media download failed: {media_response.status_code} "
                f"{media_response.text[:500]}"
            )
            print("MEDIA DOWNLOAD ERROR:", result["media_error"])
            return result

        safe_hint = secure_filename(filename_hint or "")
        if safe_hint:
            filename = safe_hint
        else:
            clean_mime = mime_type.split(";")[0].strip()
            extension = mimetypes.guess_extension(clean_mime) or ""
            if clean_mime == "audio/ogg":
                extension = ".ogg"
            elif clean_mime == "image/jpeg" and not extension:
                extension = ".jpg"
            filename = f"{media_id}_{msg_type}{extension}"

        base, ext = os.path.splitext(filename)
        filename = secure_filename(f"{base}_{media_id[-8:]}{ext}")
        path = os.path.join(MEDIA_DIR, filename)

        with open(path, "wb") as f:
            f.write(media_response.content)

        result.update({
            "media_path": filename,
            "media_filename": safe_hint or filename,
            "media_mime_type": mime_type,
            "media_error": None,
        })
        print("MEDIA SAVED:", media_id, path)
        return result

    except requests.RequestException as e:
        result["media_error"] = f"Media request exception: {e}"
        print("MEDIA DOWNLOAD EXCEPTION:", str(e))
        return result
    except OSError as e:
        result["media_error"] = f"Could not save media file: {e}"
        print("MEDIA SAVE EXCEPTION:", str(e))
        return result


# ============================================================
# SEND TEMPLATE
# ============================================================

def send_template(
    phone,
    template_name,
    language=None
):

    if (
        not WA_TOKEN
        or not WA_PHONE_ID
    ):

        return (
            False,
            "WhatsApp credentials are not configured."
        )


    phone = normalize_phone(
        phone
    )

    if not phone:

        return (
            False,
            "Invalid phone."
        )


    # --------------------------------------------------------
    # SAFETY CHECK
    # Do not send if buyer opted out
    # --------------------------------------------------------

    if contact_is_opted_out(
        phone
    ):

        return (
            False,
            "Contact has opted out."
        )


    if not language:
        language = WA_TEMPLATE_LANGUAGE


    url = (
        f"https://graph.facebook.com/"
        f"v23.0/"
        f"{WA_PHONE_ID}/messages"
    )


    payload = {

        "messaging_product":
            "whatsapp",

        "to":
            phone.lstrip("+"),

        "type":
            "template",

        "template": {

            "name":
                template_name,

            "language": {

                "code":
                    language
            }
        }
    }


    try:

        response = requests.post(

            url,

            headers={

                "Authorization":
                    f"Bearer {WA_TOKEN}",

                "Content-Type":
                    "application/json"
            },

            json=payload,

            timeout=20
        )

    except requests.RequestException as e:

        return (
            False,
            str(e)
        )


    print(
        "TEMPLATE SEND:",
        phone,
        response.status_code,
        response.text
    )


    if not response.ok:

        return (
            False,
            response.text
        )


    result = response.json()


    save_outgoing_message(

        phone,

        f"TEMPLATE: {template_name}",

        result
    )


    return (
        True,
        result
    )


# ============================================================
# SEND NORMAL TEXT
# ============================================================

def send_text_message(
    phone,
    message,
    allow_opted_out=False
):

    phone = normalize_phone(
        phone
    )

    message = (
        message
        or ""
    ).strip()


    if not phone:

        return (
            False,
            "Invalid phone."
        )


    if not message:

        return (
            False,
            "Message cannot be empty."
        )


    # --------------------------------------------------------
    # Prevent automatic/manual promotional messages
    # to opted-out contacts.
    # --------------------------------------------------------

    if (
        not allow_opted_out
        and contact_is_opted_out(
            phone
        )
    ):

        return (
            False,
            "Contact has opted out."
        )


    url = (
        f"https://graph.facebook.com/"
        f"v23.0/"
        f"{WA_PHONE_ID}/messages"
    )


    payload = {

        "messaging_product":
            "whatsapp",

        "recipient_type":
            "individual",

        "to":
            phone.lstrip("+"),

        "type":
            "text",

        "text": {

            "preview_url":
                False,

            "body":
                message
        }
    }


    try:

        response = requests.post(

            url,

            headers={

                "Authorization":
                    f"Bearer {WA_TOKEN}",

                "Content-Type":
                    "application/json"
            },

            json=payload,

            timeout=20
        )

    except requests.RequestException as e:

        return (
            False,
            str(e)
        )


    if not response.ok:

        return (
            False,
            response.text
        )


    result = response.json()


    save_outgoing_message(

        phone,

        message,

        result
    )


    return (
        True,
        result
    )


# ============================================================
# SEND CURRENT DISTRESS DEAL
# ============================================================

def send_current_deal(
    phone
):

    phone = normalize_phone(
        phone
    )


    # --------------------------------------------------------
    # Important:
    # Never send deal while contact is opted out.
    # --------------------------------------------------------

    if contact_is_opted_out(
        phone
    ):

        return (
            False,
            "Contact selected Not Interested / opted out."
        )


    deal = current_deal()

    text = (
        deal["text"]
        or ""
    ).strip()


    if not text:

        return (
            False,
            "No current distress deal saved."
        )


    if already_sent_current_deal(
        phone,
        text
    ):

        return (
            False,
            "This deal was already sent to this buyer."
        )


    ok, result = send_text_message(
        phone,
        text
    )


    if ok:

        mark_deal_sent(
            phone,
            text
        )


    return (
        ok,
        result
    )


# ============================================================
# CAMPAIGN WORKER
# ============================================================

def campaign_worker():

    global campaign_running
    global campaign_paused


    while True:


        with campaign_lock:

            if not campaign_running:
                break


        if campaign_paused:

            time.sleep(
                1
            )

            continue


        conn = db()


        row = conn.execute(
            """
            SELECT
                q.id,
                q.phone,
                q.name,
                q.delay_seconds,
                q.template_name,
                c.status,
                c.opt_in

            FROM campaign_queue q

            JOIN contacts c
              ON c.phone=q.phone

            WHERE q.status='pending'

            ORDER BY q.id ASC

            LIMIT 1
            """
        ).fetchone()


        conn.close()


        if not row:

            with campaign_lock:
                campaign_running = False

            break


        phone = row["phone"]

        delay_seconds = int(
            row["delay_seconds"]
            or 0
        )


        if delay_seconds < 0:
            delay_seconds = 0


        # ====================================================
        # WAIT BEFORE THIS CONTACT
        # ====================================================

        remaining = delay_seconds


        while remaining > 0:


            with campaign_lock:

                if not campaign_running:
                    return


            while campaign_paused:

                time.sleep(
                    1
                )


                with campaign_lock:

                    if not campaign_running:
                        return


            # -----------------------------------------------
            # During the delay, continuously check whether
            # buyer has opted out.
            # -----------------------------------------------

            if contact_is_opted_out(
                phone
            ):

                conn = db()

                conn.execute(
                    """
                    UPDATE campaign_queue

                    SET
                        status='skipped',
                        error='Contact opted out before send'

                    WHERE id=?
                    """,
                    (
                        row["id"],
                    )
                )

                conn.commit()
                conn.close()

                remaining = 0
                break


            time.sleep(
                1
            )

            remaining -= 1


        # ====================================================
        # FINAL CHECK IMMEDIATELY BEFORE SEND
        # ====================================================

        conn = db()


        current_contact = conn.execute(
            """
            SELECT
                status,
                opt_in

            FROM contacts

            WHERE phone=?
            """,
            (
                phone,
            )
        ).fetchone()


        conn.close()


        if not current_contact:

            conn = db()

            conn.execute(
                """
                UPDATE campaign_queue

                SET
                    status='skipped',
                    error='Contact no longer exists'

                WHERE id=?
                """,
                (
                    row["id"],
                )
            )

            conn.commit()
            conn.close()

            continue


        if current_contact["status"] == "opt_out":

            conn = db()

            conn.execute(
                """
                UPDATE campaign_queue

                SET
                    status='skipped',
                    error='Contact opted out'

                WHERE id=?
                """,
                (
                    row["id"],
                )
            )

            conn.commit()
            conn.close()

            continue


        # ====================================================
        # CHECK QUEUE ROW IS STILL PENDING
        #
        # This prevents a message from being sent if webhook
        # changed it to skipped while worker was waiting.
        # ====================================================

        conn = db()

        queue_row = conn.execute(
            """
            SELECT status
            FROM campaign_queue
            WHERE id=?
            """,
            (
                row["id"],
            )
        ).fetchone()

        conn.close()


        if (
            not queue_row
            or queue_row["status"] != "pending"
        ):

            continue


        # ====================================================
        # SEND APPROVED TEMPLATE
        # ====================================================

        ok, result = send_template(
            phone,
            row["template_name"]
        )


        conn = db()


        if ok:

            sent_time = now()

            conn.execute(
                """
                UPDATE campaign_queue

                SET
                    status='sent',
                    sent_at=?,
                    error=''

                WHERE id=?
                """,
                (
                    sent_time,
                    row["id"]
                )
            )

            conn.execute(
                """
                INSERT OR IGNORE INTO campaign_history(phone, template_name, sent_at)
                VALUES(?, ?, ?)
                """,
                (phone, row["template_name"], sent_time)
            )


        else:

            if contact_is_opted_out(
                phone
            ):

                conn.execute(
                    """
                    UPDATE campaign_queue

                    SET
                        status='skipped',
                        error='Contact opted out'

                    WHERE id=?
                    """,
                    (
                        row["id"],
                    )
                )

            else:

                conn.execute(
                    """
                    UPDATE campaign_queue

                    SET
                        status='failed',
                        error=?

                    WHERE id=?
                    """,
                    (
                        str(result),
                        row["id"]
                    )
                )


        conn.commit()
        conn.close()


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    conn = db()


    # ========================================================
    # HOME PAGE: SHOW ONLY INTERESTED CONTACTS
    # ========================================================

    contacts = conn.execute(
        """
        SELECT *

        FROM contacts

        WHERE status='interested'

        ORDER BY

            CASE

                WHEN unread_count > 0
                THEN 0

                ELSE 1

            END,

            last_reply_at DESC,

            updated_at DESC
        """
    ).fetchall()


    stats = {

        "total":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM contacts
                """
            ).fetchone()["n"],


        "optin":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM contacts
                WHERE opt_in=1
                """
            ).fetchone()["n"],


        "hot":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM contacts
                WHERE status='hot'
                """
            ).fetchone()["n"],


        "interested":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM contacts
                WHERE status IN(
                    'interested',
                    'replied'
                )
                """
            ).fetchone()["n"]
    }


    queue_stats = {

        "pending":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM campaign_queue
                WHERE status='pending'
                """
            ).fetchone()["n"],


        "sent":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM campaign_queue
                WHERE status='sent'
                """
            ).fetchone()["n"],


        "failed":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM campaign_queue
                WHERE status='failed'
                """
            ).fetchone()["n"],


        "skipped":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM campaign_queue
                WHERE status='skipped'
                """
            ).fetchone()["n"]
    }


    conn.close()


    return render_template(

        "index.html",

        contacts=contacts,

        stats=stats,

        queue_stats=queue_stats,

        deal=current_deal(),

        intro_template=get_setting(
            "intro_template",
            "dubai_property_interest"
        ),

        campaign_running=campaign_running,

        campaign_paused=campaign_paused,

        page_mode="interested"
    )


# ============================================================
# OTHER CONTACTS
# ============================================================

@app.route("/other-contacts")
def other_contacts():

    conn = db()


    contacts = conn.execute(
        """
        SELECT *

        FROM contacts

        WHERE status != 'interested'

        ORDER BY

            CASE

                WHEN unread_count > 0
                THEN 0

                WHEN status='replied'
                THEN 1

                WHEN status='new'
                THEN 2

                WHEN status='opt_out'
                THEN 3

                ELSE 4

            END,

            updated_at DESC
        """
    ).fetchall()


    stats = {

        "total":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM contacts
                """
            ).fetchone()["n"],


        "optin":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM contacts
                WHERE opt_in=1
                """
            ).fetchone()["n"],


        "hot":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM contacts
                WHERE status='hot'
                """
            ).fetchone()["n"],


        "interested":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM contacts
                WHERE status IN(
                    'interested',
                    'replied'
                )
                """
            ).fetchone()["n"]
    }


    queue_stats = {

        "pending":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM campaign_queue
                WHERE status='pending'
                """
            ).fetchone()["n"],


        "sent":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM campaign_queue
                WHERE status='sent'
                """
            ).fetchone()["n"],


        "failed":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM campaign_queue
                WHERE status='failed'
                """
            ).fetchone()["n"],


        "skipped":

            conn.execute(
                """
                SELECT COUNT(*) n
                FROM campaign_queue
                WHERE status='skipped'
                """
            ).fetchone()["n"]
    }


    conn.close()


    return render_template(

        "index.html",

        contacts=contacts,

        stats=stats,

        queue_stats=queue_stats,

        deal=current_deal(),

        intro_template=get_setting(
            "intro_template",
            "dubai_property_interest"
        ),

        campaign_running=campaign_running,

        campaign_paused=campaign_paused,

        page_mode="other"
    )


# ============================================================
# IMPORT EXCEL / CSV
# ============================================================

@app.post("/upload")
def upload():

    file = request.files.get("file")

    if not file:
        flash("No file selected.")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    path = os.path.join(UPLOAD_DIR, filename)
    file.save(path)

    try:
        if path.lower().endswith((".xlsx", ".xls")):
            df = pd.read_excel(path)
        else:
            df = pd.read_csv(path)
    except Exception as e:
        flash(f"Could not read file: {e}")
        return redirect(url_for("index"))

    if df.empty:
        flash("File is empty.")
        return redirect(url_for("index"))

    columns = {str(c).lower().strip(): c for c in df.columns}
    phone_col = (columns.get("phone") or columns.get("mobile") or columns.get("whatsapp")
                 or columns.get("phone number") or list(df.columns)[0])
    name_col = columns.get("name") or columns.get("customer name") or columns.get("client name")
    delay_col = (columns.get("delayseconds") or columns.get("delay seconds")
                 or columns.get("delay") or columns.get("seconds"))
    template_name = get_setting("intro_template", "dubai_property_interest")

    conn = db()

    # A new import replaces ONLY the current campaign queue.
    # Existing contacts are kept so all previous conversations remain visible.
    # Messages, campaign history, deal history and opt-out history are preserved.
    conn.execute("DELETE FROM campaign_queue")

    imported = 0
    queued = 0
    skipped_previous = 0
    skipped_optout = 0

    for _, row in df.iterrows():
        phone = normalize_phone(row.get(phone_col, ""))
        if not phone:
            continue

        name = ""
        if name_col is not None:
            raw_name = row.get(name_col, "")
            if pd.notna(raw_name):
                name = str(raw_name).strip()

        delay_seconds = 60
        if delay_col is not None:
            try:
                raw_delay = row.get(delay_col, 60)
                if pd.notna(raw_delay):
                    delay_seconds = int(float(raw_delay))
            except Exception:
                delay_seconds = 60
        delay_seconds = max(0, delay_seconds)

        hist = conn.execute(
            "SELECT opted_out FROM contact_history WHERE phone=?",
            (phone,)
        ).fetchone()
        previously_sent = conn.execute(
            "SELECT 1 FROM campaign_history WHERE phone=? AND template_name=? LIMIT 1",
            (phone, template_name)
        ).fetchone()

        existing = conn.execute(
            "SELECT name, opt_in, status FROM contacts WHERE phone=?",
            (phone,)
        ).fetchone()

        if hist and hist["opted_out"]:
            status = "opt_out"
            opt_in = 0
        elif existing:
            # Preserve the recipient's existing conversation status and opt-in state.
            status = existing["status"] or "new"
            opt_in = existing["opt_in"] or 0
        else:
            status = "new"
            opt_in = 0

        if existing:
            # Keep the old contact/conversation row and only refresh import fields.
            # Do not blank an existing name when the new spreadsheet has no name.
            effective_name = name or (existing["name"] or "")
            conn.execute(
                """
                UPDATE contacts
                SET name=?, opt_in=?, status=?, delay_seconds=?, updated_at=?
                WHERE phone=?
                """,
                (effective_name, opt_in, status, delay_seconds, now(), phone)
            )
        else:
            conn.execute(
                """
                INSERT INTO contacts(phone, name, opt_in, status, delay_seconds, created_at, updated_at)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (phone, name, opt_in, status, delay_seconds, now(), now())
            )

        imported += 1

        if status == "opt_out":
            skipped_optout += 1
            continue

        if previously_sent:
            skipped_previous += 1
            continue

        conn.execute(
            """
            INSERT INTO campaign_queue(phone, name, delay_seconds, template_name, status, queued_at)
            VALUES(?, ?, ?, ?, 'pending', ?)
            """,
            (phone, name, delay_seconds, template_name, now())
        )
        queued += 1

    conn.commit()
    conn.close()

    flash(
        f"New list loaded: {imported} contacts. Queued {queued}. "
        f"Skipped {skipped_previous} previously contacted and {skipped_optout} opted-out contacts. "
        "Previous conversations were kept."
    )
    return redirect(url_for("index"))


# ============================================================
# CAMPAIGN START
# ============================================================

@app.post("/start-campaign")
def start_campaign():

    global campaign_running
    global campaign_paused


    with campaign_lock:

        if campaign_running:

            return jsonify(
                {
                    "ok":
                        False,

                    "result":
                        "Campaign is already running."
                }
            )


        campaign_running = True
        campaign_paused = False


    thread = threading.Thread(
        target=campaign_worker,
        daemon=True
    )


    thread.start()


    return jsonify(
        {
            "ok":
                True
        }
    )


# ============================================================
# CAMPAIGN PAUSE
# ============================================================

@app.post("/pause-campaign")
def pause_campaign():

    global campaign_paused

    campaign_paused = True

    return jsonify(
        {
            "ok":
                True
        }
    )


# ============================================================
# CAMPAIGN RESUME
# ============================================================

@app.post("/resume-campaign")
def resume_campaign():

    global campaign_paused

    campaign_paused = False

    return jsonify(
        {
            "ok":
                True
        }
    )


# ============================================================
# CAMPAIGN STOP
# ============================================================

@app.post("/stop-campaign")
def stop_campaign():

    global campaign_running
    global campaign_paused


    with campaign_lock:

        campaign_running = False
        campaign_paused = False


    return jsonify(
        {
            "ok":
                True
        }
    )


# ============================================================
# CAMPAIGN STATUS
# ============================================================

@app.get("/campaign-status")
def campaign_status():

    conn = db()


    pending = conn.execute(
        """
        SELECT COUNT(*) n
        FROM campaign_queue
        WHERE status='pending'
        """
    ).fetchone()["n"]


    sent = conn.execute(
        """
        SELECT COUNT(*) n
        FROM campaign_queue
        WHERE status='sent'
        """
    ).fetchone()["n"]


    failed = conn.execute(
        """
        SELECT COUNT(*) n
        FROM campaign_queue
        WHERE status='failed'
        """
    ).fetchone()["n"]


    skipped = conn.execute(
        """
        SELECT COUNT(*) n
        FROM campaign_queue
        WHERE status='skipped'
        """
    ).fetchone()["n"]


    next_contact = conn.execute(
        """
        SELECT
            q.phone,
            q.name,
            q.delay_seconds

        FROM campaign_queue q

        JOIN contacts c
          ON c.phone=q.phone

        WHERE
            q.status='pending'
            AND c.status != 'opt_out'

        ORDER BY q.id ASC

        LIMIT 1
        """
    ).fetchone()


    conn.close()


    return jsonify(
        {
            "ok":
                True,

            "running":
                campaign_running,

            "paused":
                campaign_paused,

            "pending":
                pending,

            "sent":
                sent,

            "failed":
                failed,

            "skipped":
                skipped,

            "next_contact":

                dict(next_contact)

                if next_contact

                else None
        }
    )


# ============================================================
# RESET CAMPAIGN QUEUE
# ============================================================

@app.post("/reset-campaign")
def reset_campaign():

    global campaign_running
    global campaign_paused


    campaign_running = False
    campaign_paused = False


    conn = db()

    conn.execute(
        """
        DELETE FROM campaign_queue
        """
    )

    conn.commit()
    conn.close()


    return jsonify(
        {
            "ok":
                True
        }
    )


# ============================================================
# SAVE DEAL
# ============================================================

@app.post("/save-deal")
def save_deal():

    set_setting(
        "deal_title",
        request.form.get(
            "deal_title",
            ""
        ).strip()
    )


    set_setting(
        "deal_text",
        request.form.get(
            "deal_text",
            ""
        ).strip()
    )


    auto_send = (

        "1"

        if request.form.get(
            "deal_auto_send"
        ) == "on"

        else "0"
    )


    set_setting(
        "deal_auto_send",
        auto_send
    )


    flash(
        "Current distress deal saved."
    )


    return redirect(
        url_for(
            "index"
        )
    )


# ============================================================
# SAVE TEMPLATE
# ============================================================

@app.post("/save-template")
def save_template():

    template_name = request.form.get(
        "template_name",
        ""
    ).strip()


    if template_name:

        set_setting(
            "intro_template",
            template_name
        )


    flash(
        "Template name saved."
    )


    return redirect(
        url_for(
            "index"
        )
    )


# ============================================================
# SEND TEST TEMPLATE
# ============================================================

@app.post("/send-test")
def send_test():

    phone = normalize_phone(
        request.form.get(
            "phone",
            ""
        )
    )


    template_name = request.form.get(
        "template_name",
        ""
    ).strip()


    ok, result = send_template(
        phone,
        template_name
    )


    return jsonify(
        {
            "ok":
                ok,

            "result":
                result
        }
    )


# ============================================================
# SEND DEAL
# ============================================================

@app.post("/send-deal")
def send_deal():

    phone = normalize_phone(
        request.form.get(
            "phone",
            ""
        )
    )


    ok, result = send_current_deal(
        phone
    )


    return jsonify(
        {
            "ok":
                ok,

            "result":
                result
        }
    )


# ============================================================
# MANUAL REPLY
# ============================================================

@app.post("/reply")
def reply():

    phone = normalize_phone(
        request.form.get(
            "phone",
            ""
        )
    )


    message = request.form.get(
        "message",
        ""
    ).strip()


    ok, result = send_text_message(
        phone,
        message
    )


    return jsonify(
        {
            "ok":
                ok,

            "result":
                result
        }
    )


# ============================================================
# DELETE CONTACT
# ============================================================

@app.post("/delete-contact")
def delete_contact():

    phone = normalize_phone(request.form.get("phone", ""))
    if not phone:
        return jsonify({"ok": False, "result": "Phone required."}), 400

    conn = db()
    conn.execute("DELETE FROM campaign_queue WHERE phone=?", (phone,))
    conn.execute("DELETE FROM contacts WHERE phone=?", (phone,))
    conn.commit()
    conn.close()

    # Intentionally keep messages, deal_sends, campaign_history and contact_history.
    return jsonify({"ok": True})


@app.post("/delete-all-contacts")
def delete_all_contacts():
    conn = db()
    conn.execute("DELETE FROM campaign_queue")
    conn.execute("DELETE FROM contacts")
    conn.commit()
    conn.close()

    # Intentionally keep all previous conversations and history.
    return jsonify({"ok": True})


# ============================================================
# NOTIFICATIONS
# ============================================================

@app.get("/notifications")
def notifications():

    conn = db()


    rows = conn.execute(
        """
        SELECT

            phone,
            name,
            status,
            unread_count,
            last_message,
            last_reply_at

        FROM contacts

        WHERE unread_count > 0

        ORDER BY last_reply_at DESC
        """
    ).fetchall()


    total = conn.execute(
        """
        SELECT
            COALESCE(
                SUM(unread_count),
                0
            ) total

        FROM contacts
        """
    ).fetchone()["total"]


    conn.close()


    return jsonify(
        {
            "ok":
                True,

            "total_unread":
                total,

            "contacts":
                [
                    dict(row)
                    for row
                    in rows
                ]
        }
    )


# ============================================================
# MARK READ
# ============================================================

@app.post("/mark-read")
def mark_read():

    phone = normalize_phone(
        request.form.get(
            "phone",
            ""
        )
    )


    conn = db()


    conn.execute(
        """
        UPDATE contacts
        SET unread_count=0
        WHERE phone=?
        """,
        (
            phone,
        )
    )


    conn.commit()
    conn.close()


    return jsonify(
        {
            "ok":
                True
        }
    )


# ============================================================
# WEBHOOK VERIFY
# ============================================================

@app.get("/webhook")
def verify_webhook():

    mode = request.args.get(
        "hub.mode"
    )

    token = request.args.get(
        "hub.verify_token"
    )

    challenge = request.args.get(
        "hub.challenge"
    )


    if (
        mode == "subscribe"
        and token == WA_VERIFY_TOKEN
    ):

        return (
            challenge,
            200
        )


    return (
        "Forbidden",
        403
    )


# ============================================================
# WHATSAPP WEBHOOK
# ============================================================

@app.post("/webhook")
def webhook():

    # --------------------------------------------------------
    # VERIFY META WEBHOOK SIGNATURE
    # --------------------------------------------------------
    # Meta signs webhook requests as:
    # X-Hub-Signature-256: sha256=<hex digest>
    #
    # Configure META_APP_SECRET in production so fake webhook
    # POSTs cannot alter contact/campaign state.
    # --------------------------------------------------------

    if META_APP_SECRET:

        supplied_signature = request.headers.get(
            "X-Hub-Signature-256",
            ""
        )

        raw_body = request.get_data(
            cache=True
        )

        expected_signature = (
            "sha256="
            + hmac.new(
                META_APP_SECRET.encode("utf-8"),
                raw_body,
                hashlib.sha256
            ).hexdigest()
        )

        if (
            not supplied_signature
            or not hmac.compare_digest(
                supplied_signature,
                expected_signature
            )
        ):
            return (
                "Forbidden",
                403
            )


    data = request.get_json(
        silent=True
    ) or {}


    try:

        for entry in data.get(
            "entry",
            []
        ):


            for change in entry.get(
                "changes",
                []
            ):


                value = change.get(
                    "value",
                    {}
                )


                # ====================================================
                # DELIVERY STATUS
                # ====================================================

                for status in value.get(
                    "statuses",
                    []
                ):


                    message_id = status.get(
                        "id",
                        ""
                    )


                    recipient = normalize_phone(
                        status.get(
                            "recipient_id",
                            ""
                        )
                    )


                    message_status = status.get(
                        "status",
                        ""
                    )


                    errors = status.get(
                        "errors",
                        []
                    )


                    error_text = (

                        json.dumps(
                            errors
                        )

                        if errors

                        else ""
                    )


                    conn = db()


                    row = conn.execute(
                        """
                        SELECT id
                        FROM messages
                        WHERE wa_message_id=?
                        """,
                        (
                            message_id,
                        )
                    ).fetchone()


                    if row:

                        conn.execute(
                            """
                            UPDATE messages

                            SET
                                delivery_status=?,
                                status_error=?,
                                updated_at=?

                            WHERE wa_message_id=?
                            """,
                            (
                                message_status,
                                error_text,
                                now(),
                                message_id
                            )
                        )


                    else:

                        conn.execute(
                            """
                            INSERT INTO messages(

                                phone,
                                direction,
                                body,
                                wa_message_id,
                                delivery_status,
                                status_error,
                                created_at,
                                updated_at
                            )

                            VALUES(
                                ?,
                                'out',
                                '',
                                ?,
                                ?,
                                ?,
                                ?,
                                ?
                            )
                            """,
                            (
                                recipient,
                                message_id,
                                message_status,
                                error_text,
                                now(),
                                now()
                            )
                        )


                    conn.commit()
                    conn.close()


                # ====================================================
                # INCOMING REPLY
                # ====================================================

                for msg in value.get(
                    "messages",
                    []
                ):


                    phone = normalize_phone(
                        msg.get(
                            "from",
                            ""
                        )
                    )


                    if not phone:
                        continue


                    msg_type = msg.get(
                        "type",
                        ""
                    )


                    body = ""
                    media = None

                    if msg_type == "text":
                        body = msg.get("text", {}).get("body", "")

                    elif msg_type == "button":
                        body = msg.get("button", {}).get("text", "")

                    elif msg_type == "interactive":
                        interactive = msg.get("interactive", {})
                        if interactive.get("type") == "button_reply":
                            body = interactive.get("button_reply", {}).get("title", "")
                        elif interactive.get("type") == "list_reply":
                            body = interactive.get("list_reply", {}).get("title", "")

                    elif msg_type in ("image", "video", "audio", "document", "sticker"):
                        media_obj = msg.get(msg_type, {}) or {}
                        media_id = str(media_obj.get("id", "") or "").strip()
                        filename_hint = media_obj.get("filename", "") if msg_type == "document" else ""
                        caption = media_obj.get("caption", "")
                        mime_hint = media_obj.get("mime_type", "") or None
                        body = caption.strip() if caption else f"[{msg_type} message]"

                        print(
                            "INCOMING MEDIA:",
                            "type=", msg_type,
                            "media_id=", media_id or "<missing>",
                            "wa_message_id=", msg.get("id", "")
                        )

                        # Always preserve the Media ID in the database, even if the
                        # immediate download from Meta fails. The UI can retry later.
                        media = {
                            "media_type": msg_type,
                            "media_id": media_id,
                            "media_path": None,
                            "media_filename": secure_filename(filename_hint or "") or None,
                            "media_mime_type": mime_hint,
                            "media_error": None if media_id else "Webhook did not contain a WhatsApp Media ID.",
                        }

                        if media_id:
                            downloaded = download_whatsapp_media(
                                media_id,
                                msg_type=msg_type,
                                filename_hint=filename_hint
                            )
                            if downloaded:
                                # download_whatsapp_media() also keeps media_id when
                                # Meta rejects or expires the media URL.
                                media.update(downloaded)

                    else:
                        body = f"[{msg_type} message]"


                    # WhatsApp may provide the sender's profile/display name
                    # in value.contacts[].profile.name. Keep it on the contact
                    # so the dashboard can display a name even when the original
                    # spreadsheet contact row was removed earlier.
                    profile_name = ""
                    try:
                        for wa_contact in value.get("contacts", []) or []:
                            wa_id = normalize_phone(wa_contact.get("wa_id", ""))
                            if not wa_id or wa_id == phone:
                                profile_name = str(
                                    ((wa_contact.get("profile") or {}).get("name")) or ""
                                ).strip()
                                if profile_name:
                                    break
                    except Exception:
                        profile_name = ""

                    lower_body = (
                        body
                        .lower()
                        .strip()
                    )


                    # =================================================
                    # RESPONSE CLASSIFICATION
                    # =================================================

                    opt_out_words = [

                        "stop",
                        "unsubscribe",
                        "remove me",
                        "not interested",
                        "no updates",
                        "don't message",
                        "do not message"
                    ]


                    interested_words = [

                        "yes",
                        "yes, send me deals",
                        "yes send me deals",
                        "send me deals",
                        "send deals",
                        "interested",
                        "send details",
                        "send me details",
                        "more details"
                    ]


                    # -------------------------------------------------
                    # CRITICAL FIX:
                    #
                    # "not interested" contains "interested".
                    #
                    # Therefore opt-out MUST be evaluated first and
                    # interest is only allowed when opt-out is false.
                    # -------------------------------------------------

                    # Treat an actual standalone word "no" as
                    # Not Interested too. Using a word boundary avoids
                    # false matches inside words such as "know".
                    has_no_word = bool(
                        re.search(
                            r"\bno\b",
                            lower_body
                        )
                    )


                    is_opt_out = (

                        has_no_word

                        or any(

                            phrase in lower_body

                            for phrase
                            in opt_out_words
                        )
                    )


                    is_interested = (

                        not is_opt_out

                        and any(

                            phrase in lower_body

                            for phrase
                            in interested_words
                        )
                    )


                    # =================================================
                    # SAVE CONTACT / MESSAGE
                    # =================================================

                    conn = db()


                    conn.execute(
                        """
                        INSERT INTO contacts(

                            phone,
                            name,
                            created_at,
                            updated_at,
                            unread_count,
                            last_reply_at
                        )

                        VALUES(
                            ?,
                            ?,
                            ?,
                            ?,
                            1,
                            ?
                        )

                        ON CONFLICT(phone)

                        DO UPDATE SET

                            name=CASE
                                WHEN TRIM(COALESCE(excluded.name, '')) != ''
                                THEN excluded.name
                                ELSE contacts.name
                            END,

                            updated_at=
                                excluded.updated_at,

                            last_reply_at=
                                excluded.last_reply_at,

                            unread_count=
                                contacts.unread_count + 1
                        """,
                        (
                            phone,
                            profile_name,
                            now(),
                            now(),
                            now()
                        )
                    )


                    conn.execute(
                        """
                        INSERT INTO messages(
                            phone, direction, body, wa_message_id, delivery_status,
                            media_type, media_id, media_path, media_filename, media_mime_type, media_error,
                            created_at, updated_at
                        )
                        VALUES(?, 'in', ?, ?, 'received', ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            phone,
                            body,
                            msg.get("id", ""),
                            media.get("media_type") if media else None,
                            media.get("media_id") if media else None,
                            media.get("media_path") if media else None,
                            media.get("media_filename") if media else None,
                            media.get("media_mime_type") if media else None,
                            media.get("media_error") if media else None,
                            now(),
                            now()
                        )
                    )


                    # =================================================
                    # NOT INTERESTED / STOP
                    # =================================================

                    if is_opt_out:

                        new_status = "opt_out"
                        new_optin = 0


                        # ---------------------------------------------
                        # Immediately disable all pending campaign
                        # items for this buyer.
                        # ---------------------------------------------

                        conn.execute(
                            """
                            UPDATE campaign_queue

                            SET
                                status='skipped',
                                error='Contact selected Not Interested'

                            WHERE
                                phone=?
                                AND status='pending'
                            """,
                            (
                                phone,
                            )
                        )


                    # =================================================
                    # YES / INTERESTED
                    #
                    # This also REACTIVATES someone who previously
                    # clicked Not Interested.
                    # =================================================

                    elif is_interested:

                        new_status = "interested"
                        new_optin = 1


                    # =================================================
                    # OTHER REPLY
                    # =================================================

                    else:

                        old = conn.execute(
                            """
                            SELECT
                                status,
                                opt_in

                            FROM contacts

                            WHERE phone=?
                            """,
                            (
                                phone,
                            )
                        ).fetchone()


                        # ---------------------------------------------
                        # If this buyer previously said No / Not
                        # Interested, ANY later incoming message that
                        # is not another No immediately reactivates them
                        # as Interested. This includes text, image,
                        # document, audio, video, etc.
                        # ---------------------------------------------

                        if (
                            old
                            and old["status"] == "opt_out"
                        ):

                            new_status = "interested"
                            new_optin = 1

                        # Keep an already-interested buyer interested
                        # when they continue the conversation.
                        elif (
                            old
                            and old["status"] == "interested"
                        ):

                            new_status = "interested"
                            new_optin = 1

                        else:

                            new_status = "replied"

                            new_optin = (
                                old["opt_in"]
                                if old
                                else 0
                            )


                    conn.execute(
                        """
                        INSERT INTO contact_history(phone, opted_out, updated_at)
                        VALUES(?, ?, ?)
                        ON CONFLICT(phone) DO UPDATE SET
                            opted_out=excluded.opted_out,
                            updated_at=excluded.updated_at
                        """,
                        (phone, 1 if new_status == "opt_out" else 0, now())
                    )


                    conn.execute(
                        """
                        UPDATE contacts

                        SET
                            status=?,
                            opt_in=?,
                            last_message=?,
                            updated_at=?,
                            last_reply_at=?

                        WHERE phone=?
                        """,
                        (
                            new_status,
                            new_optin,
                            body,
                            now(),
                            now(),
                            phone
                        )
                    )


                    conn.commit()
                    conn.close()


                    # =================================================
                    # AUTO SEND CURRENT DISTRESS DEAL
                    #
                    # Only explicit positive replies reach here.
                    #
                    # "Not Interested" can NEVER trigger this.
                    # =================================================

                    if (
                        is_interested
                        and not is_opt_out
                    ):

                        # ---------------------------------------------
                        # Confirm status again from DB before sending.
                        # ---------------------------------------------

                        latest = get_contact_status(
                            phone
                        )


                        if (
                            latest
                            and latest["status"] == "interested"
                            and latest["opt_in"] == 1
                        ):

                            deal = current_deal()


                            if (
                                deal["auto_send"]
                                and deal["text"].strip()
                            ):

                                if not already_sent_current_deal(
                                    phone,
                                    deal["text"]
                                ):

                                    send_current_deal(
                                        phone
                                    )


        return (
            "OK",
            200
        )


    except Exception as e:

        print(
            "WEBHOOK ERROR:",
            str(e)
        )


        return jsonify(
            {
                "error":
                    str(e)
            }
        ), 500


# ============================================================
# SERVE DOWNLOADED WHATSAPP MEDIA
# ============================================================

@app.get("/media/<path:filename>")
def serve_media(filename):
    return send_from_directory(MEDIA_DIR, filename)


@app.get("/message-media/<int:message_id>")
def serve_message_media(message_id):
    """Serve media for a message, retrying the Meta download if necessary."""
    conn = db()
    row = conn.execute(
        """
        SELECT id, media_type, media_id, media_path, media_filename, media_mime_type
        FROM messages
        WHERE id=?
        """,
        (message_id,)
    ).fetchone()

    if not row:
        conn.close()
        return "Message not found", 404

    media_path = row["media_path"]
    if media_path:
        full_path = os.path.join(MEDIA_DIR, media_path)
        if os.path.isfile(full_path):
            conn.close()
            return send_from_directory(MEDIA_DIR, media_path)

    media_id = row["media_id"]
    media_type = row["media_type"] or "file"
    filename_hint = row["media_filename"] or ""

    if not media_id:
        conn.close()
        return (
            "This older media message has no saved WhatsApp Media ID. "
            "Ask the sender to resend the image after installing the fixed version.",
            404
        )

    media = download_whatsapp_media(
        media_id,
        msg_type=media_type,
        filename_hint=filename_hint
    )

    if not media or not media.get("media_path"):
        error = (media or {}).get("media_error") or "Unable to download WhatsApp media."
        conn.execute(
            "UPDATE messages SET media_error=?, updated_at=? WHERE id=?",
            (error, now(), message_id)
        )
        conn.commit()
        conn.close()
        return f"Unable to open image: {error}", 502

    conn.execute(
        """
        UPDATE messages
        SET media_path=?, media_filename=?, media_mime_type=?, media_error=NULL, updated_at=?
        WHERE id=?
        """,
        (
            media.get("media_path"),
            media.get("media_filename"),
            media.get("media_mime_type"),
            now(),
            message_id
        )
    )
    conn.commit()
    conn.close()

    return send_from_directory(MEDIA_DIR, media["media_path"])


# ============================================================
# CONVERSATION
# ============================================================

@app.get(
    "/conversation/<phone>"
)
def conversation(
    phone
):

    phone = normalize_phone(
        phone
    )


    conn = db()


    rows = conn.execute(
        """
        SELECT

            id,
            direction,
            body,
            delivery_status,
            status_error,
            created_at,
            media_type,
            media_id,
            media_path,
            media_filename,
            media_mime_type,
            media_error

        FROM messages

        WHERE phone=?

        ORDER BY id ASC
        """,
        (
            phone,
        )
    ).fetchall()


    conn.close()


    return jsonify(
        [
            dict(row)
            for row
            in rows
        ]
    )


# ============================================================
# ROBOTS
# ============================================================

@app.get("/robots.txt")
def robots_txt():

    return Response(
        "User-agent: *\nDisallow: /\n",
        status=200,
        content_type="text/plain; charset=utf-8"
    )


# ============================================================
# PRIVACY
# ============================================================

@app.get("/privacy")
def privacy_policy():

    return """
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<title>
Privacy Policy | Dubai Realty Select
</title>

</head>

<body style="
font-family:Arial;
max-width:850px;
margin:40px auto;
line-height:1.7;
padding:20px;
">

<h1>
Privacy Policy
</h1>

<p>
Dubai Realty Select provides real estate information
and selected property opportunities in Dubai and the UAE.
</p>

<p>
Information supplied through WhatsApp may be used to respond
to enquiries and provide relevant property opportunities.
</p>

<p>
We do not sell personal information.
</p>

<p>
You may reply STOP or Not Interested at any time
to stop promotional communications.
</p>

<p>
<strong>Dubai Realty Select</strong><br>
Dubai, United Arab Emirates
</p>

</body>

</html>
"""


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return jsonify(
        {
            "ok":
                True,

            "campaign_running":
                campaign_running,

            "campaign_paused":
                campaign_paused,

            "whatsapp_token_configured":
                bool(WA_TOKEN),

            "phone_id_configured":
                bool(WA_PHONE_ID),

            "dashboard_auth_configured":
                bool(
                    DASHBOARD_USER
                    and DASHBOARD_PASSWORD
                ),

            "webhook_signature_check":
                bool(META_APP_SECRET),

            "build":
                APP_BUILD
        }
    )


# ============================================================
# APPLICATION INITIALIZATION
# ============================================================

# Railway normally starts this app with Gunicorn (gunicorn app:app).
# In that case __main__ is not executed, so initialize the database
# at import time.
init_db()

print("BUILD:", APP_BUILD)
print("RUNNING FILE:", os.path.abspath(__file__))

if not DASHBOARD_USER or not DASHBOARD_PASSWORD:
    print(
        "WARNING: DASHBOARD_USER / DASHBOARD_PASSWORD are not configured. "
        "Private dashboard routes will return HTTP 503."
    )

if not META_APP_SECRET:
    print(
        "WARNING: META_APP_SECRET is not configured. "
        "WhatsApp webhook POST signature validation is disabled."
    )


# ============================================================
# LOCAL DEVELOPMENT START
# ============================================================

if __name__ == "__main__":

    print("")
    print(
        "======================================"
    )

    print(
        "DUBAI REALTY SELECT"
    )

    print(
        "WHATSAPP LEAD DESK"
    )

    print(
        "======================================"
    )

    app.run(
        host="0.0.0.0",
        port=int(
            os.getenv(
                "PORT",
                "5000"
            )
        ),
        debug=(
            os.getenv(
                "FLASK_DEBUG",
                "0"
            ) == "1"
        )
    )
