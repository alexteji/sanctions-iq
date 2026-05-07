import hashlib
import json
import os
import sqlite3
import time
import threading
from datetime import datetime, timedelta

import feedparser
import requests as _requests

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "sanctions.db"))

NEWS_SOURCES = [
    "https://feeds.reuters.com/reuters/businessNews",
    "https://home.treasury.gov/policy-issues/financial-sanctions/recent-actions/feed",
    "https://www.consilium.europa.eu/en/policies/sanctions/rss/",
]

# ─── Core checker ─────────────────────────────────────────────────────────────

def check_entity(entry_id, name):
    """
    Check a monitored entity against news feeds and sanctions lists.
    Returns list of new hit dicts that weren't previously seen.
    """
    new_hits = []
    name_lower = name.lower()
    words = name_lower.split()

    # 1. Sanctions database match
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    like_clauses = " AND ".join(["(lower(name) LIKE ? OR lower(aliases) LIKE ?)"] * len(words))
    params = []
    for w in words:
        params += [f"%{w}%", f"%{w}%"]
    rows = con.execute(
        f"SELECT * FROM sanctions_entities WHERE {like_clauses}",
        params
    ).fetchall()
    con.close()

    for r in rows:
        h = hashlib.md5(f"sanctions:{entry_id}:{r['id']}".encode()).hexdigest()
        hit = {
            "monitoring_id": entry_id,
            "hit_type": "sanctions",
            "title": f"Sanctions match: {r['name']} ({r['list_name']})",
            "body": f"Listed under {r['program']} on {r['designation_date']}. Country: {r['country']}.",
            "source": r["list_name"],
            "url": "",
            "hash": h,
        }
        if _is_new_hit(h):
            new_hits.append(hit)

    # 2. News feed search
    for feed_url in NEWS_SOURCES:
        try:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries[:20]:
                title = entry.get("title", "")
                summary = entry.get("summary", entry.get("description", ""))[:600]
                url = entry.get("link", "")
                combined = (title + " " + summary).lower()
                if not all(w in combined for w in words):
                    continue
                h = hashlib.md5(f"news:{entry_id}:{url}:{title}".encode()).hexdigest()
                hit = {
                    "monitoring_id": entry_id,
                    "hit_type": "news",
                    "title": title,
                    "body": summary,
                    "source": feed.feed.get("title", feed_url),
                    "url": url,
                    "hash": h,
                }
                if _is_new_hit(h):
                    new_hits.append(hit)
        except Exception:
            pass

    return new_hits

def _is_new_hit(h):
    con = sqlite3.connect(DB_PATH)
    exists = con.execute("SELECT 1 FROM monitoring_hits WHERE hash=?", (h,)).fetchone()
    con.close()
    return not exists

def _save_hits(hits):
    if not hits:
        return
    con = sqlite3.connect(DB_PATH)
    for hit in hits:
        try:
            con.execute(
                """INSERT INTO monitoring_hits
                   (monitoring_id, hit_type, title, body, source, url, hash)
                   VALUES (?,?,?,?,?,?,?)""",
                (hit["monitoring_id"], hit["hit_type"], hit["title"],
                 hit["body"], hit["source"], hit["url"], hit["hash"])
            )
        except sqlite3.IntegrityError:
            pass
    con.commit()
    con.close()

def _mark_notified(monitoring_id):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "UPDATE monitoring_hits SET notified=1 WHERE monitoring_id=? AND notified=0",
        (monitoring_id,)
    )
    con.execute(
        "UPDATE monitoring_list SET last_checked=?, last_alert_sent=? WHERE id=?",
        (datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), monitoring_id)
    )
    con.commit()
    con.close()

def _mark_checked(monitoring_id):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "UPDATE monitoring_list SET last_checked=? WHERE id=?",
        (datetime.utcnow().isoformat(), monitoring_id)
    )
    con.commit()
    con.close()

# ─── Email ────────────────────────────────────────────────────────────────────

def _send_alert_email(to_email, user_name, entity_name, hits):
    api_key = os.getenv("RESEND_API_KEY", "")
    from_addr = os.getenv("RESEND_FROM", "bureauq <noreply@bureauq.app>")

    hits_html = ""
    for h in hits:
        badge_color = "#ef4444" if h["hit_type"] == "sanctions" else "#3b82f6"
        badge_label = "SANCTIONS MATCH" if h["hit_type"] == "sanctions" else "NEWS MENTION"
        link = f'<a href="{h["url"]}" style="color:#3b82f6">{h["url"]}</a>' if h["url"] else ""
        hits_html += f"""
        <div style="background:#1a1f2e;border-left:3px solid {badge_color};border-radius:6px;padding:14px 16px;margin-bottom:12px">
          <div style="font-size:10px;font-weight:700;letter-spacing:.8px;color:{badge_color};margin-bottom:6px">{badge_label}</div>
          <div style="font-size:14px;font-weight:600;color:#e2e8f0;margin-bottom:5px">{h['title']}</div>
          <div style="font-size:12px;color:#94a3b8;line-height:1.5;margin-bottom:5px">{h['body'][:300]}{'...' if len(h['body'] or '')>300 else ''}</div>
          <div style="font-size:11px;color:#64748b">Source: {h['source']}{' · ' + link if link else ''}</div>
        </div>"""

    html = f"""
    <div style="font-family:-apple-system,sans-serif;max-width:580px;margin:40px auto;background:#111520;border:1px solid #2a3050;border-radius:12px;overflow:hidden">
      <div style="background:linear-gradient(135deg,#3b82f6,#6366f1);padding:24px 28px">
        <div style="font-size:20px;font-weight:800;color:#fff;letter-spacing:-.5px">bureauq</div>
        <div style="font-size:13px;color:rgba(255,255,255,.7);margin-top:3px">Live Monitoring Alert</div>
      </div>
      <div style="padding:28px">
        <p style="font-size:15px;color:#e2e8f0;margin-bottom:6px">Hi {user_name.split()[0]},</p>
        <p style="font-size:13px;color:#94a3b8;margin-bottom:20px;line-height:1.6">
          We found <strong style="color:#e2e8f0">{len(hits)} new item{'s' if len(hits)!=1 else ''}</strong>
          related to your monitored entity <strong style="color:#e2e8f0">"{entity_name}"</strong>.
        </p>
        {hits_html}
        <a href="https://bureauq.com" style="display:inline-block;background:#3b82f6;color:#fff;padding:11px 22px;border-radius:7px;text-decoration:none;font-weight:600;font-size:13px;margin-top:8px">
          View in Dashboard &rarr;
        </a>
        <p style="font-size:11px;color:#64748b;margin-top:20px;line-height:1.5">
          You're receiving this because "{entity_name}" is on your Live Monitoring list.<br/>
          Manage your monitoring list at <a href="https://bureauq.com" style="color:#64748b">bureauq.com</a>.
        </p>
      </div>
    </div>"""

    if api_key:
        try:
            _requests.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "from": from_addr,
                    "to": [to_email],
                    "subject": f"bureauq alert: new activity on \"{entity_name}\"",
                    "html": html,
                },
                timeout=10,
            )
        except Exception as e:
            print(f"[monitoring] email error: {e}")
    else:
        print(f"\n{'='*60}")
        print(f"  MONITORING ALERT (no RESEND_API_KEY)")
        print(f"  To:     {to_email}")
        print(f"  Entity: {entity_name}")
        print(f"  Hits:   {len(hits)}")
        for h in hits:
            print(f"    [{h['hit_type'].upper()}] {h['title']}")
        print(f"{'='*60}\n")

# ─── Background runner ────────────────────────────────────────────────────────

def run_monitoring_cycle():
    """Check all active monitored entities and send email alerts for new hits."""
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    entries = con.execute(
        """SELECT ml.*, u.email, u.name as user_name
           FROM monitoring_list ml
           JOIN users u ON u.id = ml.user_id
           WHERE ml.active = 1"""
    ).fetchall()
    con.close()

    for entry in entries:
        try:
            new_hits = check_entity(entry["id"], entry["name"])
            _save_hits(new_hits)
            _mark_checked(entry["id"])
            if new_hits:
                _send_alert_email(
                    entry["email"],
                    entry["user_name"],
                    entry["name"],
                    new_hits,
                )
                _mark_notified(entry["id"])
        except Exception as e:
            print(f"[monitoring] error checking '{entry['name']}': {e}")

def start_monitoring_thread():
    def loop():
        while True:
            try:
                run_monitoring_cycle()
            except Exception as e:
                print(f"[monitoring] cycle error: {e}")
            time.sleep(1800)  # every 30 minutes
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t

# ─── Flask blueprint ──────────────────────────────────────────────────────────

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

monitoring_bp = Blueprint("monitoring", __name__)

@monitoring_bp.route("/api/monitoring", methods=["GET"])
@login_required
def get_monitoring_list():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM monitoring_list WHERE user_id=? AND active=1 ORDER BY created_at DESC",
        (current_user.id,)
    ).fetchall()
    result = []
    for r in rows:
        unread = con.execute(
            "SELECT COUNT(*) FROM monitoring_hits WHERE monitoring_id=? AND notified=0",
            (r["id"],)
        ).fetchone()[0]
        total = con.execute(
            "SELECT COUNT(*) FROM monitoring_hits WHERE monitoring_id=?",
            (r["id"],)
        ).fetchone()[0]
        result.append({**dict(r), "unread_hits": unread, "total_hits": total})
    con.close()
    return jsonify(result)

@monitoring_bp.route("/api/monitoring", methods=["POST"])
@login_required
def add_monitoring():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Name required"}), 400
    con = sqlite3.connect(DB_PATH)
    existing = con.execute(
        "SELECT id FROM monitoring_list WHERE user_id=? AND lower(name)=? AND active=1",
        (current_user.id, name.lower())
    ).fetchone()
    if existing:
        con.close()
        return jsonify({"error": "Already monitoring this entity"}), 409
    cur = con.execute(
        "INSERT INTO monitoring_list(user_id, name, entity_type, notes) VALUES(?,?,?,?)",
        (current_user.id, name, data.get("entity_type", "individual"), data.get("notes", ""))
    )
    con.commit()
    entry_id = cur.lastrowid
    con.close()
    # Run an immediate first check in a background thread
    threading.Thread(
        target=_immediate_check, args=(entry_id, name, current_user.email, current_user.name),
        daemon=True
    ).start()
    return jsonify({"id": entry_id, "name": name})

def _immediate_check(entry_id, name, email, user_name):
    try:
        hits = check_entity(entry_id, name)
        _save_hits(hits)
        _mark_checked(entry_id)
        if hits:
            _send_alert_email(email, user_name, name, hits)
            _mark_notified(entry_id)
    except Exception as e:
        print(f"[monitoring] immediate check error: {e}")

@monitoring_bp.route("/api/monitoring/<int:mid>", methods=["DELETE"])
@login_required
def remove_monitoring(mid):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "UPDATE monitoring_list SET active=0 WHERE id=? AND user_id=?",
        (mid, current_user.id)
    )
    con.commit()
    con.close()
    return jsonify({"ok": True})

@monitoring_bp.route("/api/monitoring/<int:mid>/hits", methods=["GET"])
@login_required
def get_hits(mid):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    # Verify ownership
    owner = con.execute(
        "SELECT id FROM monitoring_list WHERE id=? AND user_id=?",
        (mid, current_user.id)
    ).fetchone()
    if not owner:
        con.close()
        return jsonify({"error": "Not found"}), 404
    hits = con.execute(
        "SELECT * FROM monitoring_hits WHERE monitoring_id=? ORDER BY found_at DESC LIMIT 50",
        (mid,)
    ).fetchall()
    con.close()
    return jsonify([dict(h) for h in hits])

@monitoring_bp.route("/api/monitoring/<int:mid>/check", methods=["POST"])
@login_required
def manual_check(mid):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT * FROM monitoring_list WHERE id=? AND user_id=? AND active=1",
        (mid, current_user.id)
    ).fetchone()
    con.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    threading.Thread(
        target=_immediate_check,
        args=(mid, row["name"], current_user.email, current_user.name),
        daemon=True
    ).start()
    return jsonify({"ok": True, "message": f"Checking '{row['name']}'..."})
