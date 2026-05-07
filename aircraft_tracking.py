import hashlib
import json
import os
import sqlite3
import threading
import time
from datetime import datetime

import feedparser
import requests as _requests

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "sanctions.db"))

NEWS_SOURCES = [
    "https://feeds.reuters.com/reuters/businessNews",
    "https://home.treasury.gov/policy-issues/financial-sanctions/recent-actions/feed",
    "https://www.consilium.europa.eu/en/policies/sanctions/rss/",
]

OPENSKY_BASE = "https://opensky-network.org/api"

# ICAO airport prefix → sanctioned country
SANCTIONED_ICAO_PREFIXES = {
    "ok": "North Korea", "ep": "Iran", "os": "Syria",
    "ud": "Crimea / Ukraine (occupied)",
}

# ADS-B navigation status codes
NAV_STATUS = {
    0: "Under way", 1: "At anchor", 2: "Not under command",
    3: "Restricted manoeuvrability", 5: "Moored", 8: "Under way sailing",
}

# ─── OpenSky ADS-B lookup (free, no key) ─────────────────────────────────────

def get_aircraft_position(icao24):
    """Fetch live ADS-B state from OpenSky Network. Free, no API key needed."""
    if not icao24:
        return None
    try:
        resp = _requests.get(
            f"{OPENSKY_BASE}/states/all",
            params={"icao24": icao24.lower().strip()},
            timeout=10,
        )
        data = resp.json()
        states = data.get("states") or []
        if not states:
            return None
        s = states[0]
        # OpenSky state vector fields (indices 0-16)
        alt_m = s[7]
        alt_ft = round(alt_m * 3.28084) if alt_m else None
        speed_ms = s[9]
        speed_kts = round(speed_ms * 1.94384) if speed_ms else None
        return {
            "icao24": s[0],
            "callsign": (s[1] or "").strip(),
            "origin_country": s[2],
            "last_contact": s[4],
            "longitude": s[5],
            "latitude": s[6],
            "altitude_ft": alt_ft,
            "on_ground": s[8],
            "speed_kts": speed_kts,
            "heading": s[10],
            "vertical_rate": s[11],
            "squawk": s[14],
            "timestamp": datetime.utcnow().isoformat(),
            "source": "OpenSky Network",
        }
    except Exception:
        pass
    return None

def get_recent_flight(icao24):
    """Get the most recent flight for an aircraft from OpenSky (free)."""
    if not icao24:
        return None
    try:
        now = int(time.time())
        resp = _requests.get(
            f"{OPENSKY_BASE}/flights/aircraft",
            params={"icao24": icao24.lower().strip(), "begin": now - 86400, "end": now},
            timeout=10,
        )
        flights = resp.json()
        if flights and isinstance(flights, list):
            return flights[-1]
    except Exception:
        pass
    return None

# ─── Core checker ─────────────────────────────────────────────────────────────

def check_aircraft(aircraft_id, name, icao24=None, registration=None):
    new_hits = []
    name_lower = name.lower()
    words = [w for w in name_lower.split() if len(w) > 2]
    if not words:
        words = name_lower.split()

    # 1. Sanctions DB — name / registration match
    search_terms = list({name_lower, (registration or "").lower()})
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    for term in search_terms:
        if not term:
            continue
        rows = con.execute(
            "SELECT * FROM sanctions_entities WHERE lower(name) LIKE ? OR lower(aliases) LIKE ?",
            (f"%{term}%", f"%{term}%"),
        ).fetchall()
        for r in rows:
            h = hashlib.md5(f"as:{aircraft_id}:{r['id']}".encode()).hexdigest()
            hit = {
                "aircraft_id": aircraft_id, "hit_type": "sanctions",
                "title": f"Sanctions match: {r['name']} ({r['list_name']})",
                "body": f"Listed under {r['program']} on {r['designation_date']}. Country: {r['country']}.",
                "source": r["list_name"], "url": "", "hash": h,
            }
            if _is_new(h, "aircraft_hits"):
                new_hits.append(hit)
    con.close()

    # 2. ADS-B position via OpenSky (free)
    if icao24:
        pos = get_aircraft_position(icao24)
        if pos:
            _update_position("aircraft_monitoring", aircraft_id, pos)

        # Route check — sanctioned airports
        flight = get_recent_flight(icao24)
        if flight:
            for key, label in [("estDepartureAirport", "departed from"),
                                ("estArrivalAirport", "arrived at")]:
                airport = (flight.get(key) or "").strip()
                if not airport:
                    continue
                prefix = airport[:2].lower()
                if prefix in SANCTIONED_ICAO_PREFIXES:
                    country = SANCTIONED_ICAO_PREFIXES[prefix]
                    h = hashlib.md5(
                        f"aa:{aircraft_id}:{airport}:{datetime.utcnow().date()}".encode()
                    ).hexdigest()
                    hit = {
                        "aircraft_id": aircraft_id, "hit_type": "sanctioned_airport",
                        "title": f"Sanctioned jurisdiction flight: {airport}",
                        "body": (f"Aircraft {label} {airport} ({country}). "
                                 f"Callsign: {flight.get('callsign','—')}. "
                                 f"OpenSky data."),
                        "source": "ADS-B / OpenSky Network",
                        "url": f"https://opensky-network.org/aircraft-profile?icao24={icao24}",
                        "hash": h,
                    }
                    if _is_new(h, "aircraft_hits"):
                        new_hits.append(hit)

    # 3. News feed
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
                h = hashlib.md5(f"an:{aircraft_id}:{url}:{title}".encode()).hexdigest()
                hit = {
                    "aircraft_id": aircraft_id, "hit_type": "news",
                    "title": title, "body": summary,
                    "source": feed.feed.get("title", feed_url), "url": url, "hash": h,
                }
                if _is_new(h, "aircraft_hits"):
                    new_hits.append(hit)
        except Exception:
            pass

    return new_hits

# ─── DB helpers ───────────────────────────────────────────────────────────────

def _is_new(h, table):
    con = sqlite3.connect(DB_PATH)
    exists = con.execute(f"SELECT 1 FROM {table} WHERE hash=?", (h,)).fetchone()
    con.close()
    return not exists

def _update_position(table, row_id, pos):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        f"UPDATE {table} SET last_position=?, last_checked=? WHERE id=?",
        (json.dumps(pos), datetime.utcnow().isoformat(), row_id),
    )
    con.commit()
    con.close()

def _save_aircraft_hits(hits):
    if not hits:
        return
    con = sqlite3.connect(DB_PATH)
    for hit in hits:
        try:
            con.execute(
                """INSERT INTO aircraft_hits(aircraft_id,hit_type,title,body,source,url,hash)
                   VALUES(?,?,?,?,?,?,?)""",
                (hit["aircraft_id"], hit["hit_type"], hit["title"],
                 hit["body"], hit["source"], hit["url"], hit["hash"]),
            )
        except sqlite3.IntegrityError:
            pass
    con.commit()
    con.close()

def _mark_aircraft_checked(aircraft_id):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "UPDATE aircraft_monitoring SET last_checked=? WHERE id=?",
        (datetime.utcnow().isoformat(), aircraft_id),
    )
    con.commit()
    con.close()

# ─── Email alert ──────────────────────────────────────────────────────────────

def _send_aircraft_alert(to_email, user_name, aircraft_name, hits):
    api_key = os.getenv("RESEND_API_KEY", "")
    from_addr = os.getenv("RESEND_FROM", "bureauq <noreply@bureauq.app>")
    type_colors = {
        "sanctions": "#ef4444", "sanctioned_airport": "#f97316", "news": "#3b82f6",
    }
    type_labels = {
        "sanctions": "SANCTIONS MATCH", "sanctioned_airport": "SANCTIONED AIRPORT",
        "news": "NEWS MENTION",
    }
    hits_html = ""
    for h in hits:
        c = type_colors.get(h["hit_type"], "#3b82f6")
        lbl = type_labels.get(h["hit_type"], h["hit_type"].upper())
        link = f'<a href="{h["url"]}" style="color:#3b82f6">{h["url"]}</a>' if h.get("url") else ""
        body_preview = (h["body"] or "")[:300] + ("..." if len(h["body"] or "") > 300 else "")
        hits_html += f"""
        <div style="background:#1a1f2e;border-left:3px solid {c};border-radius:6px;padding:14px 16px;margin-bottom:12px">
          <div style="font-size:10px;font-weight:700;letter-spacing:.8px;color:{c};margin-bottom:6px">✈️ {lbl}</div>
          <div style="font-size:14px;font-weight:600;color:#e2e8f0;margin-bottom:5px">{h['title']}</div>
          <div style="font-size:12px;color:#94a3b8;line-height:1.5;margin-bottom:5px">{body_preview}</div>
          <div style="font-size:11px;color:#64748b">Source: {h['source']}{(' · ' + link) if link else ''}</div>
        </div>"""

    html = f"""<div style="font-family:-apple-system,sans-serif;max-width:580px;margin:40px auto;background:#111520;border:1px solid #2a3050;border-radius:12px;overflow:hidden">
      <div style="background:linear-gradient(135deg,#8b5cf6,#6366f1);padding:24px 28px">
        <div style="font-size:20px;font-weight:800;color:#fff">bureauq</div>
        <div style="font-size:13px;color:rgba(255,255,255,.7);margin-top:3px">✈️ Aircraft Monitoring Alert</div>
      </div>
      <div style="padding:28px">
        <p style="font-size:15px;color:#e2e8f0;margin-bottom:6px">Hi {user_name.split()[0]},</p>
        <p style="font-size:13px;color:#94a3b8;margin-bottom:20px;line-height:1.6">
          <strong style="color:#e2e8f0">{len(hits)} new item{'s' if len(hits)!=1 else ''}</strong>
          found for aircraft <strong style="color:#e2e8f0">"{aircraft_name}"</strong>.
        </p>
        {hits_html}
        <a href="https://bureauq.com" style="display:inline-block;background:#8b5cf6;color:#fff;padding:11px 22px;border-radius:7px;text-decoration:none;font-weight:600;font-size:13px;margin-top:8px">View in Dashboard →</a>
      </div>
    </div>"""

    if api_key:
        try:
            _requests.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"from": from_addr, "to": [to_email],
                      "subject": f"bureauq aircraft alert: \"{aircraft_name}\"", "html": html},
                timeout=10,
            )
        except Exception as e:
            print(f"[aircraft] email error: {e}")
    else:
        print(f"\n{'='*55}\n  AIRCRAFT ALERT — {aircraft_name}\n  Hits: {len(hits)}\n{'='*55}\n")

# ─── Background thread ────────────────────────────────────────────────────────

def run_aircraft_cycle():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    entries = con.execute(
        """SELECT am.*, u.email, u.name AS user_name
           FROM aircraft_monitoring am
           JOIN users u ON u.id = am.user_id
           WHERE am.active = 1"""
    ).fetchall()
    con.close()
    for entry in entries:
        try:
            hits = check_aircraft(entry["id"], entry["name"], entry["icao24"], entry["registration"])
            _save_aircraft_hits(hits)
            _mark_aircraft_checked(entry["id"])
            if hits:
                _send_aircraft_alert(entry["email"], entry["user_name"], entry["name"], hits)
        except Exception as e:
            print(f"[aircraft] error checking '{entry['name']}': {e}")

def start_aircraft_thread():
    def loop():
        while True:
            try:
                run_aircraft_cycle()
            except Exception as e:
                print(f"[aircraft] cycle error: {e}")
            time.sleep(1800)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t

# ─── Flask blueprint ──────────────────────────────────────────────────────────

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

aircraft_bp = Blueprint("aircraft", __name__)

@aircraft_bp.route("/api/aircraft", methods=["GET"])
@login_required
def get_aircraft_list():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM aircraft_monitoring WHERE user_id=? AND active=1 ORDER BY created_at DESC",
        (current_user.id,),
    ).fetchall()
    result = []
    for r in rows:
        unread = con.execute(
            "SELECT COUNT(*) FROM aircraft_hits WHERE aircraft_id=? AND notified=0", (r["id"],)
        ).fetchone()[0]
        total = con.execute(
            "SELECT COUNT(*) FROM aircraft_hits WHERE aircraft_id=?", (r["id"],)
        ).fetchone()[0]
        pos = json.loads(r["last_position"]) if r["last_position"] else None
        result.append({**dict(r), "unread_hits": unread, "total_hits": total, "position": pos})
    con.close()
    return jsonify(result)

@aircraft_bp.route("/api/aircraft", methods=["POST"])
@login_required
def add_aircraft():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Name required"}), 400
    con = sqlite3.connect(DB_PATH)
    if con.execute(
        "SELECT id FROM aircraft_monitoring WHERE user_id=? AND lower(name)=? AND active=1",
        (current_user.id, name.lower()),
    ).fetchone():
        con.close()
        return jsonify({"error": "Already monitoring this aircraft"}), 409
    cur = con.execute(
        "INSERT INTO aircraft_monitoring(user_id,name,registration,icao24,aircraft_type,notes) VALUES(?,?,?,?,?,?)",
        (current_user.id, name, data.get("registration", ""), data.get("icao24", ""),
         data.get("aircraft_type", "fixed-wing"), data.get("notes", "")),
    )
    con.commit()
    aid = cur.lastrowid
    con.close()
    threading.Thread(
        target=_immediate_aircraft_check,
        args=(aid, name, data.get("icao24", ""), data.get("registration", ""),
              current_user.email, current_user.name),
        daemon=True,
    ).start()
    return jsonify({"id": aid, "name": name})

def _immediate_aircraft_check(aid, name, icao24, registration, email, user_name):
    try:
        hits = check_aircraft(aid, name, icao24, registration)
        _save_aircraft_hits(hits)
        _mark_aircraft_checked(aid)
        if hits:
            _send_aircraft_alert(email, user_name, name, hits)
    except Exception as e:
        print(f"[aircraft] immediate check error: {e}")

@aircraft_bp.route("/api/aircraft/<int:aid>", methods=["DELETE"])
@login_required
def remove_aircraft(aid):
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE aircraft_monitoring SET active=0 WHERE id=? AND user_id=?", (aid, current_user.id))
    con.commit()
    con.close()
    return jsonify({"ok": True})

@aircraft_bp.route("/api/aircraft/<int:aid>/hits", methods=["GET"])
@login_required
def get_aircraft_hits(aid):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    if not con.execute(
        "SELECT id FROM aircraft_monitoring WHERE id=? AND user_id=?", (aid, current_user.id)
    ).fetchone():
        con.close()
        return jsonify({"error": "Not found"}), 404
    hits = con.execute(
        "SELECT * FROM aircraft_hits WHERE aircraft_id=? ORDER BY found_at DESC LIMIT 50", (aid,)
    ).fetchall()
    con.execute("UPDATE aircraft_hits SET notified=1 WHERE aircraft_id=? AND notified=0", (aid,))
    con.commit()
    con.close()
    return jsonify([dict(h) for h in hits])

@aircraft_bp.route("/api/aircraft/<int:aid>/check", methods=["POST"])
@login_required
def manual_aircraft_check(aid):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT * FROM aircraft_monitoring WHERE id=? AND user_id=? AND active=1", (aid, current_user.id)
    ).fetchone()
    con.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    threading.Thread(
        target=_immediate_aircraft_check,
        args=(aid, row["name"], row["icao24"], row["registration"],
              current_user.email, current_user.name),
        daemon=True,
    ).start()
    return jsonify({"ok": True, "message": f"Checking '{row['name']}'..."})

@aircraft_bp.route("/api/aircraft/<int:aid>/position", methods=["GET"])
@login_required
def aircraft_position(aid):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT * FROM aircraft_monitoring WHERE id=? AND user_id=? AND active=1", (aid, current_user.id)
    ).fetchone()
    con.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    pos = get_aircraft_position(row["icao24"])
    if pos:
        _update_position("aircraft_monitoring", aid, pos)
        return jsonify(pos)
    cached = json.loads(row["last_position"]) if row["last_position"] else None
    if cached:
        return jsonify({**cached, "cached": True})
    return jsonify({"error": "no_data"}), 404
