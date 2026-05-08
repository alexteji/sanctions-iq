import hashlib
import json
import os
import sqlite3
import threading
import time
from datetime import datetime

import feedparser
import requests as _requests

from utils import fetch_with_retry, fetch_feed

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "sanctions.db"))

NEWS_SOURCES = [
    "https://feeds.reuters.com/reuters/businessNews",
    "https://home.treasury.gov/policy-issues/financial-sanctions/recent-actions/feed",
    "https://www.consilium.europa.eu/en/policies/sanctions/rss/",
    "https://www.gov.uk/government/organisations/office-of-financial-sanctions-implementation.atom",
    "https://www.fatf-gafi.org/en/publications/Fatfgeneral/rss-feed.xml",
]

# High-risk flag states (ISO 2-letter codes)
HIGH_RISK_FLAGS = {
    "KP": "North Korea", "IR": "Iran", "SY": "Syria",
    "CU": "Cuba", "VE": "Venezuela", "BY": "Belarus",
}

# Ports/place names associated with sanctioned jurisdictions
SANCTIONED_PORT_TERMS = [
    "bandar abbas", "bushehr", "kharg", "assaluyeh",           # Iran
    "latakia", "tartous", "tartus", "baniyas",                  # Syria
    "wonsan", "nampo", "rason", "chongjin", "rajin",            # DPRK
    "novorossiysk", "sevastopol", "kerch", "feodosiya",         # Russia/Crimea
    "havana",                                                    # Cuba
]

# ─── AIS position lookup ──────────────────────────────────────────────────────

def get_vessel_position(mmsi):
    """Fetch live AIS position. Tries MarineTraffic first, falls back to VesselFinder."""
    if not mmsi:
        return None

    # ── Primary: MarineTraffic ────────────────────────────────────────────────
    api_key = os.getenv("MARINETRAFFIC_API_KEY", "")
    if api_key:
        try:
            resp = fetch_with_retry(
                f"https://services.marinetraffic.com/api/exportvessel/v:8/{api_key}"
                f"/MMSI:{mmsi}/protocol:jsono",
                max_attempts=2, timeout=12,
            )
            data = resp.json()
            if data and isinstance(data, list) and data[0]:
                v = data[0]
                return {
                    "lat": v.get("LAT"), "lon": v.get("LON"),
                    "speed": v.get("SPEED"), "heading": v.get("HEADING"),
                    "status": v.get("STATUS"), "course": v.get("COURSE"),
                    "last_port": v.get("LAST_PORT"),
                    "destination": v.get("DESTINATION"),
                    "flag": v.get("FLAG"),
                    "draught": v.get("DRAUGHT"),
                    "timestamp": v.get("TIMESTAMP"),
                    "source": "MarineTraffic",
                }
        except Exception as exc:
            print(f"[vessels] MarineTraffic error for {mmsi}: {exc}")

    # ── Fallback: VesselFinder (requires VESSELFINDER_API_KEY) ────────────────
    vf_key = os.getenv("VESSELFINDER_API_KEY", "")
    if vf_key:
        try:
            resp = fetch_with_retry(
                "https://api.vesselfinder.com/vessels",
                params={"userkey": vf_key, "mmsi": mmsi},
                max_attempts=2, timeout=12,
            )
            data = resp.json()
            if data and isinstance(data, list) and data[0]:
                v = data[0].get("AIS", {})
                return {
                    "lat": v.get("LATITUDE"), "lon": v.get("LONGITUDE"),
                    "speed": v.get("SPEED"), "heading": v.get("HEADING"),
                    "status": None, "course": v.get("COURSE"),
                    "last_port": v.get("LAST_PORT"),
                    "destination": v.get("DESTINATION"),
                    "flag": v.get("FLAG"),
                    "draught": v.get("DRAUGHT"),
                    "timestamp": str(v.get("TIMESTAMP", "")),
                    "source": "VesselFinder",
                }
        except Exception as exc:
            print(f"[vessels] VesselFinder error for {mmsi}: {exc}")

    return None

# ─── Core checker ─────────────────────────────────────────────────────────────

def check_vessel(vessel_id, name, imo=None, mmsi=None, flag=None):
    new_hits = []
    name_lower = name.lower()
    words = [w for w in name_lower.split() if len(w) > 2]
    if not words:
        words = name_lower.split()

    # 1. Sanctions DB — name match
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    like_clauses = " AND ".join(["(lower(name) LIKE ? OR lower(aliases) LIKE ?)"] * len(words))
    params = []
    for w in words:
        params += [f"%{w}%", f"%{w}%"]
    rows = con.execute(
        f"SELECT * FROM sanctions_entities WHERE {like_clauses}", params
    ).fetchall()
    con.close()
    for r in rows:
        h = hashlib.md5(f"vs:{vessel_id}:{r['id']}".encode()).hexdigest()
        hit = {
            "vessel_id": vessel_id, "hit_type": "sanctions",
            "title": f"Sanctions match: {r['name']} ({r['list_name']})",
            "body": f"Listed under {r['program']} on {r['designation_date']}. Country: {r['country']}.",
            "source": r["list_name"], "url": "", "hash": h,
        }
        if _is_new(h, "vessel_hits"):
            new_hits.append(hit)

    # 2. Flag state risk
    flag_code = (flag or "").upper()
    if flag_code in HIGH_RISK_FLAGS:
        country = HIGH_RISK_FLAGS[flag_code]
        h = hashlib.md5(f"vf:{vessel_id}:{flag_code}".encode()).hexdigest()
        hit = {
            "vessel_id": vessel_id, "hit_type": "flag_risk",
            "title": f"High-risk flag state: {country} ({flag_code})",
            "body": (f"Vessel is registered under {country}, a comprehensively sanctioned "
                     f"jurisdiction. Enhanced due diligence required under OFAC, EU, and UK sanctions."),
            "source": "Flag State Risk Assessment", "url": "", "hash": h,
        }
        if _is_new(h, "vessel_hits"):
            new_hits.append(hit)

    # 3. AIS position — port risk
    if mmsi:
        pos = get_vessel_position(mmsi)
        if pos:
            _update_position("vessel_monitoring", vessel_id, pos)
            dest = (pos.get("destination") or "").lower()
            last_port = (pos.get("last_port") or "").lower()
            for term in SANCTIONED_PORT_TERMS:
                if term in dest or term in last_port:
                    loc = dest if term in dest else last_port
                    h = hashlib.md5(f"vp:{vessel_id}:{term}:{datetime.utcnow().date()}".encode()).hexdigest()
                    hit = {
                        "vessel_id": vessel_id, "hit_type": "sanctioned_port",
                        "title": f"Sanctioned port activity: {term.title()}",
                        "body": (f"Vessel {'headed to' if term in dest else 'last called at'} "
                                 f"{loc.title()}, a port in a sanctioned jurisdiction. "
                                 f"Destination: {pos.get('destination','—')}, "
                                 f"Last port: {pos.get('last_port','—')}."),
                        "source": "AIS / MarineTraffic", "url": "", "hash": h,
                    }
                    if _is_new(h, "vessel_hits"):
                        new_hits.append(hit)

    # 4. News feed
    for feed_url in NEWS_SOURCES:
        feed = fetch_feed(feed_url)
        if not feed:
            continue
        for entry in feed.entries[:20]:
            try:
                title   = entry.get("title", "")
                summary = entry.get("summary", entry.get("description", ""))[:600]
                url     = entry.get("link", "")
                combined = (title + " " + summary).lower()
                if not all(w in combined for w in words):
                    continue
                h = hashlib.md5(f"vn:{vessel_id}:{url}:{title}".encode()).hexdigest()
                hit = {
                    "vessel_id": vessel_id, "hit_type": "news",
                    "title": title, "body": summary,
                    "source": feed.feed.get("title", feed_url), "url": url, "hash": h,
                }
                if _is_new(h, "vessel_hits"):
                    new_hits.append(hit)
            except Exception as exc:
                print(f"[vessels] news entry error: {exc}")

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

def _save_vessel_hits(hits):
    if not hits:
        return
    con = sqlite3.connect(DB_PATH)
    for hit in hits:
        try:
            con.execute(
                """INSERT INTO vessel_hits(vessel_id,hit_type,title,body,source,url,hash)
                   VALUES(?,?,?,?,?,?,?)""",
                (hit["vessel_id"], hit["hit_type"], hit["title"],
                 hit["body"], hit["source"], hit["url"], hit["hash"]),
            )
        except sqlite3.IntegrityError:
            pass
    con.commit()
    con.close()

def _mark_vessel_checked(vessel_id):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "UPDATE vessel_monitoring SET last_checked=? WHERE id=?",
        (datetime.utcnow().isoformat(), vessel_id),
    )
    con.commit()
    con.close()

# ─── Email alert ──────────────────────────────────────────────────────────────

def _send_vessel_alert(to_email, user_name, vessel_name, hits):
    api_key = os.getenv("RESEND_API_KEY", "")
    from_addr = os.getenv("RESEND_FROM", "bureauq <noreply@bureauq.app>")
    type_colors = {
        "sanctions": "#ef4444", "flag_risk": "#f97316",
        "sanctioned_port": "#f97316", "news": "#3b82f6",
    }
    type_labels = {
        "sanctions": "SANCTIONS MATCH", "flag_risk": "FLAG STATE RISK",
        "sanctioned_port": "SANCTIONED PORT", "news": "NEWS MENTION",
    }
    hits_html = ""
    for h in hits:
        c = type_colors.get(h["hit_type"], "#3b82f6")
        lbl = type_labels.get(h["hit_type"], h["hit_type"].upper())
        link = f'<a href="{h["url"]}" style="color:#3b82f6">{h["url"]}</a>' if h.get("url") else ""
        body_preview = (h["body"] or "")[:300] + ("..." if len(h["body"] or "") > 300 else "")
        hits_html += f"""
        <div style="background:#1a1f2e;border-left:3px solid {c};border-radius:6px;padding:14px 16px;margin-bottom:12px">
          <div style="font-size:10px;font-weight:700;letter-spacing:.8px;color:{c};margin-bottom:6px">🚢 {lbl}</div>
          <div style="font-size:14px;font-weight:600;color:#e2e8f0;margin-bottom:5px">{h['title']}</div>
          <div style="font-size:12px;color:#94a3b8;line-height:1.5;margin-bottom:5px">{body_preview}</div>
          <div style="font-size:11px;color:#64748b">Source: {h['source']}{(' · ' + link) if link else ''}</div>
        </div>"""

    html = f"""<div style="font-family:-apple-system,sans-serif;max-width:580px;margin:40px auto;background:#111520;border:1px solid #2a3050;border-radius:12px;overflow:hidden">
      <div style="background:linear-gradient(135deg,#0ea5e9,#3b82f6);padding:24px 28px">
        <div style="font-size:20px;font-weight:800;color:#fff">bureauq</div>
        <div style="font-size:13px;color:rgba(255,255,255,.7);margin-top:3px">🚢 Vessel Monitoring Alert</div>
      </div>
      <div style="padding:28px">
        <p style="font-size:15px;color:#e2e8f0;margin-bottom:6px">Hi {user_name.split()[0]},</p>
        <p style="font-size:13px;color:#94a3b8;margin-bottom:20px;line-height:1.6">
          <strong style="color:#e2e8f0">{len(hits)} new item{'s' if len(hits)!=1 else ''}</strong>
          found for vessel <strong style="color:#e2e8f0">"{vessel_name}"</strong>.
        </p>
        {hits_html}
        <a href="https://bureauq.com" style="display:inline-block;background:#0ea5e9;color:#fff;padding:11px 22px;border-radius:7px;text-decoration:none;font-weight:600;font-size:13px;margin-top:8px">View in Dashboard →</a>
      </div>
    </div>"""

    if api_key:
        try:
            _requests.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"from": from_addr, "to": [to_email],
                      "subject": f"bureauq vessel alert: \"{vessel_name}\"", "html": html},
                timeout=10,
            )
        except Exception as e:
            print(f"[vessels] email error: {e}")
    else:
        print(f"\n{'='*55}\n  VESSEL ALERT — {vessel_name}\n  Hits: {len(hits)}\n{'='*55}\n")

# ─── Background thread ────────────────────────────────────────────────────────

def run_vessel_cycle():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    entries = con.execute(
        """SELECT vm.*, u.email, u.name AS user_name
           FROM vessel_monitoring vm
           JOIN users u ON u.id = vm.user_id
           WHERE vm.active = 1"""
    ).fetchall()
    con.close()
    for entry in entries:
        try:
            hits = check_vessel(entry["id"], entry["name"], entry["imo"], entry["mmsi"], entry["flag"])
            _save_vessel_hits(hits)
            _mark_vessel_checked(entry["id"])
            if hits:
                _send_vessel_alert(entry["email"], entry["user_name"], entry["name"], hits)
        except Exception as e:
            print(f"[vessels] error checking '{entry['name']}': {e}")

def start_vessel_thread():
    def loop():
        while True:
            try:
                run_vessel_cycle()
            except Exception as e:
                print(f"[vessels] cycle error: {e}")
            time.sleep(1800)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t

# ─── Flask blueprint ──────────────────────────────────────────────────────────

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

vessel_bp = Blueprint("vessels", __name__)

@vessel_bp.route("/api/vessels", methods=["GET"])
@login_required
def get_vessels():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM vessel_monitoring WHERE user_id=? AND active=1 ORDER BY created_at DESC",
        (current_user.id,),
    ).fetchall()
    result = []
    for r in rows:
        unread = con.execute(
            "SELECT COUNT(*) FROM vessel_hits WHERE vessel_id=? AND notified=0", (r["id"],)
        ).fetchone()[0]
        total = con.execute(
            "SELECT COUNT(*) FROM vessel_hits WHERE vessel_id=?", (r["id"],)
        ).fetchone()[0]
        pos = json.loads(r["last_position"]) if r["last_position"] else None
        result.append({**dict(r), "unread_hits": unread, "total_hits": total, "position": pos})
    con.close()
    return jsonify(result)

@vessel_bp.route("/api/vessels", methods=["POST"])
@login_required
def add_vessel():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Name required"}), 400
    con = sqlite3.connect(DB_PATH)
    if con.execute(
        "SELECT id FROM vessel_monitoring WHERE user_id=? AND lower(name)=? AND active=1",
        (current_user.id, name.lower()),
    ).fetchone():
        con.close()
        return jsonify({"error": "Already monitoring this vessel"}), 409
    cur = con.execute(
        "INSERT INTO vessel_monitoring(user_id,name,imo,mmsi,flag,vessel_type,notes) VALUES(?,?,?,?,?,?,?)",
        (current_user.id, name, data.get("imo", ""), data.get("mmsi", ""),
         data.get("flag", ""), data.get("vessel_type", "tanker"), data.get("notes", "")),
    )
    con.commit()
    vid = cur.lastrowid
    con.close()
    threading.Thread(
        target=_immediate_vessel_check,
        args=(vid, name, data.get("imo", ""), data.get("mmsi", ""),
              data.get("flag", ""), current_user.email, current_user.name),
        daemon=True,
    ).start()
    return jsonify({"id": vid, "name": name})

def _immediate_vessel_check(vid, name, imo, mmsi, flag, email, user_name):
    try:
        hits = check_vessel(vid, name, imo, mmsi, flag)
        _save_vessel_hits(hits)
        _mark_vessel_checked(vid)
        if hits:
            _send_vessel_alert(email, user_name, name, hits)
    except Exception as e:
        print(f"[vessels] immediate check error: {e}")

@vessel_bp.route("/api/vessels/<int:vid>", methods=["DELETE"])
@login_required
def remove_vessel(vid):
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE vessel_monitoring SET active=0 WHERE id=? AND user_id=?", (vid, current_user.id))
    con.commit()
    con.close()
    return jsonify({"ok": True})

@vessel_bp.route("/api/vessels/<int:vid>/hits", methods=["GET"])
@login_required
def get_vessel_hits(vid):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    if not con.execute(
        "SELECT id FROM vessel_monitoring WHERE id=? AND user_id=?", (vid, current_user.id)
    ).fetchone():
        con.close()
        return jsonify({"error": "Not found"}), 404
    hits = con.execute(
        "SELECT * FROM vessel_hits WHERE vessel_id=? ORDER BY found_at DESC LIMIT 50", (vid,)
    ).fetchall()
    con.execute("UPDATE vessel_hits SET notified=1 WHERE vessel_id=? AND notified=0", (vid,))
    con.commit()
    con.close()
    return jsonify([dict(h) for h in hits])

@vessel_bp.route("/api/vessels/<int:vid>/check", methods=["POST"])
@login_required
def manual_vessel_check(vid):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT * FROM vessel_monitoring WHERE id=? AND user_id=? AND active=1", (vid, current_user.id)
    ).fetchone()
    con.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    threading.Thread(
        target=_immediate_vessel_check,
        args=(vid, row["name"], row["imo"], row["mmsi"], row["flag"],
              current_user.email, current_user.name),
        daemon=True,
    ).start()
    return jsonify({"ok": True, "message": f"Checking '{row['name']}'..."})

@vessel_bp.route("/api/vessels/map", methods=["GET"])
@login_required
def vessels_map():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM vessel_monitoring WHERE active=1 AND user_id=?",
        (current_user.id,)
    ).fetchall()
    con.close()
    result = []
    for r in rows:
        pos = json.loads(r["last_position"]) if r["last_position"] else {}
        if not pos.get("lat") or not pos.get("lon"):
            continue
        flag = (r["flag"] or "").upper()[:2]
        flagged = flag in HIGH_RISK_FLAGS
        result.append({
            "id": r["id"], "name": r["name"],
            "imo": r["imo"], "mmsi": r["mmsi"], "flag": r["flag"],
            "lat": pos.get("lat"), "lon": pos.get("lon"),
            "speed": pos.get("speed"), "heading": pos.get("heading"),
            "destination": pos.get("destination"),
            "last_port": pos.get("last_port"),
            "flagged": flagged,
        })
    return jsonify(result)

@vessel_bp.route("/api/vessels/<int:vid>/position", methods=["GET"])
@login_required
def vessel_position(vid):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT * FROM vessel_monitoring WHERE id=? AND user_id=? AND active=1", (vid, current_user.id)
    ).fetchone()
    con.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    if not os.getenv("MARINETRAFFIC_API_KEY"):
        cached = json.loads(row["last_position"]) if row["last_position"] else None
        return jsonify({"error": "no_api_key", "cached": cached})
    pos = get_vessel_position(row["mmsi"])
    if pos:
        _update_position("vessel_monitoring", vid, pos)
        return jsonify(pos)
    cached = json.loads(row["last_position"]) if row["last_position"] else None
    if cached:
        return jsonify({**cached, "cached": True})
    return jsonify({"error": "no_data"}), 404
