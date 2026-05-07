import os
import json
import sqlite3
import threading
import time
import hashlib
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template, redirect, url_for, g
from flask_login import login_required, current_user
import requests
import feedparser
from dateutil import parser as date_parser

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", os.urandom(32).hex())
# On Render the persistent disk is mounted at /data; fall back to local path for dev
DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "sanctions.db"))

# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            entity_type TEXT DEFAULT 'individual',
            notes TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            last_checked TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT,
            severity TEXT DEFAULT 'medium',
            source TEXT,
            url TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            read INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS news_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            summary TEXT,
            source TEXT,
            url TEXT,
            published TEXT,
            fetched_at TEXT DEFAULT (datetime('now')),
            hash TEXT UNIQUE
        );
        CREATE TABLE IF NOT EXISTS screen_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT,
            result_count INTEGER,
            lists_checked TEXT,
            screened_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS sanctions_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            list_name TEXT,
            entity_type TEXT,
            name TEXT,
            aliases TEXT,
            country TEXT,
            program TEXT,
            designation_date TEXT,
            details TEXT,
            synced_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            created_at TEXT DEFAULT (datetime('now')),
            last_login TEXT,
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            subscription_status TEXT DEFAULT 'trialing',
            subscription_plan TEXT,
            trial_ends_at TEXT,
            subscription_ends_at TEXT
        );
        CREATE TABLE IF NOT EXISTS monitoring_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            entity_type TEXT DEFAULT 'individual',
            notes TEXT,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now')),
            last_checked TEXT,
            last_alert_sent TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS monitoring_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            monitoring_id INTEGER NOT NULL,
            hit_type TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT,
            source TEXT,
            url TEXT,
            found_at TEXT DEFAULT (datetime('now')),
            notified INTEGER DEFAULT 0,
            hash TEXT UNIQUE,
            FOREIGN KEY(monitoring_id) REFERENCES monitoring_list(id)
        );
        CREATE TABLE IF NOT EXISTS vessel_monitoring (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            imo TEXT,
            mmsi TEXT,
            flag TEXT,
            vessel_type TEXT DEFAULT 'tanker',
            notes TEXT,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now')),
            last_position TEXT,
            last_checked TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS vessel_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vessel_id INTEGER NOT NULL,
            hit_type TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT,
            source TEXT,
            url TEXT,
            found_at TEXT DEFAULT (datetime('now')),
            notified INTEGER DEFAULT 0,
            hash TEXT UNIQUE,
            FOREIGN KEY(vessel_id) REFERENCES vessel_monitoring(id)
        );
        CREATE TABLE IF NOT EXISTS aircraft_monitoring (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            registration TEXT,
            icao24 TEXT,
            aircraft_type TEXT DEFAULT 'fixed-wing',
            notes TEXT,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now')),
            last_position TEXT,
            last_checked TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS aircraft_hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aircraft_id INTEGER NOT NULL,
            hit_type TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT,
            source TEXT,
            url TEXT,
            found_at TEXT DEFAULT (datetime('now')),
            notified INTEGER DEFAULT 0,
            hash TEXT UNIQUE,
            FOREIGN KEY(aircraft_id) REFERENCES aircraft_monitoring(id)
        );
        CREATE TABLE IF NOT EXISTS sync_status (
            list_name TEXT PRIMARY KEY,
            last_synced TEXT,
            record_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'never'
        );
        CREATE TABLE IF NOT EXISTS sync_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            list_name TEXT NOT NULL,
            status TEXT NOT NULL,
            records_synced INTEGER DEFAULT 0,
            message TEXT,
            synced_at TEXT DEFAULT (datetime('now'))
        );
    """)
    _migrate_users(cur)
    _seed_demo_data(cur)
    con.commit()

def _migrate_users(cur):
    """Add subscription columns to existing users table if missing."""
    existing = {r[1] for r in cur.execute("PRAGMA table_info(users)").fetchall()}
    additions = {
        "stripe_customer_id":     "TEXT",
        "stripe_subscription_id": "TEXT",
        "subscription_status":    "TEXT DEFAULT 'trialing'",
        "subscription_plan":      "TEXT",
        "trial_ends_at":          "TEXT",
        "subscription_ends_at":   "TEXT",
    }
    for col, typedef in additions.items():
        if col not in existing:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} {typedef}")
    # Seed trial_ends_at for existing users who don't have one
    trial_end = (datetime.utcnow() + timedelta(days=14)).isoformat()
    cur.execute(
        "UPDATE users SET trial_ends_at=? WHERE trial_ends_at IS NULL",
        (trial_end,)
    )

def _seed_demo_data(cur):
    cur.execute("SELECT COUNT(*) FROM alerts")
    if cur.fetchone()[0] == 0:
        demo_alerts = [
            ("OFAC Update: New SDN Designations", "OFAC designated 12 entities and individuals related to Russian energy sector evasion networks.", "high", "OFAC", "https://ofac.treasury.gov", datetime.utcnow().isoformat()),
            ("EU Sanctions: Additional Belarus Listings", "Council Regulation adds 4 individuals responsible for serious human rights violations.", "high", "EU Official Journal", "https://eur-lex.europa.eu", (datetime.utcnow() - timedelta(hours=3)).isoformat()),
            ("UN Security Council: DPRK Panel Report", "Quarterly report identifies new methods used to circumvent sanctions regime.", "medium", "UNSC", "https://un.org", (datetime.utcnow() - timedelta(hours=7)).isoformat()),
            ("UK FCDO: Iran Designations", "Financial sanctions updated under the Iran (Sanctions) Regulations 2019.", "medium", "UK FCDO", "https://gov.uk", (datetime.utcnow() - timedelta(days=1)).isoformat()),
            ("FATF: High-Risk Jurisdictions Updated", "Grey list updated — Myanmar, Burkina Faso, and Senegal under increased monitoring.", "low", "FATF", "https://fatf-gafi.org", (datetime.utcnow() - timedelta(days=2)).isoformat()),
        ]
        cur.executemany(
            "INSERT INTO alerts(title,body,severity,source,url,created_at) VALUES(?,?,?,?,?,?)",
            demo_alerts
        )

    cur.execute("SELECT COUNT(*) FROM watchlist")
    if cur.fetchone()[0] == 0:
        demo_watchlist = [
            ("Rosneft Oil Company", "entity", "Russian state oil company under EU/UK sanctions"),
            ("Kim Jong-un", "individual", "DPRK Supreme Leader — UNSC/OFAC/EU/UK sanctioned"),
            ("Sberbank", "entity", "Russian state bank — OFAC SDN listed"),
            ("Wagner Group", "entity", "Russian private military company — multiple list designations"),
        ]
        cur.executemany(
            "INSERT INTO watchlist(name,entity_type,notes,last_checked) VALUES(?,?,?,?)",
            [(n, t, no, datetime.utcnow().isoformat()) for n, t, no in demo_watchlist]
        )

    cur.execute("SELECT COUNT(*) FROM sanctions_entities")
    if cur.fetchone()[0] == 0:
        _seed_sanctions_entities(cur)

def _seed_sanctions_entities(cur):
    entities = [
        # OFAC SDN samples
        ("OFAC SDN", "individual", "PUTIN, Vladimir Vladimirovich", "Putin;VVP", "Russia", "RUSSIA-EO14024", "2022-03-11", '{"dob":"1952-10-07","passport":"RU-S/N"}'),
        ("OFAC SDN", "entity", "ROSNEFT OIL COMPANY", "Rosneft;Rosneft' OAO", "Russia", "UKRAINE-EO13685", "2022-02-24", '{"address":"Sofiyskaya Embankment 26/1, Moscow"}'),
        ("OFAC SDN", "entity", "SBERBANK", "Sberbank Rossii;PJSC Sberbank", "Russia", "RUSSIA-EO14024", "2022-04-06", '{"swift":"SABRRUMM"}'),
        ("OFAC SDN", "individual", "SECHIN, Igor Ivanovich", "Sechin;I.I. Sechin", "Russia", "UKRAINE-EO13661", "2014-04-28", '{"dob":"1960-09-07"}'),
        ("OFAC SDN", "entity", "INTERNET RESEARCH AGENCY LLC", "IRA;Agentstvo Internet Issledovaniy", "Russia", "RUSSIA-EO13848", "2018-02-16", '{}'),
        ("OFAC SDN", "individual", "KIM, Jong Un", "Kim Jong-un;KJU", "Korea, North", "DPRK4", "2016-07-06", '{"dob":"1984-01-08"}'),
        ("OFAC SDN", "entity", "MAHAN AIR", "Mahan Airways", "Iran", "IRAN", "2011-10-12", '{"icao":"IRM"}'),
        ("OFAC SDN", "individual", "LUKASHENKO, Alexander Grigoryevich", "Lukashenka", "Belarus", "BELARUS-EO13405", "2006-06-19", '{"dob":"1954-08-30"}'),
        ("OFAC SDN", "entity", "WAGNER GROUP", "PMC Wagner;Concord Management", "Russia", "RUSSIA-EO14024", "2023-01-26", '{}'),
        ("OFAC SDN", "individual", "AL-BAGHDADI, Abu Bakr", "Ibrahim Awad Ibrahim al-Badri;Abu Du'a", "Iraq", "SDGT", "2004-10-15", '{"dob":"1971-07-28","deceased":"2019"}'),
        # EU Sanctions
        ("EU Consolidated", "individual", "LAVROV, Sergei Viktorovich", "Lavrov", "Russia", "Russia (Ukraine)", "2022-02-28", '{"function":"Minister of Foreign Affairs"}'),
        ("EU Consolidated", "entity", "GAZPROM", "Gazprom PJSC;OAO Gazprom", "Russia", "Russia (Ukraine)", "2022-06-03", '{"sector":"Energy"}'),
        ("EU Consolidated", "individual", "MILLER, Alexei Borisovich", "Alexei Miller", "Russia", "Russia (Ukraine)", "2022-06-03", '{"function":"CEO Gazprom"}'),
        ("EU Consolidated", "individual", "PRIGOZHIN, Yevgeny Viktorovich", "Prigozhin;Chef Putin", "Russia", "Russia (Ukraine)", "2020-10-22", '{"dob":"1961-06-01"}'),
        # UN Security Council
        ("UNSC", "entity", "ISLAMIC STATE IN IRAQ AND THE LEVANT", "ISIS;ISIL;Daesh;IS", "Iraq/Syria", "1267/1989/2253", "2014-05-30", '{"alias_count":30}'),
        ("UNSC", "entity", "AL-QAIDA", "Al-Qaeda;AQ;Base", "Afghanistan", "1267/1989/2253", "1999-10-15", '{}'),
        ("UNSC", "individual", "BIN LADEN, Usama Mohammad Awad", "Osama bin Laden;UBL", "Saudi Arabia", "1267/1989/2253", "2001-09-25", '{"dob":"1957-03-10","deceased":"2011"}'),
        ("UNSC", "entity", "KOREA MINING DEVELOPMENT TRADING CORPORATION", "KOMID", "Korea, North", "1718", "2009-04-24", '{"sector":"Arms"}'),
        # UK FCDO
        ("UK FCDO", "individual", "ABRAMOVICH, Roman Arkadyevich", "Abramovich", "Russia", "Russia (Sanctions) (EU Exit) Regulations 2019", "2022-03-10", '{"dob":"1966-10-24"}'),
        ("UK FCDO", "entity", "VTB BANK", "VTB;Vneshtorgbank", "Russia", "Russia (Sanctions) (EU Exit) Regulations 2019", "2022-02-24", '{}'),
        ("UK FCDO", "individual", "DERIPASKA, Oleg Vladimirovich", "Deripaska", "Russia", "Russia (Sanctions) (EU Exit) Regulations 2019", "2022-03-10", '{"dob":"1968-01-02"}'),
    ]
    cur.executemany(
        "INSERT INTO sanctions_entities(list_name,entity_type,name,aliases,country,program,designation_date,details) VALUES(?,?,?,?,?,?,?,?)",
        entities
    )

# ─── Background Tasks ────────────────────────────────────────────────────────

NEWS_FEEDS = [
    {"name": "Reuters Sanctions", "url": "https://feeds.reuters.com/reuters/businessNews"},
    {"name": "OFAC Updates",      "url": "https://home.treasury.gov/policy-issues/financial-sanctions/recent-actions/feed"},
    {"name": "EU Sanctions News", "url": "https://www.consilium.europa.eu/en/policies/sanctions/rss/"},
]

def _fetch_news():
    """Pull RSS feeds and store in DB, dedup by hash."""
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    keywords = ["sanction", "compliance", "ofac", "designation", "aml", "terror finance", "money laundering", "export control", "debarment"]
    inserted = 0
    for feed_meta in NEWS_FEEDS:
        try:
            feed = feedparser.parse(feed_meta["url"])
            for entry in feed.entries[:15]:
                title = entry.get("title", "")
                summary = entry.get("summary", entry.get("description", ""))[:500]
                url = entry.get("link", "")
                published = ""
                if hasattr(entry, "published"):
                    try:
                        published = date_parser.parse(entry.published).isoformat()
                    except Exception:
                        published = entry.published
                full_text = (title + summary).lower()
                if not any(kw in full_text for kw in keywords):
                    continue
                h = hashlib.md5((title + url).encode()).hexdigest()
                try:
                    cur.execute(
                        "INSERT INTO news_cache(title,summary,source,url,published,hash) VALUES(?,?,?,?,?,?)",
                        (title, summary, feed_meta["name"], url, published, h)
                    )
                    inserted += 1
                except sqlite3.IntegrityError:
                    pass
        except Exception:
            pass
    con.commit()
    con.close()
    return inserted

def _background_refresh():
    while True:
        try:
            with app.app_context():
                _fetch_news()
        except Exception:
            pass
        time.sleep(600)  # refresh every 10 min

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    sub = get_subscription(current_user.id)
    return render_template("index.html", user=current_user, sub=sub)

@login_required
@app.route("/api/stats")
@login_required
def api_stats():
    db = get_db()
    total_entities = db.execute("SELECT COUNT(*) FROM sanctions_entities").fetchone()[0]
    by_list = db.execute(
        "SELECT list_name, COUNT(*) as cnt FROM sanctions_entities GROUP BY list_name"
    ).fetchall()
    unread_alerts = db.execute("SELECT COUNT(*) FROM alerts WHERE read=0").fetchone()[0]
    watchlist_count = db.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
    news_count = db.execute("SELECT COUNT(*) FROM news_cache").fetchone()[0]
    screens_today = db.execute(
        "SELECT COUNT(*) FROM screen_history WHERE date(screened_at)=date('now')"
    ).fetchone()[0]
    return jsonify({
        "total_sanctioned_entities": total_entities,
        "unread_alerts": unread_alerts,
        "watchlist_count": watchlist_count,
        "news_items": news_count,
        "screens_today": screens_today,
        "by_list": [{"list": r["list_name"], "count": r["cnt"]} for r in by_list],
        "last_updated": datetime.utcnow().isoformat() + "Z",
    })

@login_required
@app.route("/api/screen", methods=["POST"])
@login_required
def api_screen():
    data = request.get_json(force=True)
    query = (data.get("query") or "").strip()
    if not query or len(query) < 2:
        return jsonify({"error": "Query too short"}), 400
    db = get_db()
    q_lower = query.lower()
    words = q_lower.split()
    like_clauses = " AND ".join(
        ["(lower(name) LIKE ? OR lower(aliases) LIKE ?)"] * len(words)
    )
    params = []
    for w in words:
        params += [f"%{w}%", f"%{w}%"]
    rows = db.execute(
        f"SELECT * FROM sanctions_entities WHERE {like_clauses} LIMIT 50",
        params
    ).fetchall()
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "list_name": r["list_name"],
            "entity_type": r["entity_type"],
            "name": r["name"],
            "aliases": r["aliases"].split(";") if r["aliases"] else [],
            "country": r["country"],
            "program": r["program"],
            "designation_date": r["designation_date"],
            "details": json.loads(r["details"]) if r["details"] else {},
        })
    db.execute(
        "INSERT INTO screen_history(query,result_count,lists_checked) VALUES(?,?,?)",
        (query, len(results), "OFAC SDN,EU Consolidated,UNSC,UK FCDO")
    )
    db.commit()
    return jsonify({"query": query, "hits": len(results), "results": results})

@login_required
@app.route("/api/alerts")
def api_alerts():
    db = get_db()
    limit = min(int(request.args.get("limit", 20)), 100)
    rows = db.execute(
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@login_required
@app.route("/api/alerts/<int:alert_id>/read", methods=["POST"])
def mark_alert_read(alert_id):
    db = get_db()
    db.execute("UPDATE alerts SET read=1 WHERE id=?", (alert_id,))
    db.commit()
    return jsonify({"ok": True})

@login_required
@app.route("/api/alerts/read-all", methods=["POST"])
def mark_all_read():
    db = get_db()
    db.execute("UPDATE alerts SET read=1")
    db.commit()
    return jsonify({"ok": True})

@login_required
@app.route("/api/news")
def api_news():
    db = get_db()
    limit = min(int(request.args.get("limit", 30)), 100)
    rows = db.execute(
        "SELECT * FROM news_cache ORDER BY fetched_at DESC LIMIT ?", (limit,)
    ).fetchall()
    result = [dict(r) for r in rows]
    if not result:
        result = _get_fallback_news()
    return jsonify(result)

def _get_fallback_news():
    now = datetime.utcnow()
    return [
        {"id":1,"title":"OFAC Issues Russia-Related Designations Targeting Evasion Networks","summary":"The U.S. Department of the Treasury's Office of Foreign Assets Control (OFAC) today designated 14 individuals and 28 entities involved in facilitating sanctions evasion on behalf of Russia.","source":"OFAC","url":"https://home.treasury.gov/news/press-releases","published":(now - timedelta(hours=2)).isoformat(),"fetched_at":now.isoformat()},
        {"id":2,"title":"EU Adopts 14th Package of Sanctions Against Russia","summary":"The Council adopted the 14th package of restrictive measures against Russia for its continued military aggression against Ukraine, targeting additional individuals and entities.","source":"EU Council","url":"https://www.consilium.europa.eu","published":(now - timedelta(hours=5)).isoformat(),"fetched_at":now.isoformat()},
        {"id":3,"title":"FATF Updates High-Risk Jurisdiction List — Four Countries Added","summary":"The Financial Action Task Force has updated its list of jurisdictions under increased monitoring, adding four new countries exhibiting strategic AML/CFT deficiencies.","source":"FATF","url":"https://www.fatf-gafi.org","published":(now - timedelta(hours=8)).isoformat(),"fetched_at":now.isoformat()},
        {"id":4,"title":"UK Sanctions: New Designations Under Cyber (Sanctions) Regulations","summary":"FCDO has sanctioned 6 individuals affiliated with the Lazarus Group for cyberattacks targeting critical infrastructure and cryptocurrency theft.","source":"UK FCDO","url":"https://www.gov.uk/government/collections/financial-sanctions-regime-specific-consolidated-lists","published":(now - timedelta(hours=12)).isoformat(),"fetched_at":now.isoformat()},
        {"id":5,"title":"UN Security Council: DPRK Sanctions Committee Issues Midterm Report","summary":"The Panel of Experts reports continued violations of Security Council resolutions, including illicit ship-to-ship transfers of petroleum products and cyberattacks generating illicit revenue.","source":"UNSC","url":"https://www.un.org/securitycouncil/sanctions","published":(now - timedelta(days=1)).isoformat(),"fetched_at":now.isoformat()},
        {"id":6,"title":"BIS Adds 42 Entities to Entity List for Supporting Russia and China Military Programs","summary":"The Commerce Department's Bureau of Industry and Security added 42 entities to the Entity List for supporting military programs in Russia and China, imposing export licensing requirements.","source":"BIS","url":"https://www.bis.doc.gov","published":(now - timedelta(days=1, hours=4)).isoformat(),"fetched_at":now.isoformat()},
        {"id":7,"title":"FinCEN Alert: Increasing Use of Real Estate for Sanctions Evasion","summary":"FinCEN has issued an alert to financial institutions regarding escalating use of shell companies and real estate transactions to evade sanctions and launder proceeds.","source":"FinCEN","url":"https://www.fincen.gov/news","published":(now - timedelta(days=2)).isoformat(),"fetched_at":now.isoformat()},
        {"id":8,"title":"European Banking Authority: New AML/CFT Guidelines for Correspondent Banking","summary":"The EBA has published final guidelines strengthening requirements for risk assessment and due diligence in correspondent banking relationships, effective January 2026.","source":"EBA","url":"https://www.eba.europa.eu","published":(now - timedelta(days=2, hours=6)).isoformat(),"fetched_at":now.isoformat()},
    ]

@login_required
@app.route("/api/watchlist", methods=["GET"])
def api_watchlist_get():
    db = get_db()
    rows = db.execute("SELECT * FROM watchlist ORDER BY created_at DESC").fetchall()
    result = []
    for r in rows:
        item = dict(r)
        hits = db.execute(
            "SELECT COUNT(*) FROM sanctions_entities WHERE lower(name) LIKE ? OR lower(aliases) LIKE ?",
            (f"%{r['name'].lower()}%", f"%{r['name'].lower()}%")
        ).fetchone()[0]
        item["sanctions_hits"] = hits
        result.append(item)
    return jsonify(result)

@login_required
@app.route("/api/watchlist", methods=["POST"])
def api_watchlist_add():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Name required"}), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO watchlist(name,entity_type,notes,last_checked) VALUES(?,?,?,?)",
        (name, data.get("entity_type", "individual"), data.get("notes", ""), datetime.utcnow().isoformat())
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "name": name})

@login_required
@app.route("/api/watchlist/<int:wid>", methods=["DELETE"])
def api_watchlist_delete(wid):
    db = get_db()
    db.execute("DELETE FROM watchlist WHERE id=?", (wid,))
    db.commit()
    return jsonify({"ok": True})

@login_required
@app.route("/api/entities")
def api_entities():
    db = get_db()
    list_name = request.args.get("list", "")
    entity_type = request.args.get("type", "")
    country = request.args.get("country", "")
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))
    clauses, params = [], []
    if list_name:
        clauses.append("list_name=?"); params.append(list_name)
    if entity_type:
        clauses.append("entity_type=?"); params.append(entity_type)
    if country:
        clauses.append("lower(country) LIKE ?"); params.append(f"%{country.lower()}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    total = db.execute(f"SELECT COUNT(*) FROM sanctions_entities {where}", params).fetchone()[0]
    rows = db.execute(
        f"SELECT * FROM sanctions_entities {where} ORDER BY name LIMIT ? OFFSET ?",
        params + [limit, offset]
    ).fetchall()
    return jsonify({
        "total": total,
        "offset": offset,
        "limit": limit,
        "entities": [dict(r) for r in rows]
    })

@login_required
@app.route("/api/countries")
def api_countries():
    db = get_db()
    rows = db.execute(
        "SELECT country, COUNT(*) as cnt FROM sanctions_entities GROUP BY country ORDER BY cnt DESC"
    ).fetchall()
    country_risk = {
        "Russia": "critical", "Korea, North": "critical", "Iran": "critical",
        "Syria": "critical", "Cuba": "high", "Venezuela": "high",
        "Belarus": "high", "Myanmar": "high", "Iraq": "high",
        "Libya": "medium", "Somalia": "medium", "Sudan": "medium",
        "Yemen": "medium", "Zimbabwe": "medium",
    }
    result = []
    for r in rows:
        result.append({
            "country": r["country"],
            "count": r["cnt"],
            "risk_level": country_risk.get(r["country"], "low")
        })
    return jsonify(result)

@login_required
@app.route("/api/refresh-news", methods=["POST"])
def api_refresh_news():
    inserted = _fetch_news()
    return jsonify({"ok": True, "new_items": inserted})

@login_required
@app.route("/api/screen-history")
def api_screen_history():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM screen_history ORDER BY screened_at DESC LIMIT 20"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/me")
@login_required
def api_me():
    return jsonify({
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "role": current_user.role,
    })

# ─── Auth & billing wiring ────────────────────────────────────────────────────

from auth import auth_bp, login_manager
from billing import billing_bp, subscription_active, get_subscription
from monitoring import monitoring_bp, start_monitoring_thread
from vessel_tracking import vessel_bp, start_vessel_thread
from aircraft_tracking import aircraft_bp, start_aircraft_thread
from sanctions_sync import sync_bp, start_sync_thread, screen_pep

login_manager.init_app(app)
login_manager.login_view = "auth.login"
login_manager.login_message = None
app.register_blueprint(auth_bp)
app.register_blueprint(billing_bp)
app.register_blueprint(monitoring_bp)
app.register_blueprint(vessel_bp)
app.register_blueprint(aircraft_bp)
app.register_blueprint(sync_bp)

@app.context_processor
def inject_now():
    return {"now": datetime.utcnow()}

@app.before_request
def enforce_subscription():
    """Block API calls and dashboard for users with no active subscription."""
    exempt_prefixes = ("/login", "/logout", "/register", "/forgot-password",
                       "/reset-password", "/pricing", "/billing", "/static",
                       "/api/auth")
    if any(request.path.startswith(p) for p in exempt_prefixes):
        return
    if not current_user.is_authenticated:
        return
    if subscription_active(current_user.id):
        return
    # Subscription inactive — API gets 402, dashboard gets redirect
    if request.path.startswith("/api/"):
        return jsonify({"error": "subscription_required",
                        "upgrade_url": "/pricing"}), 402
    return redirect(url_for("billing.pricing"))

def create_app():
    init_db()
    bg = threading.Thread(target=_background_refresh, daemon=True)
    bg.start()
    start_monitoring_thread()
    start_vessel_thread()
    start_aircraft_thread()
    start_sync_thread()
    return app

if __name__ == "__main__":
    create_app()
    port = int(os.getenv("PORT", 5050))
    print(f"\n🌐  Sanctions Monitor running at http://127.0.0.1:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
