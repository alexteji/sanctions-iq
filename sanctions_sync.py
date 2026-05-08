"""
Live sanctions list sync + PEP screening.

Sanctions sources (all free, no key needed):
  OFAC SDN        — https://www.treasury.gov/ofac/downloads/sdn.xml
  UN SC           — https://scsanctions.un.org/resources/xml/en/consolidated.xml
  UK OFSI         — https://ofsistorage.blob.core.windows.net/publishlive/ConList.csv
  EU FSF          — https://webgate.ec.europa.eu/fsd/fsf/  (XML)
  World Bank      — https://finances.worldbank.org  (Socrata JSON API)
  BIS Entity List — https://efts.bis.doc.gov  (CSV)
  Australia DFAT  — https://www.dfat.gov.au  (XLSX, requires openpyxl)

PEP screening:
  OpenSanctions API — https://api.opensanctions.org
  Free tier: ~100 req/day anonymous.  Set OPENSANCTIONS_API_KEY for higher limits.
"""

import csv
import io
import json
import os
import sqlite3
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime

import requests as _requests

from utils import fetch_with_retry

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "sanctions.db"))

OFAC_URL    = "https://www.treasury.gov/ofac/downloads/sdn.xml"
UN_SC_URL   = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
UK_URL      = "https://ofsistorage.blob.core.windows.net/publishlive/ConList.csv"
EU_URL      = ("https://webgate.ec.europa.eu/fsd/fsf/public/files/"
               "xmlFullSanctionsList_1_1/content?token=dG9rZW4tMjAxNw")
OS_API      = "https://api.opensanctions.org"
WB_URL      = "https://finances.worldbank.org/resource/ezgi-7imi.json?$limit=50000"
BIS_URL     = ("https://efts.bis.doc.gov/complete-search-of-existing-actions"
               "?format=csv&search%5B%5D=EL")
AU_DFAT_URL = ("https://www.dfat.gov.au/sites/default/files/"
               "australian-sanctions-consolidated-list.xlsx")

# ─── Sync log helpers ─────────────────────────────────────────────────────────

def _log(list_name, status, count, msg=""):
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO sync_log(list_name,status,records_synced,message) VALUES(?,?,?,?)",
        (list_name, status, count, msg),
    )
    con.execute(
        """INSERT INTO sync_status(list_name,last_synced,record_count,status)
           VALUES(?,?,?,?)
           ON CONFLICT(list_name) DO UPDATE SET
             last_synced=excluded.last_synced,
             record_count=excluded.record_count,
             status=excluded.status""",
        (list_name, datetime.utcnow().isoformat(), count, status),
    )
    con.commit()
    con.close()

def _replace_list(list_name, entries, also_delete=None):
    """Atomically replace all rows for a list."""
    con = sqlite3.connect(DB_PATH)
    con.execute("DELETE FROM sanctions_entities WHERE list_name=?", (list_name,))
    if also_delete:
        con.execute("DELETE FROM sanctions_entities WHERE list_name=?", (also_delete,))
    con.executemany(
        """INSERT INTO sanctions_entities
           (list_name,entity_type,name,aliases,country,program,designation_date,details)
           VALUES(?,?,?,?,?,?,?,?)""",
        entries,
    )
    con.commit()
    con.close()

# ─── OFAC SDN ─────────────────────────────────────────────────────────────────

def sync_ofac_sdn():
    print("[sync] OFAC SDN …")
    try:
        resp = fetch_with_retry(OFAC_URL, timeout=120)
        root = ET.fromstring(resp.content)

        entries = []
        for entry in root.findall("sdnEntry"):
            last  = entry.findtext("lastName")  or ""
            first = entry.findtext("firstName") or ""
            name  = f"{last}, {first}".strip(", ") if first else last
            if not name:
                continue

            sdn_type    = (entry.findtext("sdnType") or "").lower()
            entity_type = "individual" if "individual" in sdn_type else "entity"

            programs = [p.text for p in entry.findall(".//program") if p.text]
            program  = ", ".join(programs[:3])

            akas    = [a.findtext("lastName") or "" for a in entry.findall(".//aka")]
            aliases = ";".join(filter(None, akas[:8]))

            countries = [a.findtext("country") or "" for a in entry.findall(".//address")]
            country   = next((c for c in countries if c), "")

            dobs = [d.findtext("dateOfBirth") or "" for d in entry.findall(".//dateOfBirthItem")]
            dob  = dobs[0] if dobs else ""

            ids = {}
            for id_node in entry.findall(".//id"):
                t = id_node.findtext("idType")
                v = id_node.findtext("idNumber")
                if t and v:
                    ids[t] = v

            entries.append((
                "OFAC SDN", entity_type, name, aliases, country,
                program, dob, json.dumps(ids),
            ))

        _replace_list("OFAC SDN", entries)
        _log("OFAC SDN", "ok", len(entries))
        print(f"[sync] OFAC SDN: {len(entries):,} records")
        return len(entries)
    except Exception as e:
        _log("OFAC SDN", "error", 0, str(e))
        print(f"[sync] OFAC SDN error: {e}")
        return 0

# ─── UN Security Council ──────────────────────────────────────────────────────

def sync_un_sc():
    print("[sync] UN Security Council …")
    try:
        resp = fetch_with_retry(UN_SC_URL, timeout=60)
        root = ET.fromstring(resp.content)

        entries = []

        for ind in root.findall(".//INDIVIDUAL"):
            parts = [
                ind.findtext("FIRST_NAME")  or "",
                ind.findtext("SECOND_NAME") or "",
                ind.findtext("THIRD_NAME")  or "",
                ind.findtext("FOURTH_NAME") or "",
            ]
            name = " ".join(p for p in parts if p).strip()
            if not name:
                continue

            list_type = ind.findtext("UN_LIST_TYPE") or "UNSC"
            listed_on = ind.findtext("LISTED_ON")    or ""

            nats    = [n.text for n in ind.findall(".//NATIONALITY/VALUE") if n.text]
            country = nats[0] if nats else ""

            akas    = [a.findtext("ALIAS_NAME") or "" for a in ind.findall(".//INDIVIDUAL_ALIAS")]
            aliases = ";".join(filter(None, akas[:8]))

            dobs    = [d.findtext("DATE") or d.findtext("YEAR") or ""
                       for d in ind.findall(".//INDIVIDUAL_DATE_OF_BIRTH")]
            dob     = dobs[0] if dobs else ""

            entries.append(("UNSC", "individual", name, aliases, country,
                            list_type, listed_on, json.dumps({"dob": dob})))

        for ent in root.findall(".//ENTITY"):
            name = ent.findtext("FIRST_NAME") or ""
            if not name:
                continue

            list_type = ent.findtext("UN_LIST_TYPE") or "UNSC"
            listed_on = ent.findtext("LISTED_ON")    or ""

            akas    = [a.findtext("ALIAS_NAME") or "" for a in ent.findall(".//ENTITY_ALIAS")]
            aliases = ";".join(filter(None, akas[:8]))

            entries.append(("UNSC", "entity", name, aliases, "",
                            list_type, listed_on, "{}"))

        _replace_list("UNSC", entries)
        _log("UNSC", "ok", len(entries))
        print(f"[sync] UNSC: {len(entries):,} records")
        return len(entries)
    except Exception as e:
        _log("UNSC", "error", 0, str(e))
        print(f"[sync] UNSC error: {e}")
        return 0

# ─── UK OFSI ──────────────────────────────────────────────────────────────────

def sync_uk_ofsi():
    print("[sync] UK OFSI …")
    try:
        resp = fetch_with_retry(UK_URL, timeout=60)

        content = resp.content.decode("utf-8-sig", errors="replace")
        reader  = csv.DictReader(io.StringIO(content))
        headers = reader.fieldnames or []

        # UK OFSI columns vary slightly between versions — map defensively
        def _col(row, *candidates):
            for c in candidates:
                v = row.get(c, "").strip()
                if v:
                    return v
            return ""

        entries = []
        for row in reader:
            # Name: try "Name 6" (entity name) then numbered name parts
            name_parts = [_col(row, f"Name {i}") for i in range(1, 7)]
            name       = " ".join(p for p in name_parts if p).strip()
            if not name:
                continue

            group_type  = _col(row, "Group Type", "GroupType").lower()
            entity_type = "individual" if "individual" in group_type else "entity"

            regime    = _col(row, "Regime", "Sanctions Regime")
            listed_on = _col(row, "Date Designated", "DateDesignated")
            country   = _col(row, "Country", "Nationality")

            akas    = [_col(row, f"Alias {i}") for i in range(1, 7)]
            aliases = ";".join(filter(None, akas))

            entries.append(("UK OFSI", entity_type, name, aliases, country,
                            regime, listed_on, "{}"))

        # Replace both new and old seeded name for this list
        _replace_list("UK OFSI", entries, also_delete="UK FCDO")
        _log("UK OFSI", "ok", len(entries))
        print(f"[sync] UK OFSI: {len(entries):,} records")
        return len(entries)
    except Exception as e:
        _log("UK OFSI", "error", 0, str(e))
        print(f"[sync] UK OFSI error: {e}")
        return 0

# ─── EU Consolidated ──────────────────────────────────────────────────────────

def sync_eu():
    print("[sync] EU FSF …")
    try:
        resp = fetch_with_retry(EU_URL, timeout=90)
        root = ET.fromstring(resp.content)

        entries = []
        # EU XML: <sanctionEntity><entity><nameAliasList><nameAlias .../>
        for se in root.findall(".//sanctionEntity"):
            subj = se.find(".//subjectType")
            stype = (subj.get("code", "") if subj is not None else "").lower()
            entity_type = "individual" if "person" in stype else "entity"

            reg = se.find(".//regulationSummary")
            listed_on = reg.get("publicationDate", "") if reg is not None else ""

            prog_node = se.find(".//regulationType")
            program   = prog_node.get("code", "") if prog_node is not None else ""

            aliases_list, name = [], ""
            for na in se.findall(".//nameAlias"):
                fn = na.get("firstName", "")
                ln = na.get("lastName",  "")
                wn = na.get("wholeName", "")
                full = wn or (f"{fn} {ln}".strip())
                if full:
                    aliases_list.append(full)
            if aliases_list:
                name    = aliases_list[0]
                aliases = ";".join(aliases_list[1:7])
            if not name:
                continue

            countries = [c.get("isoCode", "") for c in se.findall(".//citizenship")]
            country   = countries[0] if countries else ""

            entries.append(("EU Consolidated", entity_type, name, aliases, country,
                            program, listed_on, "{}"))

        _replace_list("EU Consolidated", entries)
        _log("EU Consolidated", "ok", len(entries))
        print(f"[sync] EU: {len(entries):,} records")
        return len(entries)
    except Exception as e:
        _log("EU Consolidated", "error", 0, str(e))
        print(f"[sync] EU error: {e}")
        return 0

# ─── World Bank Debarment ─────────────────────────────────────────────────────

def sync_world_bank():
    """World Bank Listing of Ineligible Firms and Individuals (Socrata JSON API)."""
    print("[sync] World Bank Debarment …")
    try:
        resp = fetch_with_retry(WB_URL, timeout=60)
        rows = resp.json()
        if not isinstance(rows, list):
            raise ValueError(f"Unexpected response type: {type(rows)}")

        entries = []
        for row in rows:
            name = (row.get("firmname") or row.get("firm_name") or "").strip()
            if not name:
                continue
            country   = (row.get("country") or "").strip()
            address   = (row.get("address") or "").strip()
            from_date = (row.get("fromdate") or row.get("debarment_from_date") or "").strip()
            to_date   = (row.get("todate") or row.get("debarment_to_date") or "").strip()
            grounds   = (row.get("grounds") or row.get("ineligibility_status") or "Debarment").strip()
            status    = (row.get("ineligibilitystatus") or row.get("ineligibility_status") or "").strip()
            details   = json.dumps({
                "address": address,
                "to_date": to_date,
                "status": status,
                "grounds": grounds,
            })
            entries.append((
                "World Bank Debarment", "entity", name, "", country,
                "World Bank Debarment", from_date, details,
            ))

        _replace_list("World Bank Debarment", entries)
        _log("World Bank Debarment", "ok", len(entries))
        print(f"[sync] World Bank Debarment: {len(entries):,} records")
        return len(entries)
    except Exception as e:
        _log("World Bank Debarment", "error", 0, str(e))
        print(f"[sync] World Bank Debarment error: {e}")
        return 0


# ─── US BIS Entity List ───────────────────────────────────────────────────────

def sync_bis_entity_list():
    """US Bureau of Industry and Security Entity List (export control, free CSV)."""
    print("[sync] BIS Entity List …")
    try:
        resp = fetch_with_retry(BIS_URL, timeout=60)
        content = resp.content.decode("utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(content))

        def _col(row, *candidates):
            for c in candidates:
                v = row.get(c, "").strip()
                if v and v not in ("-", "N/A"):
                    return v
            return ""

        entries = []
        for row in reader:
            name = _col(row, "Name", "name")
            if not name:
                continue
            country    = _col(row, "Country", "country")
            city       = _col(row, "City", "city")
            state      = _col(row, "State/Province", "State", "state")
            eff_date   = _col(row, "Effective Date", "effective_date")
            lic_req    = _col(row, "License Required", "license_required")
            lic_policy = _col(row, "License Policy", "license_policy")
            notes      = _col(row, "Country Group/ Notes", "Country Group/Notes", "notes")
            details    = json.dumps({
                "city": city, "state": state,
                "license_required": lic_req,
                "license_policy": lic_policy,
                "notes": notes,
            })
            entries.append((
                "BIS Entity List", "entity", name, "", country,
                "US Export Control (EAR)", eff_date, details,
            ))

        _replace_list("BIS Entity List", entries)
        _log("BIS Entity List", "ok", len(entries))
        print(f"[sync] BIS Entity List: {len(entries):,} records")
        return len(entries)
    except Exception as e:
        _log("BIS Entity List", "error", 0, str(e))
        print(f"[sync] BIS Entity List error: {e}")
        return 0


# ─── Australia DFAT Consolidated Sanctions ───────────────────────────────────

def sync_australia_dfat():
    """Australia DFAT Consolidated Sanctions List (XLSX). Requires openpyxl."""
    print("[sync] Australia DFAT …")
    try:
        import openpyxl  # optional dependency
    except ImportError:
        _log("Australia DFAT", "error", 0, "openpyxl not installed — run: pip install openpyxl")
        print("[sync] Australia DFAT: openpyxl not installed")
        return 0
    try:
        resp = fetch_with_retry(AU_DFAT_URL, timeout=90)
        wb = openpyxl.load_workbook(io.BytesIO(resp.content), read_only=True, data_only=True)
        ws = wb.active

        headers = []
        entries = []
        for i, row in enumerate(ws.iter_rows(values_only=True)):
            if i == 0:
                headers = [str(c).strip() if c else "" for c in row]
                continue

            def _get(key, *alts):
                for k in (key, *alts):
                    try:
                        idx = next(j for j, h in enumerate(headers) if k.lower() in h.lower())
                        v = row[idx]
                        return str(v).strip() if v else ""
                    except StopIteration:
                        continue
                return ""

            name = _get("name", "full name", "entity name", "individual name")
            if not name or name.lower() in ("none", ""):
                continue

            entity_type = "individual" if "individual" in _get("type").lower() else "entity"
            country     = _get("nationality", "country", "address")
            regime      = _get("regime", "sanction regime", "category")
            listed_on   = _get("listed", "date", "listing date")
            aliases_raw = _get("alias", "other names", "also known as")

            entries.append((
                "Australia DFAT", entity_type, name,
                aliases_raw, country, regime, listed_on, "{}",
            ))
        wb.close()

        _replace_list("Australia DFAT", entries)
        _log("Australia DFAT", "ok", len(entries))
        print(f"[sync] Australia DFAT: {len(entries):,} records")
        return len(entries)
    except Exception as e:
        _log("Australia DFAT", "error", 0, str(e))
        print(f"[sync] Australia DFAT error: {e}")
        return 0


# ─── PEP screening (OpenSanctions API) ───────────────────────────────────────

def screen_pep(name):
    """
    Query OpenSanctions for PEP matches.
    Free tier works without a key (rate-limited).
    Set OPENSANCTIONS_API_KEY for production volumes.
    Returns list of match dicts.
    """
    results = []
    api_key = os.getenv("OPENSANCTIONS_API_KEY", "")
    headers = {"Authorization": f"ApiKey {api_key}"} if api_key else {}

    try:
        resp = _requests.get(
            f"{OS_API}/search/default",
            params={"q": name, "schema": "Person", "topics": "pep", "limit": 10},
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            for r in (data.get("results") or []):
                props = r.get("properties", {})
                results.append({
                    "name":        r.get("caption", name),
                    "aliases":     "; ".join((props.get("alias") or [])[:5]),
                    "position":    "; ".join((props.get("position") or [])[:3]),
                    "nationality": "; ".join((props.get("nationality") or [])[:3]),
                    "birth_date":  "; ".join((props.get("birthDate") or [])[:2]),
                    "country":     "; ".join((props.get("country") or [])[:3]),
                    "topics":      ", ".join(r.get("topics", [])),
                    "datasets":    ", ".join((r.get("datasets") or [])[:3]),
                    "score":       r.get("score", 0),
                    "url":         f"https://www.opensanctions.org/entities/{r.get('id','')}",
                })
        elif resp.status_code == 429:
            results.append({"error": "rate_limited",
                            "message": "OpenSanctions rate limit reached. Set OPENSANCTIONS_API_KEY for higher limits."})
        elif resp.status_code == 402:
            results.append({"error": "api_key_required",
                            "message": "Set OPENSANCTIONS_API_KEY for PEP screening."})
    except Exception as e:
        print(f"[pep] OpenSanctions error: {e}")

    return results

# ─── Full sync orchestrator ───────────────────────────────────────────────────

def run_full_sync():
    results = {}
    results["ofac"]         = sync_ofac_sdn()
    results["un"]           = sync_un_sc()
    results["uk"]           = sync_uk_ofsi()
    results["eu"]           = sync_eu()
    results["world_bank"]   = sync_world_bank()
    results["bis"]          = sync_bis_entity_list()
    results["australia"]    = sync_australia_dfat()
    return results

def get_sync_status():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute("SELECT * FROM sync_status ORDER BY list_name").fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
    finally:
        con.close()

def start_sync_thread():
    """Run a full sync 30 s after startup, then every 24 h."""
    def loop():
        time.sleep(30)
        while True:
            try:
                print("[sync] Starting scheduled sync …")
                run_full_sync()
                print("[sync] Scheduled sync complete.")
            except Exception as e:
                print(f"[sync] Thread error: {e}")
            time.sleep(86400)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return t

# ─── Flask blueprint ──────────────────────────────────────────────────────────

from flask import Blueprint, jsonify, request
from flask_login import login_required

sync_bp = Blueprint("sync", __name__)

@sync_bp.route("/api/sync/status", methods=["GET"])
@login_required
def api_sync_status():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    by_list = con.execute(
        "SELECT list_name, COUNT(*) as cnt FROM sanctions_entities GROUP BY list_name"
    ).fetchall()
    pep_enabled = bool(os.getenv("OPENSANCTIONS_API_KEY", ""))
    log = con.execute(
        "SELECT * FROM sync_log ORDER BY synced_at DESC LIMIT 20"
    ).fetchall()
    con.close()
    return jsonify({
        "sync_status":      get_sync_status(),
        "sanctions_by_list": [dict(r) for r in by_list],
        "pep_api_enabled":  pep_enabled,
        "log":              [dict(r) for r in log],
    })

@sync_bp.route("/api/sync/run", methods=["POST"])
@login_required
def api_sync_run():
    threading.Thread(target=run_full_sync, daemon=True).start()
    return jsonify({"ok": True, "message": "Sync started in background — check status in ~2 minutes."})

@sync_bp.route("/api/pep/search", methods=["POST"])
@login_required
def api_pep_search():
    data  = request.get_json(force=True)
    query = (data.get("query") or "").strip()
    if not query or len(query) < 2:
        return jsonify({"error": "Query too short"}), 400
    results = screen_pep(query)
    return jsonify({"query": query, "hits": len(results), "results": results})
