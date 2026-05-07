import json
import os
import sqlite3
from datetime import datetime, timedelta
from flask import (Blueprint, redirect, url_for, request, jsonify,
                   render_template, current_app)
from flask_login import login_required, current_user

billing_bp = Blueprint("billing", __name__)

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "sanctions.db"))

PLANS = {
    "starter": {
        "name": "Starter",
        "price": 49,
        "description": "For individual analysts",
        "features": [
            "1 user seat",
            "50 entity screens / day",
            "OFAC, EU, UN & UK lists",
            "Compliance alerts & news feed",
            "Watchlist up to 10 items",
            "Email support",
        ],
        "highlight": False,
        "cta": "Start 14-day free trial",
    },
    "professional": {
        "name": "Professional",
        "price": 149,
        "description": "For compliance teams",
        "features": [
            "5 user seats",
            "Unlimited entity screens",
            "OFAC, EU, UN & UK lists",
            "Priority alerts & real-time news",
            "Unlimited watchlist",
            "CSV export",
            "Priority support",
        ],
        "highlight": True,
        "cta": "Start 14-day free trial",
    },
}

# ─── Subscription helpers ─────────────────────────────────────────────────────

def get_subscription(user_id):
    """Return dict with status, plan, trial_days_left for a user."""
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "SELECT subscription_status, subscription_plan, trial_ends_at FROM users WHERE id=?",
        (user_id,)
    ).fetchone()
    con.close()
    if not row:
        return {"status": "trialing", "plan": None, "trial_days_left": 14}

    status = row["subscription_status"] or "trialing"
    trial_days_left = None

    if status == "trialing" and row["trial_ends_at"]:
        try:
            end = datetime.fromisoformat(row["trial_ends_at"])
            remaining = (end - datetime.utcnow()).days
            trial_days_left = max(0, remaining)
            if datetime.utcnow() > end:
                status = "expired"
        except Exception:
            pass

    return {
        "status": status,
        "plan": row["subscription_plan"],
        "trial_days_left": trial_days_left,
    }

def subscription_active(user_id):
    return get_subscription(user_id)["status"] in ("active", "trialing")

def _stripe():
    import stripe as _s
    _s.api_key = os.getenv("STRIPE_SECRET_KEY", "")
    return _s

def _get_or_create_customer(user):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT stripe_customer_id FROM users WHERE id=?", (user.id,)).fetchone()
    cid = row["stripe_customer_id"] if row else None
    con.close()
    if cid:
        return cid
    s = _stripe()
    customer = s.Customer.create(email=user.email, name=user.name,
                                  metadata={"user_id": str(user.id)})
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE users SET stripe_customer_id=? WHERE id=?", (customer.id, user.id))
    con.commit()
    con.close()
    return customer.id

# ─── Routes ───────────────────────────────────────────────────────────────────

@billing_bp.route("/pricing")
def pricing():
    sub = None
    if current_user.is_authenticated:
        sub = get_subscription(current_user.id)
    return render_template("pricing.html", plans=PLANS, user=current_user, sub=sub)

@billing_bp.route("/billing/checkout/<plan>", methods=["POST"])
@login_required
def create_checkout(plan):
    s = _stripe()
    if not s.api_key or plan not in PLANS:
        return redirect(url_for("billing.pricing"))
    price_id = os.getenv(f"STRIPE_PRICE_{plan.upper()}", "")
    if not price_id:
        current_app.logger.error(f"STRIPE_PRICE_{plan.upper()} not set")
        return redirect(url_for("billing.pricing"))
    cid = _get_or_create_customer(current_user)
    session = s.checkout.Session.create(
        customer=cid,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        allow_promotion_codes=True,
        subscription_data={
            "trial_period_days": 14,
            "metadata": {"plan": plan, "user_id": str(current_user.id)},
        },
        success_url=url_for("billing.checkout_success", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=url_for("billing.pricing", _external=True),
        metadata={"user_id": str(current_user.id), "plan": plan},
    )
    return redirect(session.url, code=303)

@billing_bp.route("/billing/success")
@login_required
def checkout_success():
    return render_template("billing_success.html", user=current_user)

@billing_bp.route("/billing/portal", methods=["POST"])
@login_required
def customer_portal():
    s = _stripe()
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT stripe_customer_id FROM users WHERE id=?", (current_user.id,)).fetchone()
    con.close()
    if not row or not row["stripe_customer_id"]:
        return redirect(url_for("billing.pricing"))
    portal = s.billing_portal.Session.create(
        customer=row["stripe_customer_id"],
        return_url=url_for("index", _external=True),
    )
    return redirect(portal.url, code=303)

@billing_bp.route("/billing/webhook", methods=["POST"])
def webhook():
    """Stripe webhook — no auth required, called by Stripe's servers."""
    s = _stripe()
    payload = request.get_data()
    sig = request.headers.get("Stripe-Signature", "")
    secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    try:
        if secret:
            event = s.Webhook.construct_event(payload, sig, secret)
        else:
            event = s.Event.construct_from(json.loads(payload), s.api_key)
    except Exception as e:
        current_app.logger.error(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 400
    _process_event(event)
    return jsonify({"ok": True})

def _process_event(event):
    con = sqlite3.connect(DB_PATH)
    t = event["type"]
    d = event["data"]["object"]

    if t == "checkout.session.completed":
        uid = d.get("metadata", {}).get("user_id")
        plan = d.get("metadata", {}).get("plan", "starter")
        sub_id = d.get("subscription")
        if uid:
            con.execute(
                "UPDATE users SET stripe_subscription_id=?, subscription_status='trialing', subscription_plan=? WHERE id=?",
                (sub_id, plan, uid),
            )

    elif t in ("customer.subscription.updated", "customer.subscription.created"):
        ends = datetime.fromtimestamp(d["current_period_end"]).isoformat() if d.get("current_period_end") else None
        trial_end = datetime.fromtimestamp(d["trial_end"]).isoformat() if d.get("trial_end") else None
        con.execute(
            """UPDATE users
               SET subscription_status=?, subscription_ends_at=?,
                   trial_ends_at=COALESCE(trial_ends_at, ?), stripe_subscription_id=?
               WHERE stripe_customer_id=?""",
            (d["status"], ends, trial_end, d["id"], d["customer"]),
        )

    elif t == "customer.subscription.deleted":
        con.execute(
            "UPDATE users SET subscription_status='canceled' WHERE stripe_customer_id=?",
            (d["customer"],),
        )

    elif t == "invoice.payment_failed":
        con.execute(
            "UPDATE users SET subscription_status='past_due' WHERE stripe_customer_id=?",
            (d["customer"],),
        )

    elif t == "invoice.paid":
        con.execute(
            "UPDATE users SET subscription_status='active' WHERE stripe_customer_id=?",
            (d["customer"],),
        )

    con.commit()
    con.close()
