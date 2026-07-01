"""
Groove Therapy — a small independent vinyl record store.

Nothing in this file is aware of the exploit. It is a normal Flask app with
a catalogue, a login, a user account page, and a publicly-visible customer
reviews feature. The same shape as a thousand small e-commerce apps.

The only reason this app matters for the PoC is that it has a `POST /api/review`
endpoint that stores request bodies and exposes them on a `/reviews` page —
which is how 90% of small shops handle reviews. When a body arrives that was
"actually" a smuggled victim HTTP request, the handler does the same thing it
always does: stores it and shows it. The exploit lives in Varnish's HPACK
dispatcher, not here.
"""
import base64
import hmac
from datetime import datetime, timezone
from functools import wraps
from hashlib import sha256

from flask import (
    Flask, render_template, request, redirect, make_response,
    abort, g, jsonify,
)
from flask.sessions import SessionInterface, SessionMixin

app = Flask(__name__)


# ─── Disable Flask's session machinery entirely ─────────────────────────────
# Auth on this site is HTTP Basic; nothing reads or writes Flask's session
# object, and we don't want a stray `Set-Cookie: session=...` slipping onto a
# response because something deep in Flask or a template accessed the session
# dict. Installing a null session interface guarantees no session cookie is
# ever emitted — so every authenticated request is identified purely by the
# `Authorization: Basic` header, which is exactly what the demo needs.
class _NullSession(dict, SessionMixin):
    permanent = False
    new = False
    modified = False
    accessed = False


class _NullSessionInterface(SessionInterface):
    def open_session(self, app, request):
        return _NullSession()

    def save_session(self, app, session, response):
        pass


app.session_interface = _NullSessionInterface()


@app.before_request
def _log_request():
    from sys import stderr
    print(f"  [backend] {request.method} {request.path[:60]} "
          f"cl={request.content_length} "
          f"host={request.headers.get('Host','?')[:30]} "
          f"auth={request.headers.get('Authorization','-')[:40]}",
          file=stderr, flush=True)

# ─── Catalogue ──────────────────────────────────────────────────────────────
# Representative classic / modern albums. Cover art is stylised placeholder
# SVG (see static/cover.svg / rendered in-template), so no copyright concern.
CATALOGUE = [
    dict(id="dsotm", artist="Pink Floyd",       title="The Dark Side of the Moon", year=1973, price=32.0,  hue=0,   genre="Progressive rock"),
    dict(id="kob",   artist="Miles Davis",      title="Kind of Blue",               year=1959, price=28.0,  hue=210, genre="Modal jazz"),
    dict(id="abbey", artist="The Beatles",      title="Abbey Road",                 year=1969, price=34.0,  hue=42,  genre="Rock"),
    dict(id="rum",   artist="Fleetwood Mac",    title="Rumours",                    year=1977, price=27.0,  hue=18,  genre="Soft rock"),
    dict(id="iv",    artist="Led Zeppelin",     title="IV",                         year=1971, price=30.0,  hue=5,   genre="Hard rock"),
    dict(id="ziggy", artist="David Bowie",      title="The Rise and Fall of Ziggy Stardust", year=1972, price=29.0, hue=330, genre="Glam rock"),
    dict(id="sikl",  artist="Stevie Wonder",    title="Songs in the Key of Life",   year=1976, price=38.0,  hue=145, genre="Soul / funk"),
    dict(id="blue",  artist="Joni Mitchell",    title="Blue",                       year=1971, price=25.0,  hue=220, genre="Folk"),
    dict(id="wgon",  artist="Marvin Gaye",      title="What's Going On",            year=1971, price=26.0,  hue=195, genre="Soul"),
    dict(id="okc",   artist="Radiohead",        title="OK Computer",                year=1997, price=32.0,  hue=265, genre="Alternative"),
    dict(id="autob", artist="Kraftwerk",        title="Autobahn",                   year=1974, price=24.0,  hue=0,   genre="Electronic"),
]
CATALOGUE_BY_ID = {r["id"]: r for r in CATALOGUE}

# ─── User database (toy) ────────────────────────────────────────────────────
# Single pre-registered user, password hashed (not plain) just to look real.
def _hash(pw):  # not security advice — just a stable hash
    return sha256(b"groove::" + pw.encode()).hexdigest()

USERS = {
    "alice": {
        "name": "Alice Martin",
        "pw_hash": _hash("i_love_c_programming"),
        "email": "alice.martin@example.com",
        "joined": "March 2022",
        "orders": [
            {"id": "GT-1021", "date": "2026-03-14", "item": "Fleetwood Mac — Rumours", "status": "Delivered"},
            {"id": "GT-1088", "date": "2026-04-02", "item": "Radiohead — OK Computer", "status": "Shipped"},
        ],
    }
}

# ─── In-memory data ─────────────────────────────────────────────────────────
# Pre-populated with a handful of real-looking reviews so the /reviews page
# isn't empty. New reviews (including ones smuggled via the exploit) append.
REVIEWS = [
    {"time": datetime(2026, 3, 12, 14, 7, tzinfo=timezone.utc),
     "name": "Marcus L.",
     "text": "Picked up Kind of Blue last Saturday. Quality pressing, arrived in 3 days. The sleeve had a small corner ding but the team threw in a free inner sleeve. Will be back."},
    {"time": datetime(2026, 3, 18, 9, 42, tzinfo=timezone.utc),
     "name": "Priya R.",
     "text": "I have been looking for a decent copy of Blue for years. Groove Therapy's 180g reissue is perfect. Five stars."},
    {"time": datetime(2026, 3, 24, 11, 16, tzinfo=timezone.utc),
     "name": "Dom",
     "text": "Dark Side of the Moon. Arrived with a warped seam that the shop replaced same-day. This is how customer service should work."},
    {"time": datetime(2026, 4, 1, 20, 1, tzinfo=timezone.utc),
     "name": "Sarah T.",
     "text": "Huge selection of jazz — I found a Coltrane reissue here I couldn't get anywhere else in town. Prices are fair. The staff actually know the records."},
    {"time": datetime(2026, 4, 9, 17, 33, tzinfo=timezone.utc),
     "name": "K.",
     "text": "Abbey Road half-speed master — pristine. Side two sounds like I've never heard it before."},
]


# ─── HTTP Basic authentication ──────────────────────────────────────────────
# The site authenticates users with HTTP Basic. Every authenticated request
# carries an `Authorization: Basic <base64(user:pass)>` header. The browser
# shows its native sign-in dialog the first time the user reaches a protected
# endpoint, caches the credentials for the tab, and auto-includes them on
# every subsequent same-origin request (including fetch() from the bell
# poller). See templates/base.html for the frontend side.
REALM = "Groove Therapy"


def _check_basic(username: str, password: str):
    user = USERS.get(username)
    if not user:
        return None
    if not hmac.compare_digest(user["pw_hash"], _hash(password)):
        return None
    return user


def _parse_basic_auth(header: str):
    """Decode an `Authorization: Basic <b64>` header into (user, pass) or
    (None, None) if absent/malformed. Kept lenient on padding to mirror what
    browsers actually send."""
    if not header or not header.lower().startswith("basic "):
        return None, None
    try:
        raw = base64.b64decode(header[6:].strip() + "===", validate=False)
        decoded = raw.decode("utf-8", errors="replace")
    except Exception:
        return None, None
    if ":" not in decoded:
        return None, None
    u, p = decoded.split(":", 1)
    return u.strip().lower(), p


@app.before_request
def load_user():
    g.user = None
    u, p = _parse_basic_auth(request.headers.get("Authorization", ""))
    if u is not None:
        g.user = _check_basic(u, p)


def _challenge(msg: str = "Authentication required"):
    resp = make_response(msg, 401)
    resp.headers["WWW-Authenticate"] = f'Basic realm="{REALM}"'
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    return resp


def requires_auth(fn):
    """View decorator: 401 + WWW-Authenticate when the request is not
    Basic-authenticated as a known user."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not g.user:
            return _challenge()
        return fn(*args, **kwargs)
    return wrapper


# ─── Routes ─────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    featured = CATALOGUE[:6]
    newarr = CATALOGUE[6:12]
    return render_template("index.html", featured=featured, newarr=newarr)


@app.route("/store")
def store():
    q = request.args.get("q", "").strip().lower()
    if q:
        items = [r for r in CATALOGUE if q in r["artist"].lower() or q in r["title"].lower()]
    else:
        items = CATALOGUE
    return render_template("store.html", items=items, q=q)


@app.route("/record/<rid>")
def record(rid):
    r = CATALOGUE_BY_ID.get(rid)
    if not r:
        abort(404)
    return render_template("record.html", r=r)


@app.route("/login")
@requires_auth
def login():
    # With Basic Auth there is no login form — the browser prompts natively
    # when it hits a 401. This route exists only so the nav's "Sign in"
    # link has a target; once the user authenticates it redirects onward.
    return redirect(request.args.get("next", "/account"))


@app.route("/account")
@requires_auth
def account():
    return render_template("account.html", user=g.user)


@app.route("/reviews")
def reviews():
    return render_template("reviews.html", reviews=list(reversed(REVIEWS)))


@app.route("/api/review", methods=["POST"])
def api_review():
    """Submit a customer review.

    Accepts the review text as the raw request body. For a normal review
    there is also a `name` form field; when absent we fall back to "Anonymous".
    """
    body = request.get_data(as_text=False) or b""
    name = request.form.get("name", "").strip() or "Anonymous"
    # Best-effort: if the body is form-encoded with a 'text' field, extract it.
    text = request.form.get("text")
    if text is None:
        # Treat the entire raw body as the review text.
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            text = body.decode("latin-1", errors="replace")
    REVIEWS.append({"time": datetime.now(timezone.utc), "name": name, "text": text})
    if request.form:
        return redirect("/reviews?submitted=1")
    return "Thanks for your review.\n", 200, {"Content-Type": "text/plain"}


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/api/account/notifications", methods=["POST"])
@requires_auth
def api_account_notifications():
    """Live notifications for the bell badge and order-status widget.

    Pattern used by every modern shop: the client POSTs the IDs of
    notifications it has already acknowledged plus some light device
    context, the server returns the current unread count and any new
    order-status / wishlist / restock events. The POST shape (rather than
    GET) is standard because polling typically both *reads* and *records*
    a 'last seen' cursor in the same round-trip.
    """
    # Build plausible updates from alice's open orders + a couple of
    # wishlist / restock pings. Entirely static for the demo, but shaped
    # exactly like a production payload.
    updates = []
    for o in g.user.get("orders", []):
        updates.append({
            "id":    f"n_order_{o['id']}",
            "kind":  "order",
            "ref":   o["id"],
            "title": f"Order {o['id']}: {o['status']}",
            "body":  o["item"],
            "at":    o["date"] + "T09:15:00Z",
        })
    updates.append({
        "id":    "n_restock_blue",
        "kind":  "restock",
        "ref":   "blue",
        "title": "Back in stock: Blue (Joni Mitchell)",
        "body":  "You wishlisted this record on 15 Feb.",
        "at":    "2026-04-19T14:05:00Z",
    })
    updates.append({
        "id":    "n_pricedrop_wgon",
        "kind":  "wishlist",
        "ref":   "wgon",
        "title": "Price drop: What's Going On (Marvin Gaye)",
        "body":  "Now £24 (was £26). Limited stock.",
        "at":    "2026-04-17T10:42:00Z",
    })

    # Count anything the client hasn't acked as unread.
    body = request.get_json(silent=True) or {}
    seen = set(body.get("seen", []) or [])
    unread = sum(1 for u in updates if u["id"] not in seen)
    return jsonify({"unread": unread, "updates": updates})


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
