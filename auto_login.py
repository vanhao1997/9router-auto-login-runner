"""
Auto-login ChatGPT accounts via OAuth PKCE flow.
Uses Playwright to automate browser login, fills email/password/2FA,
catches the OAuth callback, and imports refresh_token into 9router.

Input format (one per line):
  email|password|2fa_secret

Usage:
  python auto_login.py accounts.txt           # headless
  python auto_login.py accounts.txt --headed   # show browser
  python auto_login.py accounts.txt --slow     # slow mode for debugging
"""

import sys
import os
import json
import time
import re
import base64
import hashlib
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# Force UTF-8 + unbuffered output on Windows so server.py receives log
# lines in real-time instead of waiting for Python's pipe buffer.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)
else:
    # On non-Windows, ensure line-buffered output
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

# ---------- TOTP ----------
try:
    import pyotp
except ImportError:
    print("[!] pyotp not installed. Run: python -m pip install pyotp")
    sys.exit(1)

# ---------- Playwright ----------
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("[!] playwright not installed. Run: python -m pip install playwright && python -m playwright install chromium")
    sys.exit(1)

# ---------- OAuth Config (same as 9router) ----------
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
SCOPE = "openid profile email offline_access"
CALLBACK_PORT = 1455
REDIRECT_URI = f"http://localhost:{CALLBACK_PORT}/auth/callback"
IMPORT_API = os.environ.get("N9ROUTER_IMPORT_API", "http://localhost:9876/api/import").rstrip("/")
IMPORT_API_KEY = os.environ.get("N9ROUTER_IMPORT_API_KEY", "").strip()
IMPORT_FORMAT = os.environ.get("N9ROUTER_IMPORT_FORMAT", "local").strip().lower()
IMPORT_AUTH_MODE = os.environ.get("N9ROUTER_IMPORT_AUTH_MODE", "api-key").strip().lower()
DASHBOARD_PASSWORD = os.environ.get("N9ROUTER_DASHBOARD_PASSWORD", "")
DASHBOARD_LOGIN_URL = os.environ.get("N9ROUTER_DASHBOARD_LOGIN_URL", "").strip()
DEBUG_SCREENSHOTS = os.environ.get("AUTO_LOGIN_DEBUG", "false").strip().lower() in ("1", "true", "yes")
_remote_import_lock = threading.RLock()
_remote_import_cookie = None

# ---------- PKCE ----------
def generate_pkce():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def build_auth_url():
    """Build a fresh OAuth URL using the registered Codex callback URI."""
    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(16)
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "originator": "codex_cli_rs",
    }
    return AUTH_URL + "?" + urlencode(params), verifier, state


def exchange_code(code, verifier):
    body = json.dumps({
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    }).encode()
    req = Request(TOKEN_URL, data=body, headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    try:
        resp = urlopen(req, timeout=30)
        return json.loads(resp.read().decode()), None
    except HTTPError as e:
        return None, f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:200]}"
    except Exception as e:
        return None, str(e)


def decode_jwt_email(access_token):
    try:
        parts = access_token.split(".")
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = json.loads(base64.urlsafe_b64decode(payload))
        prof = decoded.get("https://api.openai.com/profile", {})
        auth = decoded.get("https://api.openai.com/auth", {})
        return {
            "email": prof.get("email", ""),
            "account_id": auth.get("chatgpt_account_id", ""),
            "plan_type": auth.get("chatgpt_plan_type", ""),
        }
    except:
        return {"email": "", "account_id": "", "plan_type": ""}


def tokens_to_connection(tokens):
    at = tokens.get("access_token", "")
    info = decode_jwt_email(at)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    exp_in = tokens.get("expires_in", 864000)
    exp_at = datetime.fromtimestamp(
        time.time() + exp_in, tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return {
        "accessToken": at,
        "refreshToken": tokens.get("refresh_token", ""),
        "idToken": tokens.get("id_token", ""),
        "expiresAt": exp_at,
        "expiresIn": exp_in,
        "testStatus": "active",
        "lastUsedAt": now,
        "consecutiveUseCount": 0,
        "backoffLevel": 0,
        "providerSpecificData": {
            "chatgptAccountId": info["account_id"],
            "chatgptPlanType": info["plan_type"],
        },
        "lastError": None,
        "lastErrorAt": None,
        "email": info["email"],
        "name": info["email"],
        "provider": "codex",
        "authType": "oauth",
    }


def _dashboard_login_url():
    if DASHBOARD_LOGIN_URL:
        return DASHBOARD_LOGIN_URL
    parsed = urlparse(IMPORT_API)
    return "{}://{}/api/auth/login".format(parsed.scheme, parsed.netloc)


def _remote_import_headers(refresh_session=False):
    global _remote_import_cookie
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if IMPORT_FORMAT != "codex-bulk":
        return headers, None
    if IMPORT_AUTH_MODE == "api-key":
        if not IMPORT_API_KEY:
            return None, "N9ROUTER_IMPORT_API_KEY is required for api-key import"
        headers["Authorization"] = "Bearer {}".format(IMPORT_API_KEY)
        return headers, None
    if IMPORT_AUTH_MODE != "dashboard-password":
        return None, "N9ROUTER_IMPORT_AUTH_MODE must be api-key or dashboard-password"
    if not DASHBOARD_PASSWORD:
        return None, "N9ROUTER_DASHBOARD_PASSWORD is required for dashboard-password import"

    with _remote_import_lock:
        if refresh_session:
            _remote_import_cookie = None
        if not _remote_import_cookie:
            request = Request(
                _dashboard_login_url(),
                data=json.dumps({"password": DASHBOARD_PASSWORD}).encode("utf-8"),
                headers={"Content-Type": "application/json; charset=utf-8"},
            )
            try:
                response = urlopen(request, timeout=15)
                cookie_values = response.headers.get_all("Set-Cookie") or []
                _remote_import_cookie = next(
                    (value.split(";", 1)[0] for value in cookie_values if value.startswith("auth_token=")),
                    None,
                )
            except HTTPError as error:
                return None, "Dashboard login failed (HTTP {})".format(error.code)
            except Exception as error:
                return None, "Dashboard login failed: {}".format(type(error).__name__)
        if not _remote_import_cookie:
            return None, "Dashboard login did not return an auth session"
        headers["Cookie"] = _remote_import_cookie
        return headers, None


def import_to_9router(conn):
    """Import one connection into local 9router or the authenticated V1 API."""
    if IMPORT_FORMAT == "codex-bulk":
        payload = {"accounts": [conn]}
    else:
        payload = {"connections": [conn]}
    for attempt in range(2):
        headers, config_error = _remote_import_headers(refresh_session=attempt > 0)
        if config_error:
            return None, config_error
        req = Request(IMPORT_API, data=json.dumps(payload).encode("utf-8"), headers=headers)
        try:
            resp = urlopen(req, timeout=15)
            payload = json.loads(resp.read().decode("utf-8"))
            if IMPORT_FORMAT == "codex-bulk":
                if payload.get("failed", 0) or payload.get("success", 0) != 1:
                    results = payload.get("results") or []
                    detail = "; ".join(str(item.get("error", "import failed")) for item in results if not item.get("ok"))
                    return None, detail or "remote Codex bulk import failed"
                return payload, None
            if not payload.get("sqliteVerified"):
                detail = "; ".join(payload.get("errors") or []) or "email not verified in 9router SQLite"
                return None, detail
            return payload, None
        except HTTPError as error:
            if IMPORT_AUTH_MODE == "dashboard-password" and error.code == 401 and attempt == 0:
                continue
            return None, "HTTP {} from import API".format(error.code)
        except Exception as error:
            return None, "{}: {}".format(type(error).__name__, str(error))


# ---------- Shared callback dispatcher ----------
class CallbackResult:
    def __init__(self):
        self.code = None
        self.state = None
        self.error = None
        self.done = threading.Event()


_callback_results = {}
_callback_lock = threading.RLock()
_callback_server = None
_callback_thread = None


class CallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/auth/callback":
            self.send_response(404)
            self.end_headers()
            return
        params = parse_qs(parsed.query)
        state = params.get("state", [None])[0]
        with _callback_lock:
            result = _callback_results.get(state)
        if not result:
            self.send_response(400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write("<html><body>OAuth callback khong hop le hoac da het han.</body></html>".encode("utf-8"))
            return
        result.code = params.get("code", [None])[0]
        result.state = state
        result.error = params.get("error", [None])[0]
        result.done.set()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write("<html><body style='font-family:system-ui;background:#1a1a2e;color:#e0e0e0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0'><div style='text-align:center'><h2>✅ Thành công!</h2><p>Vui lòng không tắt, để nó tự động hoàn tất.</p></div></body></html>".encode("utf-8"))


def start_callback_dispatcher():
    """Start exactly one server on OpenAI's registered callback port."""
    global _callback_server, _callback_thread
    with _callback_lock:
        if _callback_server:
            return
        class ReusableHTTPServer(HTTPServer):
            allow_reuse_address = True
        _callback_server = ReusableHTTPServer(("127.0.0.1", CALLBACK_PORT), CallbackHandler)
        _callback_thread = threading.Thread(target=_callback_server.serve_forever, daemon=True)
        _callback_thread.start()


def stop_callback_dispatcher():
    global _callback_server, _callback_thread
    with _callback_lock:
        server = _callback_server
        _callback_server = None
        _callback_thread = None
        _callback_results.clear()
    if server:
        server.shutdown()
        server.server_close()


def register_callback(state):
    result = CallbackResult()
    with _callback_lock:
        _callback_results[state] = result
    return result


def unregister_callback(state):
    with _callback_lock:
        _callback_results.pop(state, None)


# ---------- Browser automation ----------
def debug_page(page, label):
    """Save screenshot + log page URL/title for debugging login flow."""
    if not DEBUG_SCREENSHOTS:
        return
    try:
        safe = ''.join(c if c.isalnum() or c in ('_', '-') else '_' for c in label)[:60]
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"debug_{safe}.png")
        page.screenshot(path=path, full_page=True)
        print(f"    [debug] {label}: title={page.title()!r} url={page.url}")
        print(f"    [debug] screenshot: {path}")
    except Exception as e:
        print(f"    [debug] failed: {e}")


def _first_visible_locator(page, selectors):
    """Return first visible locator across the page and its active frames."""
    frames = [page]
    try:
        frames.extend(page.frames)
    except Exception:
        pass
    for frame in frames:
        for selector in selectors:
            try:
                locator = frame.locator(selector).first
                if locator.is_visible():
                    return locator
            except Exception:
                pass
    return None


def _safe_auth_page_state(page, checkpoint):
    """Log auth-page signals without page content, query strings, or credentials."""
    try:
        parsed = urlparse(page.url)
        host = parsed.hostname or "unknown"
        path = parsed.path or "/"
    except Exception:
        host, path = "unknown", "/"

    try:
        # Titles should not contain credentials, but redact email-like values anyway.
        title = re.sub(r"[^\s@]+@[^\s@]+", "[redacted-email]", page.title() or "")
        title = re.sub(r"[\r\n\t]+", " ", title).strip()[:120] or "untitled"
    except Exception:
        title = "unavailable"

    checks = {
        "captcha": [
            'iframe[src*="turnstile"]',
            'iframe[src*="captcha"]',
            '[data-testid*="captcha" i]',
        ],
        "cloudflare_challenge": [
            'iframe[src*="challenges.cloudflare.com"]',
            'form#challenge-form',
            '#challenge-running',
            'input[name*="cf-turnstile-response" i]',
        ],
        "account_chooser": [
            'a[href*="log-in-or-create-account"]',
            'a:has-text("Log in to another account")',
        ],
        "verification_code": [
            'input[autocomplete="one-time-code"]',
            'input[name*="otp" i]',
            'input[name*="code" i]',
        ],
        "email_field": [
            'input[autocomplete="email"]',
            'input[type="email"]',
            'input[data-login-web-auth-control="true"]',
        ],
        "password_field": [
            'input[type="password"]',
            'input[autocomplete="current-password"]',
        ],
    }
    flags = [name for name, selectors in checks.items() if _first_visible_locator(page, selectors)]
    # Cloudflare's interstitial often exposes only this title, especially in headless Chromium.
    if "cloudflare_challenge" not in flags and title.lower().startswith(("just a moment", "attention required")):
        flags.append("cloudflare_challenge")
    flags_text = ",".join(flags) if flags else "none"
    print(
        "    [auth-state] checkpoint={} host={} path={} title={!r} flags={}".format(
            checkpoint, host, path, title, flags_text
        ),
        flush=True,
    )
    return set(flags)


def _password_step_error(page):
    """Explain common OpenAI branches without logging account data or page text."""
    if _first_visible_locator(page, [
        'button:has-text("Continue with Google")',
        'button:has-text("Continue with Apple")',
        'button:has-text("Continue with Microsoft")',
    ]):
        return (
            "OpenAI requested a Google, Apple, or Microsoft sign-in instead of an "
            "email/password form. Use Manual Login for this account."
        )
    if _first_visible_locator(page, [
        'iframe[src*="turnstile"]',
        'iframe[src*="captcha"]',
        '[data-testid*="captcha" i]',
        'text=/verify you are human|security check|captcha/i',
    ]):
        return "OpenAI requested a CAPTCHA or security check. VPS auto-login cannot complete it; use a workstation browser/manual OAuth flow."
    if _first_visible_locator(page, [
        'input[autocomplete="one-time-code"]',
        'input[name*="otp" i]',
        'input[name*="code" i]',
    ]):
        return "OpenAI requested a verification code before the password step. Use Manual Login for this account."
    if _first_visible_locator(page, [
        'a[href*="log-in-or-create-account"]',
        'a:has-text("Log in to another account")',
    ]):
        return "OpenAI showed its account chooser. Retry once; the runner will select Log in to another account."
    return "OpenAI did not show a password form. VPS auto-login cannot continue; use a workstation browser/manual OAuth flow for this account."


def _email_step_error(page, flags=None):
    """Return a safe explanation when OpenAI does not render the email form."""
    flags = flags or set()
    if "cloudflare_challenge" in flags:
        return "OpenAI showed a Cloudflare challenge before email. VPS auto-login cannot complete it; use a workstation browser/manual OAuth flow."
    if _first_visible_locator(page, [
        'iframe[src*="turnstile"]',
        'iframe[src*="captcha"]',
        '[data-testid*="captcha" i]',
        'text=/verify you are human|security check|captcha/i',
    ]):
        return "OpenAI requested a CAPTCHA or security check before email. VPS auto-login cannot complete it; use a workstation browser/manual OAuth flow."
    if _first_visible_locator(page, [
        'a[href*="log-in-or-create-account"]',
        'a:has-text("Log in to another account")',
    ]):
        return "OpenAI showed its account chooser instead of the email form. Retry once; the runner will select Log in to another account."
    return "OpenAI did not show an email form. Retry once; if it repeats, see the safe [auth-state] deployment log for the detected page state."


def click_first_visible(page, selectors, timeout=3000):
    """Click the first visible selector from a list. Races all selectors."""
    import time as _time
    # Quick check: any already visible?
    locator = _first_visible_locator(page, selectors)
    if locator:
        try:
            locator.click()
            return True
        except Exception:
            pass
    # Poll until timeout
    deadline = _time.time() + timeout / 1000
    while _time.time() < deadline:
        locator = _first_visible_locator(page, selectors)
        if locator:
            try:
                locator.click()
                return True
            except Exception:
                pass
        _time.sleep(0.1)
    return False


def fill_first_visible(page, selectors, value, timeout=12000):
    """Fill the first visible input from a list. Races all selectors at once."""
    # Strategy 1: Try an already-visible field, including embedded auth frames.
    try:
        locator = _first_visible_locator(page, selectors)
        if locator:
            locator.fill(value)
            return locator
    except Exception:
        pass

    # Strategy 2: Poll all selectors rapidly until timeout
    import time as _time
    deadline = _time.time() + timeout / 1000
    while _time.time() < deadline:
        locator = _first_visible_locator(page, selectors)
        if locator:
            try:
                locator.fill(value)
                return locator
            except Exception:
                pass
        _time.sleep(0.15)  # Small poll interval

    # Strategy 3: One last sequential attempt with short timeout each
    per_sel = max(500, timeout // len(selectors)) if selectors else timeout
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            loc.wait_for(state="visible", timeout=per_sel)
            loc.fill(value)
            return loc
        except Exception:
            pass
    return None


def wait_a_bit(page, ms=1500):
    try:
        page.wait_for_load_state("domcontentloaded", timeout=ms)
    except Exception:
        pass
    time.sleep(ms / 1000)


def normalize_totp_secret(secret):
    """Normalize base32 TOTP secret and add padding if needed."""
    s = (secret or "").strip().replace(" ", "").replace("-", "").upper()
    if not s:
        return ""
    pad = len(s) % 8
    if pad:
        s += "=" * (8 - pad)
    return s


def make_totp_code(secret):
    """Generate current TOTP code safely."""
    s = normalize_totp_secret(secret)
    if not s:
        return ""
    return pyotp.TOTP(s).now()


def login_account(page, email, password, totp_secret, headed=False):
    """Navigate one account's OAuth flow through the registered shared callback."""
    auth_url, verifier, state = build_auth_url()
    result = register_callback(state)

    try:
        # Navigate to auth URL
        page.goto(auth_url, wait_until="domcontentloaded", timeout=45000)
        wait_a_bit(page, 300)
        debug_page(page, "01_open_auth")

        # A Chrome channel can occasionally show an account chooser despite a
        # fresh context. Never select a listed account; force the credential flow.
        if click_first_visible(page, [
            'a[href*="log-in-or-create-account"]',
            'a:has-text("Log in to another account")',
        ], timeout=3000):
            wait_a_bit(page, 250)

        # --- Step 1: Email ---
        email_input = fill_first_visible(page, [
            'input[name="email"]',
            'input[type="email"]',
            'input[name="username"]',
            'input[id*="email" i]',
            'input[placeholder*="email" i]',
            'input[autocomplete="email"]',
            'input[data-login-web-auth-control="true"]',
            'input[autocomplete="username"]',
            'input:not([type="hidden"]):not([type="password"])',
        ], email, timeout=20000)

        if not email_input:
            debug_page(page, "02_email_not_found")
            flags = _safe_auth_page_state(page, "email_not_found")
            return None, _email_step_error(page, flags), verifier, state

        time.sleep(0.05)
        if not click_first_visible(page, [
            'button[type="submit"]',
            'button:has-text("Continue")',
            'button:has-text("Next")',
            'button:has-text("Tiếp tục")',
            'button:has-text("Log in")',
        ], timeout=900):
            email_input.press("Enter")
        # Wait directly for the password selector once OpenAI has resolved the
        # account. Some accounts take longer to advance than the initial page.
        debug_page(page, "03_after_email")

        # Some accounts are redirected to Apple/iCloud auth or another IdP.
        # Handle generic email/password pages too.
        # --- Step 2: Password ---
        pwd_input = fill_first_visible(page, [
            'input[name="password"]',
            'input[type="password"]',
            'input[id*="password" i]',
            'input[autocomplete="current-password"]',
            'input[placeholder*="password" i]',
            'input[placeholder*="mật khẩu" i]',
            'input[data-testid*="password" i]',
        ], password, timeout=20000)

        if not pwd_input:
            debug_page(page, "04_password_not_found")
            _safe_auth_page_state(page, "password_not_found")
            return None, _password_step_error(page), verifier, state

        time.sleep(0.05)
        if not click_first_visible(page, [
            'button[type="submit"]',
            'button:has-text("Continue")',
            'button:has-text("Next")',
            'button:has-text("Log in")',
            'button:has-text("Sign in")',
            'button:has-text("Đăng nhập")',
        ], timeout=900):
            pwd_input.press("Enter")
        wait_a_bit(page, 600)
        debug_page(page, "05_after_password")

        # --- Step 3: 2FA (TOTP) ---
        if totp_secret:
            try:
                otp_code = make_totp_code(totp_secret)
            except Exception as e:
                debug_page(page, "06_totp_secret_error")
                return None, f"Invalid 2FA secret: {e}", verifier, state

            otp_input = fill_first_visible(page, [
                'input[name="code"]',
                'input[inputmode="numeric"]',
                'input[autocomplete="one-time-code"]',
                'input[id*="code" i]',
                'input[placeholder*="code" i]',
                'input[placeholder*="verification" i]',
                'input[aria-label*="code" i]',
            ], otp_code, timeout=12000)

            if otp_input:
                print("    [2FA] Filled TOTP code")
                time.sleep(0.15)
                if not click_first_visible(page, [
                    'button[type="submit"]',
                    'button:has-text("Continue")',
                    'button:has-text("Verify")',
                    'button:has-text("Next")',
                    'button:has-text("Submit")',
                ], timeout=2500):
                    otp_input.press("Enter")
                wait_a_bit(page, 2500)
                debug_page(page, "06_after_2fa")
            else:
                print("    [2FA] No TOTP prompt found yet")
                debug_page(page, "06_2fa_not_found")

        # --- Step 4: Consent + callback ---
        # If final consent/authorization keeps loading, retry the consent click up
        # to 2 more times before marking the account failed.
        got_callback = False
        for consent_try in range(3):
            # Check if already on callback before trying consent clicks
            if "localhost" in page.url and "/auth/callback" in page.url:
                got_callback = result.done.wait(timeout=1)
                if not got_callback:
                    parsed = urlparse(page.url)
                    params = parse_qs(parsed.query)
                    callback_state = params.get("state", [None])[0]
                    if callback_state == state:
                        result.code = params.get("code", [None])[0]
                        result.state = callback_state
                        result.error = params.get("error", [None])[0]
                        got_callback = result.code is not None or result.error is not None
                if got_callback:
                    break

            for _ in range(3):
                clicked = click_first_visible(page, [
                    'button:has-text("Continue")',
                    'button:has-text("Authorize")',
                    'button:has-text("Allow")',
                    'button:has-text("Accept")',
                    'button:has-text("Yes")',
                ], timeout=800)
                if not clicked:
                    break
                print(f"    [consent] Clicked continue/authorize (try {consent_try + 1}/3)")
                wait_a_bit(page, 300)
                if "localhost" in page.url and "/auth/callback" in page.url:
                    break

            try:
                current = page.url
                body_text = page.locator("body").inner_text(timeout=500).lower()
                if "localhost" in current and "/auth/callback" in current:
                    parsed = urlparse(current)
                    params = parse_qs(parsed.query)
                    callback_state = params.get("state", [None])[0]
                    if callback_state == state:
                        result.code = params.get("code", [None])[0]
                        result.state = callback_state
                        result.error = params.get("error", [None])[0]
                        got_callback = result.code is not None or result.error is not None
                        if got_callback:
                            break
                if "invalid_state" in current.lower() or "invalid_state" in body_text or "session ended" in body_text:
                    return None, "RETRYABLE_INVALID_STATE: OAuth session ended/invalid_state", verifier, state
            except Exception:
                pass

            if consent_try < 2:
                print(f"    [retry] Callback not received, retrying final consent ({consent_try + 2}/3)")
                try:
                    page.reload(wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    pass
                wait_a_bit(page, 600)

        if not got_callback:
            # Check if page URL is already on callback
            try:
                current = page.url
                if "localhost" in current and "/auth/callback" in current:
                    parsed = urlparse(current)
                    params = parse_qs(parsed.query)
                    result.code = params.get("code", [None])[0]
                    result.state = params.get("state", [None])[0]
                    got_callback = result.code is not None
            except:
                pass

        if not got_callback:
            return None, "Timeout waiting for callback after 3 consent attempts", verifier, state

        if result.error:
            return None, f"OAuth error: {result.error}", verifier, state

        if not result.code:
            return None, "No authorization code received", verifier, state

        if result.state and result.state != state:
            return None, "OAuth callback state did not match this worker", verifier, state

        # Exchange code for tokens
        tokens, err = exchange_code(result.code, verifier)
        if err:
            return None, f"Token exchange: {err}", verifier, state

        return tokens, None, verifier, state

    finally:
        unregister_callback(state)


# ---------- Main ----------
def parse_accounts(accounts_file):
    accounts = []
    with open(accounts_file, "r", encoding="utf-8") as source:
        for line in source:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            email = parts[0].strip()
            password = parts[1].strip() if len(parts) > 1 else ""
            totp = parts[2].strip() if len(parts) > 2 else ""
            if email and password:
                accounts.append((email, password, totp))
    return accounts


def emit_event(kind, email, **payload):
    """Emit machine-readable progress while keeping normal logs readable."""
    fields = ["EVENT", kind, email]
    fields.extend("{}={}".format(key, str(value).replace("|", "/")) for key, value in payload.items())
    print("|".join(fields), flush=True)


def _safe_browser_error(error):
    """Replace Playwright lifecycle noise with an actionable safe message."""
    message = str(error or "")
    lowered = message.lower()
    if (
        "target page, context or browser has been closed" in lowered
        or "browsertype.launch" in lowered
        or "browser has been closed" in lowered
    ):
        return "VPS browser closed during launch/login. Use workstation browser and Manual OAuth."
    return message


def login_one_account(index, total, account, headed, slow):
    email, password, totp_secret = account
    emit_event("START", email, index=index, total=total)
    print("[{}/{}] {}".format(index, total, email), flush=True)
    last_error = ""
    launch_kwargs = dict(
        headless=not headed,
        slow_mo=500 if slow else 0,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-save-password-bubble",
            "--disable-features=PasswordManagerOnboarding,PasswordLeakDetection",
        ],
    )

    for account_attempt in range(3):
        browser = None
        context = None
        try:
            with sync_playwright() as pw:
                try:
                    browser = pw.chromium.launch(channel="chrome", **launch_kwargs)
                    if account_attempt == 0:
                        print("    Browser: Google Chrome | shared callback={}".format(REDIRECT_URI), flush=True)
                except Exception:
                    print("    [!] Chrome unavailable, fallback Chromium", flush=True)
                    try:
                        browser = pw.chromium.launch(**launch_kwargs)
                    except Exception as fallback_error:
                        raise RuntimeError(_safe_browser_error(fallback_error))
                context = browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                )
                page = context.new_page()
                if account_attempt:
                    print("    [retry] Restarted browser ({}/3)".format(account_attempt + 1), flush=True)
                tokens, error, _, _ = login_account(page, email, password, totp_secret, headed)
                if error:
                    last_error = error
                    retryable = "RETRYABLE_INVALID_STATE" in error or "Timeout waiting for callback" in error
                    if retryable and account_attempt < 2:
                        print("    [retry] {}".format(error), flush=True)
                        continue
                    clean_error = error.replace("RETRYABLE_INVALID_STATE: ", "")
                    print("    ❌ {}".format(clean_error), flush=True)
                    emit_event("ERROR", email, error=clean_error)
                    return {"email": email, "status": "error", "error": clean_error}

                conn = tokens_to_connection(tokens)
                actual_email = conn.get("email") or email
                plan = conn.get("providerSpecificData", {}).get("chatgptPlanType", "?")
                has_rt = bool(conn.get("refreshToken"))
                print("    ✅ {} | plan={} | rt={}".format(actual_email, plan, "yes" if has_rt else "NO!"), flush=True)
                response, import_error = import_to_9router(conn)
                if response:
                    print("IMPORT_OK|{}|{}|{}|{}".format(actual_email, plan, "yes" if has_rt else "no", response.get("sqlitePath", "")), flush=True)
                    emit_event("SUCCESS", actual_email, plan=plan, refresh="yes" if has_rt else "no")
                    return {"email": actual_email, "status": "success", "plan": plan, "hasRefreshToken": has_rt, "imported": True}

                message = "OAuth OK but 9router import failed: {}".format(import_error or "unknown error")
                print("IMPORT_FAIL|{}|{}".format(actual_email, import_error or "unknown import error"), flush=True)
                emit_event("ERROR", actual_email, error=message)
                return {"email": actual_email, "status": "error", "error": message, "imported": False}
        except Exception as error:
            last_error = _safe_browser_error(error)
            if account_attempt < 2:
                print("    [retry] Exception, restarting browser: {}".format(last_error), flush=True)
                continue
            print("    ❌ Exception: {}".format(error), flush=True)
            emit_event("ERROR", email, error=last_error)
            return {"email": email, "status": "error", "error": last_error}
        finally:
            try:
                if context:
                    context.close()
            except Exception:
                pass
            try:
                if browser:
                    browser.close()
            except Exception:
                pass
    emit_event("ERROR", email, error=last_error or "Unknown login error")
    return {"email": email, "status": "error", "error": last_error or "Unknown login error"}


def main():
    if len(sys.argv) < 2:
        print("Usage: python auto_login.py accounts.txt [--headed] [--slow] [--workers N]")
        sys.exit(1)
    accounts_file = sys.argv[1]
    headed = "--headed" in sys.argv or "--show" in sys.argv
    slow = "--slow" in sys.argv
    workers = 3
    if "--workers" in sys.argv:
        try:
            workers = int(sys.argv[sys.argv.index("--workers") + 1])
        except (ValueError, IndexError):
            print("[!] --workers must be a positive integer")
            sys.exit(1)
    if workers < 1:
        print("[!] --workers must be a positive integer")
        sys.exit(1)
    if not os.path.exists(accounts_file):
        print("[!] File not found: {}".format(accounts_file))
        sys.exit(1)
    accounts = parse_accounts(accounts_file)
    if not accounts:
        print("[!] No accounts found in file")
        sys.exit(1)

    active_workers = min(workers, len(accounts))
    print("=" * 55)
    print("  Auto-Login ChatGPT → 9router (parallel OAuth PKCE)")
    print("=" * 55)
    print("  Accounts: {} | Workers requested: {} | Running: {}".format(len(accounts), workers, active_workers))
    print("  Mode: {} | Import: {}".format("headed" if headed else "headless", IMPORT_API))
    print("=" * 55, flush=True)

    results = []
    start_callback_dispatcher()
    try:
        with ThreadPoolExecutor(max_workers=active_workers, thread_name_prefix="oauth") as executor:
            futures = {
                executor.submit(login_one_account, index, len(accounts), account, headed, slow): account[0]
                for index, account in enumerate(accounts, start=1)
            }
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as error:
                    email = futures[future]
                    emit_event("ERROR", email, error=str(error))
                    results.append({"email": email, "status": "error", "error": str(error)})
    finally:
        stop_callback_dispatcher()

    results.sort(key=lambda result: (result.get("email") or "").lower())
    ok = sum(1 for result in results if result["status"] == "success")
    fail = sum(1 for result in results if result["status"] == "error")
    print("\n{}\n  SUMMARY\n{}\n  ✅ Success: {}\n  ❌ Failed:  {}\n  Total:     {}".format("=" * 55, "=" * 55, ok, fail, len(results)), flush=True)
    out_file = os.path.join(os.path.dirname(os.path.abspath(accounts_file)), "auto_login_results.json")
    with open(out_file, "w", encoding="utf-8") as output:
        json.dump(results, output, indent=2, ensure_ascii=False)
    print("  Results saved: {}".format(out_file), flush=True)


if __name__ == "__main__":
    main()
