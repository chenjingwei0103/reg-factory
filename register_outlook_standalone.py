# -*- coding: utf-8 -*-
"""
Standalone Outlook Email Registration Script
Uses BitBrowser + Playwright + Proxy to register Outlook accounts
Independent from the main register.py — only registers Outlook accounts

Usage:
  python register_outlook_standalone.py --count 10
  python register_outlook_standalone.py --count 5 --concurrency 2
  python register_outlook_standalone.py --proxy-file proxies.txt
"""

import argparse
import asyncio
import contextlib
import json
import os
import random
import re
import string
import sys
import time
import urllib.parse
from datetime import datetime

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")

import requests
from playwright.async_api import async_playwright
try:
    from playwright_stealth import Stealth as _StealthCls
    _HAS_STEALTH = True
    _stealth_obj = _StealthCls()
except ImportError:
    _HAS_STEALTH = False
    _stealth_obj = None

try:
    from check_outlook_status import check_account_api
except Exception:
    check_account_api = None

# ======================== Configuration ========================

# 导入 config 以触发 .env 加载（密钥来自 .env / 真实环境变量）。
try:
    import config  # noqa: F401
except Exception:
    pass

# Outlook 注册和解锁共用同一套 PerimeterX 目标定位与拟人按压。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import outlook_press as _outlook_press
from common.browser import react_fill
from common.traffic_saver import install as install_traffic_saver

# BitBrowser local API
BITBROWSER_API = os.environ.get("BITBROWSER_API", "http://127.0.0.1:54345")


def ensure_clash_proxy_env():
    """Use .env CLASH_PROXY for direct standalone runs, while local APIs stay direct."""
    existing = (
        os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        or ""
    ).strip()
    proxy = existing or os.environ.get("CLASH_PROXY", "").strip()
    if not proxy:
        return ""
    if not existing:
        os.environ["HTTP_PROXY"] = os.environ["HTTPS_PROXY"] = proxy
        os.environ["http_proxy"] = os.environ["https_proxy"] = proxy
    no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    parts = [p.strip() for p in no_proxy.split(",") if p.strip()]
    for item in ("127.0.0.1", "localhost", "::1"):
        if item not in parts:
            parts.append(item)
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = ",".join(parts)
    return proxy


def _fingerprint_provider():
    return (
        os.environ.get("FINGERPRINT_BROWSER")
        or os.environ.get("BROWSER_PROVIDER")
        or "bitbrowser"
    ).strip().lower()

# CAPTCHA solver keys（环境变量，默认空）
CAPSOLVER_API_KEY = os.environ.get("CAPSOLVER_API_KEY", "")
EZCAPTCHA_API_KEY = os.environ.get("EZCAPTCHA_API_KEY", "")
EZCAPTCHA_API_BASE = os.environ.get("EZCAPTCHA_API_BASE", "https://api.ez-captcha.com")

# Arkose Labs public key for Microsoft signup
MS_SIGNUP_ARKOSE_KEY = "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA"

# Output
OUTPUT_DIR = "outlook_accounts"
SCREENSHOT_DIR = "screenshots_outlook"

# Registration timeout per account (seconds)
REGISTER_TIMEOUT = 300
VERIFY_AFTER_REGISTER = True


MICROSOFT_AUTH_TERMINAL_ERRORS = (
    (
        "account_not_found",
        (
            "we couldn't find a microsoft account",
            "we could not find a microsoft account",
            "that microsoft account doesn't exist",
        ),
    ),
    (
        "password_signin_unavailable",
        (
            "password sign-in isn't available",
            "password sign in isn't available",
            "password sign-in is not available",
        ),
    ),
    (
        "signin_rate_limited",
        (
            "you've tried to sign in too many times with an incorrect account or password",
            "you have tried to sign in too many times with an incorrect account or password",
        ),
    ),
    (
        "account_locked",
        (
            "your account has been locked",
            "your microsoft account has been locked",
            "has been locked we detected activity",
        ),
    ),
)

# These messages stop the current browser sign-in page, but they do not prove
# that a freshly registered account is invalid. The HTTP OAuth path uses a
# separate session and can still succeed, so keep it available as a fallback.
MICROSOFT_AUTH_HTTP_FALLBACK_ERRORS = frozenset({
    "password_signin_unavailable",
    "signin_rate_limited",
})

# Accounts Microsoft locked cannot finish the PerimeterX hold; retrying only
# burns browser sessions and can lengthen the lockout.
MICROSOFT_AUTH_HARD_STOP_ERRORS = frozenset({"account_locked"})


def microsoft_auth_terminal_error(text):
    """Return a stable reason for Microsoft sign-in errors that must not be retried."""
    normalized = " ".join((text or "").replace("’", "'").lower().split())
    for reason, markers in MICROSOFT_AUTH_TERMINAL_ERRORS:
        if any(marker in normalized for marker in markers):
            return reason
    return ""


def microsoft_auth_allows_http_fallback(reason):
    """Return whether a browser sign-in stop is recoverable through HTTP OAuth."""
    normalized = str(reason or "").strip().lower()
    return not normalized or normalized in MICROSOFT_AUTH_HTTP_FALLBACK_ERRORS


def outlook_registration_terminal_state(url, text=""):
    """Classify browser state without treating a vanished captcha as success."""
    reason = microsoft_auth_terminal_error(text)
    if reason:
        return "error", reason
    current_url = (url or "").lower()
    page_text = (text or "").lower()
    if "privacynotice" in current_url:
        return "pending", "privacy_notice"
    if "signup.live.com" in current_url:
        return "pending", "signup_form"
    if any(host in current_url for host in (
        "account.microsoft.com",
        "account.live.com",
        "outlook.live.com",
        "outlook.office.com",
        "login.live.com/oauth20",
    )):
        return "confirmed", "post_signup_url"
    if any(marker in page_text for marker in (
        "account has been created",
        "your account is ready",
        "welcome to outlook",
    )):
        return "confirmed", "post_signup_text"
    return "pending", "unrecognized_page"


async def _microsoft_page_terminal_error(page):
    try:
        body = await page.locator("body").inner_text(timeout=3000)
    except Exception:
        body = ""
    return microsoft_auth_terminal_error(body), " ".join((body or "").split())


def verify_registered_outlook(email, password, tag=""):
    """Verify the saved password can actually log in before exporting the account."""
    if not VERIFY_AFTER_REGISTER:
        return True
    if check_account_api is None:
        print(f"  {tag} external verify unavailable; using confirmed browser state")
        return None
    result = check_account_api(email, password)
    status = result.get("status")
    code = result.get("code") or ""
    msg = result.get("message") or ""
    print(f"  {tag} post-register verify: {status} {code} {msg[:80]}")
    return status == "ok"

# Default proxies (user:pass@host:port)
# 住宅代理账密池来自环境变量 OUTLOOK_PROXIES（多个用换行或逗号分隔），默认空。
# 也可用 --proxy-file 指定文件；两者都为空时不走代理。
def _load_default_proxies():
    raw = os.environ.get("OUTLOOK_PROXIES", "")
    if not raw:
        return []
    parts = [p.strip() for p in raw.replace(",", "\n").splitlines()]
    return [p for p in parts if p and not p.startswith("#")]


DEFAULT_PROXIES = _load_default_proxies()


# ======================== BitBrowser API ========================

class BitBrowserClient:
    """BitBrowser local API client with proxy support"""

    def __new__(cls, api_base=None):
        provider = _fingerprint_provider()
        if cls is BitBrowserClient and provider not in {"bitbrowser", "bit"}:
            from bitbrowser import BitBrowser
            return BitBrowser(api_base=api_base)
        return super().__new__(cls)

    def __init__(self, api_base=None):
        self.api_base = api_base or BITBROWSER_API

    def _post(self, path, data=None):
        url = f"{self.api_base}{path}"
        resp = requests.post(url, json=data or {}, timeout=120)
        resp.raise_for_status()
        result = resp.json()
        if not result.get("success"):
            raise Exception(f"BitBrowser API error: {result.get('msg', 'unknown')}")
        return result

    def create_browser(self, name="outlook_reg", proxy_str=None):
        """Create a new browser profile with optional proxy.
        proxy_str format: user:pass@host:port
        """
        from common.traffic_saver import bitbrowser_profile_defaults

        data = {
            "name": name,
            "remark": "outlook standalone registration",
            "proxyMethod": 2,  # custom proxy
            "browserFingerPrint": {
                "coreVersion": "130",
            },
            **bitbrowser_profile_defaults(),
        }

        if proxy_str:
            parsed = self._parse_proxy(proxy_str)
            if parsed:
                data["proxyType"] = parsed.get("type", "http")
                data["host"] = parsed["host"]
                data["port"] = parsed["port"]
                if parsed.get("username"):
                    data["proxyUserName"] = parsed["username"]
                if parsed.get("password"):
                    data["proxyPassword"] = parsed["password"]
                print(f"  proxy: [{data['proxyType']}] {parsed['host']}:{parsed['port']} (user={parsed.get('username', 'none')[:20]}...)")
            else:
                data["proxyType"] = "noproxy"
                print(f"  proxy: invalid format, using noproxy")
        else:
            data["proxyType"] = "noproxy"

        result = self._post("/browser/update", data)
        profile_id = result["data"]["id"]
        try:
            from common.browser_registry import register
            register(profile_id, name=name, provider="bitbrowser", api_base=self.api_base)
        except Exception:
            pass
        print(f"  browser created: {name} (ID: {profile_id})")
        return profile_id

    def open_browser(self, profile_id):
        """Open browser window, returns WebSocket debug URL"""
        from common.traffic_saver import bitbrowser_open_payload

        payload = bitbrowser_open_payload(profile_id)
        try:
            result = self._post("/browser/open", payload)
        except Exception:
            if "args" not in payload:
                raise
            print("  BitBrowser rejected traffic-saving launch args; retrying normally")
            result = self._post("/browser/open", {"id": profile_id})
        return result["data"]

    def close_browser(self, profile_id):
        """Close browser window"""
        try:
            self._post("/browser/close", {"id": profile_id})
        except Exception:
            pass

    def delete_browser(self, profile_id):
        """Delete browser profile"""
        try:
            self._post("/browser/delete", {"id": profile_id})
            try:
                from common.browser_registry import unregister
                unregister(profile_id)
            except Exception:
                pass
            return True
        except Exception:
            return False

    def cleanup_browsers(self, keep=0):
        """Delete all browser profiles (release quota)"""
        result = self._post("/browser/list", {"page": 0, "pageSize": 200})
        browsers = result["data"]["list"]
        if not browsers:
            return 0
        browsers.sort(key=lambda b: b.get("seq", 0), reverse=True)
        to_delete = browsers[keep:]
        deleted = 0
        for b in to_delete:
            try:
                self.close_browser(b["id"])
            except Exception:
                pass
            time.sleep(1)
            try:
                self.delete_browser(b["id"])
                deleted += 1
            except Exception:
                pass
        print(f"  cleanup: deleted {deleted}/{len(to_delete)} browsers")
        return deleted

    @staticmethod
    def _parse_proxy(proxy_str):
        """Parse proxy string into dict.
        Supported formats:
          socks5://user:pass@host:port
          socks5://host:port
          user:pass@host:port          (defaults to http)
          host:port                    (defaults to http)
        """
        # Strip protocol prefix
        proxy_type = "http"
        lower = proxy_str.lower()
        if lower.startswith("socks5://"):
            proxy_type = "socks5"
            proxy_str = proxy_str[len("socks5://"):]
        elif lower.startswith("http://"):
            proxy_str = proxy_str[len("http://"):]
        elif lower.startswith("https://"):
            proxy_str = proxy_str[len("https://"):]

        # Handle comma-separated format: user:pass,host:port
        proxy_str = proxy_str.replace(",", "@", 1) if "@" not in proxy_str and "," in proxy_str else proxy_str

        match = re.match(r'^(.+):(.+)@(.+):(\d+)$', proxy_str)
        if match:
            return {
                "type": proxy_type,
                "username": match.group(1),
                "password": match.group(2),
                "host": match.group(3),
                "port": match.group(4),
            }
        match2 = re.match(r'^(.+):(\d+)$', proxy_str)
        if match2:
            return {
                "type": proxy_type,
                "host": match2.group(1),
                "port": match2.group(2),
            }
        return None


# ======================== Helper Functions ========================

def generate_birthday():
    """Generate a random birthday (25-40 years old)"""
    current_year = datetime.now().year
    year = random.randint(current_year - 40, current_year - 25)
    month = random.randint(1, 12)
    if month in (1, 3, 5, 7, 8, 10, 12):
        max_day = 31
    elif month in (4, 6, 9, 11):
        max_day = 30
    else:
        max_day = 28
    day = random.randint(1, max_day)
    return year, month, day


def generate_name():
    """Generate a random English name"""
    first_names = [
        "James", "John", "Robert", "Michael", "David", "William", "Richard", "Joseph",
        "Thomas", "Charles", "Mary", "Patricia", "Jennifer", "Linda", "Barbara",
        "Elizabeth", "Susan", "Jessica", "Sarah", "Karen", "Emily", "Emma", "Olivia",
        "Daniel", "Matthew", "Anthony", "Mark", "Steven", "Andrew", "Brian",
    ]
    last_names = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
        "Davis", "Rodriguez", "Martinez", "Anderson", "Taylor", "Thomas", "Moore",
        "Jackson", "Martin", "Lee", "Thompson", "White", "Harris", "Clark",
    ]
    return random.choice(first_names), random.choice(last_names)


def generate_email_password(domain=None):
    """Generate random Outlook email and password."""
    prefix = random.choice(string.ascii_lowercase) + "".join(
        random.choices(string.ascii_lowercase + string.digits, k=11)
    )
    domain = domain or _preferred_outlook_domain()
    email = f"{prefix}@{domain}"
    password = "Aa1!" + "".join(random.choices(string.ascii_letters + string.digits, k=12))
    return email, password, prefix


# ======================== CAPTCHA Solvers ========================

def solve_arkose_capsolver(public_key=MS_SIGNUP_ARKOSE_KEY, page_url="https://signup.live.com/", max_wait=120):
    """Use CapSolver to solve Arkose Labs (FunCaptcha) challenge."""
    if not CAPSOLVER_API_KEY:
        print("  [capsolver] no API key, skipping")
        return None
    try:
        payload = {
            "clientKey": CAPSOLVER_API_KEY,
            "task": {
                "type": "FunCaptchaTaskProxyLess",
                "websiteURL": page_url,
                "websitePublicKey": public_key,
            }
        }
        resp = requests.post("https://api.capsolver.com/createTask", json=payload, timeout=30)
        data = resp.json()
        if data.get("errorId", 1) != 0:
            print(f"  [capsolver] create error: {data.get('errorDescription', data)}")
            return None
        task_id = data["taskId"]
        print(f"  [capsolver] task: {task_id}")
        start = time.time()
        while time.time() - start < max_wait:
            time.sleep(5)
            resp = requests.post("https://api.capsolver.com/getTaskResult", json={
                "clientKey": CAPSOLVER_API_KEY, "taskId": task_id,
            }, timeout=30)
            result = resp.json()
            if result.get("status") == "ready":
                token = result.get("solution", {}).get("token")
                print(f"  [capsolver] solved! {token[:60]}...")
                return token
            elif result.get("status") == "failed":
                print(f"  [capsolver] failed")
                return None
        print("  [capsolver] timeout")
        return None
    except Exception as e:
        print(f"  [capsolver] error: {e}")
        return None


def solve_funcaptcha_ezcaptcha(public_key=MS_SIGNUP_ARKOSE_KEY, page_url="https://signup.live.com/", max_wait=120,
                               proxy_host="proxy.proxyshare.com", proxy_port=5959,
                               proxy_user="ps-s46az41wfrmk_area-US", proxy_pass="hhChjubcVIpCfLo0"):
    """Use EZ-Captcha to solve FunCaptcha (with proxy for better success rate)."""
    if not EZCAPTCHA_API_KEY:
        return None
    try:
        task = {
            "type": "FunCaptchaTask",
            "websiteURL": page_url,
            "websitePublicKey": public_key,
            "proxyType": "http",
            "proxyAddress": proxy_host,
            "proxyPort": proxy_port,
            "proxyLogin": proxy_user,
            "proxyPassword": proxy_pass,
        }
        resp = requests.post(f"{EZCAPTCHA_API_BASE}/createTask", json={
            "clientKey": EZCAPTCHA_API_KEY,
            "task": task,
        }, timeout=30)
        data = resp.json()
        if data.get("errorId", 1) != 0:
            print(f"  [ezcaptcha] create error: {data.get('errorDescription', data)}")
            return None
        task_id = data["taskId"]
        print(f"  [ezcaptcha] task: {task_id}")
        start = time.time()
        while time.time() - start < max_wait:
            time.sleep(5)
            resp = requests.post(f"{EZCAPTCHA_API_BASE}/getTaskResult", json={
                "clientKey": EZCAPTCHA_API_KEY, "taskId": task_id,
            }, timeout=30)
            result = resp.json()
            if result.get("status") == "ready":
                token = result.get("solution", {}).get("token")
                print(f"  [ezcaptcha] solved! {token[:60]}...")
                return token
            elif result.get("status") == "failed":
                return None
        return None
    except Exception as e:
        print(f"  [ezcaptcha] error: {e}")
        return None


async def solve_perimeterx_capsolver(page, context, page_url="https://signup.live.com/", max_wait=120):
    """Use CapSolver to solve PerimeterX human challenge (press-and-hold).
    Returns a dict with _px2 / _pxhd keys on success, None on failure.
    Configure CAPSOLVER_API_KEY to enable.

    CapSolver task type: AntiPerimeterXTaskProxyless
    Docs: https://docs.capsolver.com/guide/antibots/perimeter_x.html
    """
    if not CAPSOLVER_API_KEY:
        return None
    try:
        # Gather PX cookies/tokens to help the solver
        cookies = await context.cookies()
        cookie_map = {c["name"]: c["value"] for c in cookies}
        pxvid = cookie_map.get("_pxvid", "")
        pxde  = cookie_map.get("_pxde", "")
        pxcts = cookie_map.get("pxcts", "")

        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"

        payload = {
            "clientKey": CAPSOLVER_API_KEY,
            "task": {
                "type": "AntiPerimeterXTaskProxyless",
                "websiteURL": page_url,
                "userAgent": ua,
                "_pxvid": pxvid,
                "_pxde": pxde,
                "pxcts": pxcts,
            },
        }
        resp = requests.post("https://api.capsolver.com/createTask", json=payload, timeout=30)
        data = resp.json()
        if data.get("errorId", 1) != 0:
            print(f"  [capsolver-px] create error: {data.get('errorDescription', data)}")
            return None
        task_id = data["taskId"]
        print(f"  [capsolver-px] task: {task_id}")
        start = time.time()
        while time.time() - start < max_wait:
            time.sleep(5)
            resp = requests.post("https://api.capsolver.com/getTaskResult",
                                 json={"clientKey": CAPSOLVER_API_KEY, "taskId": task_id},
                                 timeout=30)
            result = resp.json()
            if result.get("status") == "ready":
                solution = result.get("solution", {})
                print(f"  [capsolver-px] solved! keys: {list(solution.keys())}")
                return solution
            elif result.get("status") == "failed":
                print(f"  [capsolver-px] failed: {result.get('errorDescription', '')}")
                return None
        print("  [capsolver-px] timeout")
        return None
    except Exception as e:
        print(f"  [capsolver-px] error: {e}")
        return None


def solve_perimeterx_ezcaptcha(page_url="https://signup.live.com/", app_id="PXzC5j78di", max_wait=60):
    """Use EZ-Captcha to solve PerimeterX."""
    if not EZCAPTCHA_API_KEY:
        return None
    try:
        resp = requests.post(f"{EZCAPTCHA_API_BASE}/createTask", json={
            "clientKey": EZCAPTCHA_API_KEY,
            "task": {"type": "PerimeterX", "websiteURL": page_url, "websiteKey": app_id}
        }, timeout=30)
        data = resp.json()
        if data.get("errorId", 1) != 0:
            print(f"  [ezcaptcha-px] create error: {data.get('errorDescription', data)}")
            return None
        task_id = data["taskId"]
        print(f"  [ezcaptcha-px] task: {task_id}")
        start = time.time()
        while time.time() - start < max_wait:
            time.sleep(5)
            resp = requests.post(f"{EZCAPTCHA_API_BASE}/getTaskResult", json={
                "clientKey": EZCAPTCHA_API_KEY, "taskId": task_id,
            }, timeout=30)
            result = resp.json()
            if result.get("status") == "ready":
                solution = result.get("solution", {})
                print(f"  [ezcaptcha-px] solved! keys: {list(solution.keys())}")
                return solution
            elif result.get("status") == "failed":
                return None
        return None
    except Exception as e:
        print(f"  [ezcaptcha-px] error: {e}")
        return None


async def inject_arkose_token(page, token):
    """Inject solved Arkose token into the page."""
    try:
        injected = await page.evaluate(f"""
            () => {{
                const frames = document.querySelectorAll('iframe[id*="enforcement"], iframe[data-e2e="enforcement-frame"]');
                if (frames.length > 0 && window.CE_READY) {{
                    window.CE_READY("{token}");
                    return "ce_ready";
                }}
                const hidden = document.querySelector('input[name="fc-token"], input[name="FunCaptcha"]');
                if (hidden) {{ hidden.value = "{token}"; return "hidden_field"; }}
                if (typeof window.fcCallback === 'function') {{ window.fcCallback("{token}"); return "fc_callback"; }}
                if (typeof window.ArkoseEnforcement !== 'undefined') {{
                    try {{ window.ArkoseEnforcement.setConfig({{data: {{token: "{token}"}}}}) }} catch(e) {{}}
                    return "arkose_enforcement";
                }}
                return "no_method";
            }}
        """)
        print(f"  [arkose] inject: {injected}")
        return injected != "no_method"
    except Exception as e:
        print(f"  [arkose] inject error: {e}")
        return False


# ======================== Graph API Token ========================

# Thunderbird's public client is enabled for consumer Microsoft accounts and
# is also used by tools/extract_graph_tokens.py. Keep each RT paired with this ID.
GRAPH_CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
GRAPH_REDIRECT_URI = "http://localhost"
GRAPH_SCOPE = "offline_access https://graph.microsoft.com/Mail.Read"
GRAPH_DEVICE_CODE_URL = (
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
)
GRAPH_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
MICROSOFT_UI_LOCALE = os.environ.get("OUTLOOK_UI_LOCALE", "en-US").strip() or "en-US"

# Microsoft only exposes some regional aliases from selected exits.  Never
# assume that a suffix such as outlook.jp or outlook.eu is universally open:
# inspect the signup page's domain picker and choose from what it advertises.
_OUTLOOK_DOMAIN_RE = re.compile(r"(?i)\b(?:outlook|hotmail|live|msn)\.[a-z0-9.-]+\b")
_GLOBAL_OUTLOOK_DOMAINS = {"outlook.com", "hotmail.com", "live.com", "msn.com"}
_OUTLOOK_SUFFIXES_BY_REGION = {
    "gb": ("co.uk", "uk"),
    "uk": ("co.uk", "uk"),
    "au": ("com.au", "au"),
    "nz": ("co.nz", "nz"),
    "br": ("com.br", "br"),
    "mx": ("com.mx", "mx"),
    "ar": ("com.ar", "ar"),
    "za": ("co.za", "za"),
    "tr": ("com.tr", "tr"),
}


def _configured_outlook_domain():
    """Return an optional explicit domain, or ``auto`` for page-driven choice."""
    value = (os.environ.get("OUTLOOK_EMAIL_DOMAIN", "auto") or "auto").strip().lower()
    if value in {"", "auto", "default", "随机", "自动"}:
        return "auto"
    value = value.lstrip("@").rstrip(".")
    return value if _OUTLOOK_DOMAIN_RE.fullmatch(value) else "auto"


def _domains_from_values(values):
    """Extract Outlook-family domains from option values/text or signup HTML."""
    found = []
    for value in values:
        for domain in _OUTLOOK_DOMAIN_RE.findall(str(value or "")):
            domain = domain.lower().rstrip(".")
            if domain not in found:
                found.append(domain)
    return found


def _preferred_outlook_domain(available=(), locale=None):
    """Choose a domain without inventing one absent from Microsoft's picker."""
    available = [str(value).lower().lstrip("@").rstrip(".") for value in available if value]
    available = [value for value in available if _OUTLOOK_DOMAIN_RE.fullmatch(value)]
    configured = _configured_outlook_domain()
    if configured != "auto" and (not available or configured in available):
        return configured

    locale = (locale or MICROSOFT_UI_LOCALE or "").strip().lower().replace("_", "-")
    region = locale.rsplit("-", 1)[-1] if "-" in locale else ""
    region_suffixes = _OUTLOOK_SUFFIXES_BY_REGION.get(region, (region,) if region else ())
    for suffix in region_suffixes:
        regional = next(
            (domain for domain in available if domain.endswith(f".{suffix}")),
            None,
        )
        if regional:
            return regional

    # The signup picker itself is network-sensitive. If it offers one regional
    # suffix alongside the global aliases, prefer that suffix even when the
    # page's mkt parameter was forced to en-US.
    regional = next(
        (domain for domain in available if domain not in _GLOBAL_OUTLOOK_DOMAINS),
        None,
    )
    if regional:
        return regional
    if "outlook.com" in available:
        return "outlook.com"
    if available:
        return available[0]
    return configured if configured != "auto" else "outlook.com"


async def _signup_domain_options(domain_dropdown):
    """Read domain picker options while tolerating a custom React select."""
    try:
        values = await domain_dropdown.locator("option").evaluate_all(
            "options => options.flatMap(option => [option.value, option.textContent])"
        )
    except Exception:
        values = []
    return _domains_from_values(values)


async def _signup_email_suffix_domains(email_input):
    """Read a suffix rendered next to the email field by newer signup forms."""
    try:
        field = await email_input.evaluate(r"""el => {
            const fragments = [];
            let node = el.parentElement;
            for (let depth = 0; node && node !== document.body && depth < 5; depth++) {
                const text = (node.innerText || node.textContent || '').trim();
                if (text && text.length <= 2000) fragments.push(text);
                node = node.parentElement;
            }
            return fragments.join('\n');
        }""", timeout=1000)
    except Exception:
        field = ""
    return _domains_from_values((field,))


async def _signup_email_domains_after_blur(email_input):
    """Let Microsoft's controlled field render its suffix before submission."""
    try:
        await email_input.press("Tab", timeout=1500)
    except Exception:
        pass
    await asyncio.sleep(0.6)
    return await _signup_email_suffix_domains(email_input)


_SIGNUP_EMAIL_SELECTOR = (
    'input[type="email"]:visible, input[name="MemberName"]:visible, '
    'input[id="MemberName"]:visible, input[id="usernameInput"]:visible, '
    'input[name="Username"]:visible'
)
_SIGNUP_PASSWORD_SELECTOR = (
    'input[type="password"]:visible, input[name="Password"]:visible, '
    'input[id="PasswordInput"]:visible, input[name="passwd"]:visible'
)


def _signup_email_input(page):
    """Return the active field, excluding stale controls kept by React."""
    return page.locator(_SIGNUP_EMAIL_SELECTOR).first


def _signup_password_input(page):
    """Return the visible password field after the email-page transition."""
    return page.locator(_SIGNUP_PASSWORD_SELECTOR).first


async def _signup_email_submission_result(page):
    """Classify the page without consulting a stale hidden email control."""
    password_input = _signup_password_input(page)
    if await password_input.count() > 0:
        return "accepted"
    email_input = _signup_email_input(page)
    if await email_input.count() == 0:
        return "pending"
    return await _signup_email_rejected(page, email_input)


def _signup_email_entry_value(prefix, domain, page_manages_domain):
    """Match the value to the active Microsoft signup form variant."""
    alias = str(prefix or "").split("@", 1)[0].strip()
    return alias if page_manages_domain else f"{alias}@{domain}"


async def _select_signup_domain(domain_dropdown, preferred):
    """Select a domain option by value or label, including @-prefixed values."""
    try:
        options = await domain_dropdown.locator("option").evaluate_all(
            "options => options.map(option => ({value: option.value, text: option.textContent}))"
        )
    except Exception:
        options = []
    for option in options:
        if preferred not in _domains_from_values((option.get("value"), option.get("text"))):
            continue
        for selector in (option.get("value"), option.get("text")):
            if not selector:
                continue
            try:
                await domain_dropdown.select_option(
                    selector if selector == option.get("value") else {"label": selector}
                )
                return True
            except Exception:
                continue
    try:
        await domain_dropdown.select_option(preferred)
        return True
    except Exception:
        return False

# Microsoft occasionally ignores mkt/ui_locales and renders according to the exit IP.
# Keep text matching as a fallback, but prefer stable element IDs and field metadata.
MS_POSITIVE_ACTION_LABELS = (
    "accept", "allow", "continue", "yes", "agree", "next", "ok",
    "agree and continue", "i agree", "got it",
    "\u662f",
    "accepter", "autoriser", "continuer", "oui", "j'accepte", "suivant",
    "aceptar", "permitir", "continuar", "sí", "siguiente", "acepto",
    "akzeptieren", "zulassen", "weiter", "ja", "zustimmen",
    "aceitar", "permitir", "continuar", "sim", "avançar", "concordo",
    "accetta", "consenti", "continua", "sì", "avanti", "accetto",
    "accepteren", "toestaan", "doorgaan", "ja", "volgende", "akkoord",
    "zaakceptuj", "zezwól", "kontynuuj", "tak", "dalej", "zgadzam się",
    "přijmout", "povolit", "pokračovat", "ano", "další", "souhlasím",
    "přijmout a pokračovat",
    "принять", "разрешить", "продолжить", "да", "далее", "согласен",
    "kabul et", "izin ver", "devam et", "evet", "ileri", "kabul ediyorum",
    "قبول", "السماح", "متابعة", "نعم", "التالي", "موافق", "أوافق",
    "接受", "允许", "同意", "继续", "下一步", "确定",
    "允許", "繼續", "下一步", "確定",
    "承諾", "許可", "続行", "次へ", "はい", "同意する",
    "\u8a31\u53ef\u3059\u308b", "\u627f\u8a8d", "\u627f\u8a8d\u3059\u308b",
    "\u540c\u610f", "\u540c\u610f\u3057\u3066\u7d9a\u884c", "\u540c\u610f\u3057\u3066\u6b21\u3078", "\u78ba\u8a8d",
    "동의", "허용", "계속", "다음", "예", "확인",
    # Hindi (India)
    "स्वीकार करें", "अनुमति दें", "जारी रखें", "हाँ", "सहमत", "अगला", "ठीक है",
    "सहमत होकर जारी रखें", "मैं सहमत हूँ",
    # Bahasa Indonesia (Indonesia)
    "terima", "izinkan", "lanjutkan", "ya", "setuju", "berikutnya", "oke",
    "setujui dan lanjutkan", "saya setuju",
    "naprej", "nadaljuj", "sprejmi", "strinjam se", "se strinjam", "v redu", "da",
)
MS_NEGATIVE_ACTION_LABELS = (
    "deny", "decline", "cancel", "no", "back",
    "\u5426",
    "refuser", "annuler", "non",
    "rechazar", "denegar", "cancelar", "no",
    "ablehnen", "abbrechen", "nein",
    "recusar", "negar", "cancelar", "não",
    "rifiuta", "nega", "annulla", "no",
    "weigeren", "annuleren", "nee",
    "odrzuć", "anuluj", "nie",
    "odmítnout", "zrušit", "ne", "zpět",
    "отклонить", "отмена", "нет",
    "reddet", "iptal", "hayır",
    "رفض", "إلغاء", "لا", "رجوع",
    "拒绝", "拒絕", "取消", "否", "いいえ", "拒否", "\u62d2\u5426\u3059\u308b",
    "\u8a31\u53ef\u3057\u306a\u3044", "\u30ad\u30e3\u30f3\u30bb\u30eb", "\u623b\u308b",
    "취소", "거부", "아니요",
    # Hindi (India)
    "अस्वीकार करें", "अनुमति न दें", "रद्द करें", "नहीं", "वापस",
    # Bahasa Indonesia (Indonesia)
    "tolak", "jangan izinkan", "batalkan", "batal", "tidak", "kembali",
)
MS_SKIP_ACTION_LABELS = (
    "skip for now", "skip", "not now", "no thanks", "maybe later", "later",
    "ignorer pour le moment", "ignorer", "pas maintenant", "non merci", "plus tard",
    "omitir por ahora", "omitir", "ahora no", "no, gracias", "más tarde",
    "vorerst überspringen", "überspringen", "nicht jetzt", "nein, danke", "später",
    "ignorar por enquanto", "ignorar", "agora não", "não, obrigado", "mais tarde",
    "ignora per ora", "ignora", "non ora", "no, grazie", "più tardi",
    "voorlopig overslaan", "overslaan", "niet nu", "nee, bedankt", "later",
    "pomiń na razie", "pomiń", "nie teraz", "nie, dziękuję", "później",
    "nyní přeskočit", "přeskočit", "teď ne", "ne, děkuji", "možná později", "později",
    "пропустить", "не сейчас", "нет, спасибо", "позже",
    "şimdilik atla", "atla", "şimdi değil", "hayır, teşekkürler", "daha sonra",
    "تخطي الآن", "تخطي", "ليس الآن", "لا شكرًا", "ربما لاحقًا", "لاحقًا",
    "暂时跳过", "跳过", "现在不", "以后再说", "不用了",
    "暫時略過", "略過", "現在不要", "稍後再說",
    "今はしない", "スキップ", "後で", "건너뛰기", "나중에", "지금은 안 함",
    # Hindi (India)
    "अभी के लिए छोड़ें", "अभी छोड़ें", "छोड़ें", "अभी नहीं", "नहीं धन्यवाद", "शायद बाद में", "बाद में",
    # Bahasa Indonesia (Indonesia)
    "lewati untuk saat ini", "lewati", "jangan sekarang", "tidak, terima kasih",
    "mungkin nanti", "nanti",
    "zavrni", "prekliči", "nazaj", "ne",
)


def _microsoft_url_with_locale(url):
    """Add locale hints without overwriting OAuth/device-code parameters."""
    parsed = urllib.parse.urlsplit(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    existing = {key.lower() for key, _ in params}
    if "mkt" not in existing:
        params.append(("mkt", MICROSOFT_UI_LOCALE))
    if "ui_locales" not in existing:
        params.append(("ui_locales", MICROSOFT_UI_LOCALE))
    return urllib.parse.urlunsplit((
        parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(params), parsed.fragment
    ))


async def _click_microsoft_action(
    page, labels=MS_POSITIVE_ACTION_LABELS, negative_labels=MS_NEGATIVE_ACTION_LABELS,
    preferred_ids=(), include_links=False,
):
    """Click a visible Microsoft action using IDs first and localized text second."""
    script = r"""({labels, negativeLabels, preferredIds, includeLinks}) => {
            const normalize = value => String(value || '')
                .replace(/\s+/g, ' ').trim().toLocaleLowerCase();
            const visible = el => {
                const style = getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                return !el.disabled && el.getAttribute('aria-disabled') !== 'true'
                    && style.display !== 'none' && style.visibility !== 'hidden'
                    && rect.width > 0 && rect.height > 0;
            };
            const textOf = el => normalize(
                el.value || el.innerText || el.textContent
                || el.getAttribute('aria-label') || el.getAttribute('title')
            );
            const blocked = text => negativeLabels.some(label =>
                text === label || text.startsWith(label + ' ')
            );
            for (const id of preferredIds) {
                const el = document.getElementById(id);
                if (el && visible(el) && !blocked(textOf(el))) {
                    el.click();
                    return textOf(el) || '#' + id;
                }
            }
            const controls = document.querySelectorAll(
                includeLinks
                    ? 'button, a, input[type="submit"], input[type="button"], [role="button"]'
                    : 'button, a[role="button"], input[type="submit"], input[type="button"], [role="button"]'
            );
            for (const el of controls) {
                if (!visible(el)) continue;
                const text = textOf(el);
                if (!text || blocked(text)) continue;
                if (labels.some(label => text === label || text.startsWith(label + ' '))) {
                    el.click();
                    return text;
                }
            }
            if (includeLinks) return '';
            const positiveIdentifiers = new Set([
                'accept', 'allow', 'approve', 'consent', 'continue',
                'next', 'yes', 'confirm', 'primary'
            ]);
            const negativeIdentifiers = new Set([
                'deny', 'decline', 'reject', 'cancel', 'no', 'back', 'secondary'
            ]);
            for (const el of controls) {
                if (!visible(el)) continue;
                const semantic = normalize([
                    el.id, el.getAttribute('name'), el.getAttribute('data-testid'),
                    el.getAttribute('data-test-id'), el.getAttribute('aria-label')
                ].filter(Boolean).join(' '));
                const tokens = semantic.split(/[^a-z0-9]+/).filter(Boolean);
                if (tokens.some(token => negativeIdentifiers.has(token))) continue;
                if (tokens.some(token => positiveIdentifiers.has(token))) {
                    el.click();
                    return semantic || textOf(el);
                }
            }
            return '';
        }"""
    payload = {
        "labels": [label.lower() for label in labels],
        "negativeLabels": [label.lower() for label in negative_labels],
        "preferredIds": list(preferred_ids),
        "includeLinks": bool(include_links),
    }
    # KMSI and consent controls may be rendered inside an auth iframe. The
    # page body still exposes the prompt text, so checking only the top-level
    # document can report "detected" forever without finding its button.
    targets = [page]
    try:
        targets.extend(frame for frame in page.frames if frame is not page)
    except Exception:
        pass
    for target in targets:
        try:
            clicked = await target.evaluate(script, payload)
            if clicked:
                return clicked
        except Exception:
            continue
    return ""


def _birthdate_field_kind(metadata):
    """Classify a birth-date field from stable metadata across UI locales."""
    value = " ".join(str(metadata.get(key) or "") for key in (
        "id", "name", "ariaLabel", "placeholder", "text"
    )).lower()
    stable_tokens = (
        ("month", ("birthmonth",)),
        ("year", ("birthyear",)),
        ("country", ("country", "region")),
        ("day", ("birthday", "birthdate")),
    )
    for kind, kind_tokens in stable_tokens:
        if any(token in value for token in kind_tokens):
            return kind
    tokens = {
        "month": ("birthmonth", "month", "mois", "mes", "monat", "mês", "mese",
                  "maand", "miesiąc", "месяц", "bulan", "महीना", "माह", "月", "월"),
        "day": ("birthday", "birthdate", "day", "jour", "día", "dia", "tag",
                "giorno", "dag", "dzień", "день", "gün", "hari", "दिन", "日", "일"),
        "year": ("birthyear", "year", "année", "año", "ano", "jahr", "anno",
                 "jaar", "rok", "год", "yıl", "tahun", "वर्ष", "साल", "年", "년"),
        "country": ("country", "region", "pays", "país", "land", "paese",
                    "kraj", "страна", "ülke", "negara", "wilayah", "देश", "क्षेत्र",
                    "国家", "國家", "国", "국가"),
    }
    if value.strip() == "ay":
        return "month"
    # Stable IDs such as BirthMonthDropdown contain "birthday" as a substring.
    for kind in ("month", "year", "country", "day"):
        if any(token in value for token in tokens[kind]):
            return kind
    return ""


async def _birthdate_combo_state(combo):
    try:
        state = await combo.evaluate(r"""el => ({
            text: String(el.innerText || el.textContent || '').trim(),
            value: String(el.value || el.getAttribute('data-value') || '').trim(),
            label: String(el.getAttribute('aria-label') || '').trim(),
            active: String(el.getAttribute('aria-activedescendant') || '').trim(),
            expanded: el.getAttribute('aria-expanded') === 'true'
        })""", timeout=1500)
        if isinstance(state, dict):
            return state
    except Exception:
        pass
    return {
        "text": (await combo.text_content() or "").strip(),
        "value": (await combo.get_attribute("value") or "").strip(),
        "label": (await combo.get_attribute("aria-label") or "").strip(),
        "active": "",
        "expanded": False,
    }


def _birthdate_combo_selected(before, after, value, kind):
    fields = ("text", "value", "label", "active")
    before_values = tuple(str(before.get(field) or "").strip() for field in fields)
    after_values = tuple(str(after.get(field) or "").strip() for field in fields)
    combined = " ".join(after_values)
    numbers = {
        int(match)
        for match in re.findall(r"(?<!\d)(\d{1,2})(?!\d)", combined)
    }
    if int(value) in numbers:
        return True
    if kind != "month" or before_values == after_values:
        return False
    selected_text = str(after.get("text") or after.get("value") or "").strip()
    placeholders = {
        "", "month", "birth month", "select month", "choose month",
        "mm", "--", "-",
    }
    return selected_text.lower() not in placeholders


async def _click_birthdate_option(page, value, kind):
    try:
        return await page.evaluate(r"""payload => {
            const visible = el => {
                const rect = el.getBoundingClientRect();
                const style = getComputedStyle(el);
                return rect.width > 0 && rect.height > 0
                    && style.display !== 'none' && style.visibility !== 'hidden'
                    && el.getAttribute('aria-disabled') !== 'true';
            };
            const all = [...document.querySelectorAll(
                '[role="option"], [role="menuitemradio"], option'
            )].filter(visible);
            const usable = all.filter(el => {
                const disabled = el.disabled || el.getAttribute('aria-disabled') === 'true';
                const text = String(el.textContent || el.getAttribute('aria-label') || '').trim();
                return !disabled && text && !/^(month|day|select|choose|--|-)$/i.test(text);
            });
            const numericValue = el => {
                const candidates = [
                    el.getAttribute('data-value'), el.getAttribute('value'),
                    el.getAttribute('aria-label'), el.textContent
                ];
                for (const candidate of candidates) {
                    const match = String(candidate || '').trim().match(/^(\d{1,2})(?:\D.*)?$/);
                    if (match) return Number(match[1]);
                }
                return null;
            };
            let target = usable.find(option => numericValue(option) === Number(payload.value));
            if (!target && payload.kind === 'month' && usable.length >= 12) {
                target = usable[Number(payload.value) - 1];
            }
            if (!target) return false;
            target.scrollIntoView({block: 'nearest'});
            target.focus();
            for (const type of ['mousedown', 'mouseup']) {
                target.dispatchEvent(new MouseEvent(type, {bubbles: true, cancelable: true, view: window}));
            }
            target.click();
            return true;
        }""", {"value": int(value), "kind": kind})
    except Exception:
        return False


async def _select_birthdate_combo_option(page, combo, value, kind="month"):
    """Select and verify a Microsoft ARIA month/day combobox."""
    value = int(value)
    if kind not in {"month", "day"}:
        raise ValueError(f"unsupported birthdate combo kind: {kind}")
    if value < 1 or value > (12 if kind == "month" else 31):
        raise ValueError(f"invalid birthdate {kind}: {value}")

    before = await _birthdate_combo_state(combo)
    for attempt in range(3):
        if attempt:
            try:
                await page.keyboard.press("Escape")
            except Exception:
                pass
        try:
            await combo.click(force=True)
        except Exception:
            await combo.evaluate("el => { el.focus(); el.click(); return true; }")
        await asyncio.sleep(0.35)

        clicked = (
            await _click_birthdate_option(page, value, kind)
            if attempt == 0
            else False
        )
        if not clicked:
            # Keyboard navigation remains reliable when the option portal is
            # hidden from DOM queries by Microsoft's component implementation.
            await page.keyboard.press("Home")
            down_count = value - 1 + (1 if attempt == 2 else 0)
            for _ in range(down_count):
                await page.keyboard.press("ArrowDown")
            await page.keyboard.press("Enter")
        await asyncio.sleep(0.45)

        after = await _birthdate_combo_state(combo)
        if _birthdate_combo_selected(before, after, value, kind):
            return True
    raise RuntimeError(f"Microsoft {kind} dropdown did not commit value {value}")


async def _select_native_numeric_option(select, value):
    """Select month/day from a native select with localized option labels."""
    for candidate in (str(value), f"{value:02d}"):
        try:
            await select.select_option(value=candidate)
            return True
        except Exception:
            pass
    try:
        options = select.locator("option")
        count = await options.count()
        for index in range(count):
            option = options.nth(index)
            option_value = (await option.get_attribute("value") or "").strip()
            option_text = (await option.text_content() or "").strip()
            for candidate in (option_value, option_text):
                match = re.match(r"^(\d{1,2})(?:\D.*)?$", candidate)
                if match and int(match.group(1)) == value:
                    await select.select_option(index=index)
                    return True
        # Localized month names retain chronological order. A 13th item is
        # normally the placeholder; a 12-item list starts directly at January.
        if count >= 13 and value <= 12:
            await select.select_option(index=value)
            return True
        if count >= 12 and value <= 12:
            await select.select_option(index=value - 1)
            return True
    except Exception:
        pass
    return False


async def _signup_email_rejected(page, email_input):
    """Detect a rejected alias from field validity/ARIA before localized text."""
    try:
        if await email_input.count() == 0:
            return ""
        state = await email_input.evaluate(r"""el => {
            const described = (el.getAttribute('aria-describedby') || '')
                .split(/\s+/).filter(Boolean)
                .map(id => document.getElementById(id)?.innerText || '').join(' ');
            const nearby = el.closest('form, [role="main"], main')?.innerText || '';
            return {
                ariaInvalid: el.getAttribute('aria-invalid') === 'true',
                typeMismatch: !!el.validity?.typeMismatch,
                patternMismatch: !!el.validity?.patternMismatch,
                customError: !!el.validity?.customError,
                message: [el.validationMessage, described, nearby].join(' ').toLowerCase(),
                visible: !!el.offsetParent,
            };
        }""", timeout=1000)
    except Exception:
        state = {}
    message = state.get("message") or ""
    format_markers = (
        "valid", "format", "letter", "caractère", "formato", "gültig",
        "válido", "valido", "corretto", "geldig", "prawidł", "допустим",
        "geçerli", "मान्य", "अक्षर", "huruf", "格式", "有效", "文字", "올바른",
    )
    if (
        state.get("typeMismatch")
        or state.get("patternMismatch")
        or any(marker in message for marker in format_markers)
    ):
        return "format"
    if state.get("ariaInvalid") or state.get("customError"):
        return "taken"
    return ""


def _microsoft_direct_session():
    """Exchange OAuth codes directly; signup proxy state must not affect Graph."""
    session = requests.Session()
    session.trust_env = False
    session.proxies = {"http": None, "https": None}
    return session


def _request_graph_device_code():
    for attempt in range(1, 4):
        session = _microsoft_direct_session()
        try:
            response = session.post(
                GRAPH_DEVICE_CODE_URL,
                data={"client_id": GRAPH_CLIENT_ID, "scope": GRAPH_SCOPE},
                timeout=30,
            )
            data = response.json()
            if response.status_code == 200 and data.get("device_code") and data.get("user_code"):
                return data
            error = data.get("error_description") or data.get("error") or "unknown error"
            print(f"  [graph] device-code request failed: {str(error)[:140]}")
            return None
        except Exception as e:
            if attempt < 3:
                time.sleep(1.5)
                continue
            print(f"  [graph] device-code request error: {str(e)[:120]}")
            return None
        finally:
            session.close()
    return None


def _exchange_graph_device_code(device_code):
    """Perform one non-blocking device-code token poll."""
    session = _microsoft_direct_session()
    try:
        response = session.post(
            GRAPH_TOKEN_URL,
            data={
                "client_id": GRAPH_CLIENT_ID,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            },
            timeout=30,
        )
        data = response.json()
    except Exception as e:
        return "retry", {"error_description": str(e)}
    finally:
        session.close()
    if response.status_code == 200 and data.get("access_token"):
        data["client_id"] = GRAPH_CLIENT_ID
        return "ready", data
    error = data.get("error") or ""
    if error in {"authorization_pending", "slow_down"}:
        return "pending", data
    return "failed", data


async def _skip_optional_recovery_email(page, idx=0):
    """Skip optional recovery/alternate-email enrollment in any common locale."""
    tag = f"[#{idx}]"
    try:
        body = " ".join(
            (await page.locator("body").inner_text(timeout=3000)).split()
        ).lower()
    except Exception:
        return False, False
    try:
        current_url = (page.url or "").lower()
    except Exception:
        current_url = ""
    page_markers = (
        "recovery email", "alternate email", "add an email address",
        "security info", "help us protect your account",
        "help protect your account", "add an email", "add email",
        "アカウントの保護にご協力ください", "メール アドレスを追加", "メールの追加",
        "adresse e-mail de récupération", "informations de sécurité",
        "correo de recuperación", "información de seguridad",
        "wiederherstellungs-e-mail", "sicherheitsinformationen",
        "email de recuperação", "informações de segurança",
        "email di recupero", "informazioni di sicurezza",
        "herstel-e-mailadres", "beveiligingsgegevens",
        "adres e-mail odzyskiwania", "informacje zabezpieczające",
        "резервный адрес электронной почты", "сведения для защиты",
        "kurtarma e-postası", "güvenlik bilgileri",
        "辅助邮箱", "恢复邮箱", "备用邮箱", "添加电子邮件",
        "帮助我们保护你的帐户", "協助我們保護您的帳戶",
        "復原電子郵件", "備用電子郵件", "セキュリティ情報",
        "回復用メール", "보안 정보", "복구 이메일",
        "पुनर्प्राप्ति ईमेल", "वैकल्पिक ईमेल", "सुरक्षा जानकारी",
        "खाता सुरक्षित रखने में हमारी मदद करें",
        "email pemulihan", "email alternatif", "info keamanan",
        "bantu kami melindungi akun anda", "tambahkan alamat email",
    )
    detected = "/proofs/add" in current_url or any(marker in body for marker in page_markers)
    if not detected:
        return False, False
    clicked = await _click_microsoft_action(
        page, labels=MS_SKIP_ACTION_LABELS, negative_labels=(),
        preferred_ids=("iShowSkip", "idBtn_Skip", "skipBtn", "Skip"),
    )
    if clicked:
        print(f"  {tag} [graph] skipped optional recovery email")
        await asyncio.sleep(2)
        return True, True
    return True, False


def _graph_recovery_settings():
    try:
        import config as _config
    except Exception:
        _config = None
    enabled = getattr(_config, "OUTLOOK_GRAPH_RECOVERY_EMAIL", None)
    if enabled is None:
        enabled = os.environ.get("OUTLOOK_GRAPH_RECOVERY_EMAIL", "true")
        enabled = str(enabled).strip().lower() in {"1", "true", "yes", "on"}
    provider = getattr(_config, "OUTLOOK_GRAPH_RECOVERY_PROVIDER", "") or os.environ.get(
        "OUTLOOK_GRAPH_RECOVERY_PROVIDER", "yyds"
    )
    timeout = getattr(_config, "OUTLOOK_GRAPH_RECOVERY_TIMEOUT", None)
    interval = getattr(_config, "OUTLOOK_GRAPH_RECOVERY_POLL_INTERVAL", None)
    try:
        timeout = max(10, int(timeout if timeout is not None else os.environ.get(
            "OUTLOOK_GRAPH_RECOVERY_TIMEOUT", "120"
        )))
    except (TypeError, ValueError):
        timeout = 120
    try:
        interval = max(1, int(interval if interval is not None else os.environ.get(
            "OUTLOOK_GRAPH_RECOVERY_POLL_INTERVAL", "5"
        )))
    except (TypeError, ValueError):
        interval = 5
    return bool(enabled), str(provider).strip() or "yyds", timeout, interval


def _graph_recovery_outlook_mailbox():
    """Return the configured user-owned Outlook inbox record without logging it."""
    try:
        import config as _config
    except Exception:
        _config = None
    return str(
        getattr(_config, "OUTLOOK_GRAPH_RECOVERY_OUTLOOK_MAILBOX", "")
        or os.environ.get("OUTLOOK_GRAPH_RECOVERY_OUTLOOK_MAILBOX", "")
    ).strip()


async def _first_visible(locator):
    """Return the first visible match, skipping hidden inputs ahead of it."""
    try:
        count = int(await locator.count())
    except Exception:
        return None
    for index in range(min(count, 12)):
        item = locator.nth(index)
        try:
            if await item.is_visible():
                return item
        except Exception:
            continue
    return None


async def _recovery_email_form_diagnostics(page):
    """Return safe control metadata for a recovery-email form that will not advance."""
    try:
        captured = await page.evaluate(r"""() => {
            const visible = el => {
                const style = getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                return style.display !== 'none' && style.visibility !== 'hidden'
                    && rect.width > 0 && rect.height > 0;
            };
            const identity = value => String(value || '').slice(0, 80);
            return {
                path: String(location.pathname || '').slice(0, 160),
                inputs: [...document.querySelectorAll('input')]
                    .filter(visible).slice(0, 6).map(el => ({
                        type: identity(el.type),
                        id: identity(el.id),
                        name: identity(el.name),
                        disabled: !!el.disabled,
                        ariaInvalid: el.getAttribute('aria-invalid') === 'true',
                        valid: typeof el.checkValidity === 'function' ? el.checkValidity() : null,
                        valueLength: String(el.value || '').length,
                        message: identity(el.validationMessage),
                    })),
                buttons: [...document.querySelectorAll(
                    'button, input[type="submit"], input[type="button"]'
                )].filter(visible).slice(0, 8).map(el => ({
                    id: identity(el.id),
                    type: identity(el.type),
                    disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true',
                })),
            };
        }""", timeout=2000)
    except Exception:
        return {"capture": "unavailable"}
    if not isinstance(captured, dict):
        return {"capture": "unavailable"}

    def _text(value, limit=160):
        return str(value or "")[:limit]

    inputs = []
    for item in list(captured.get("inputs") or [])[:6]:
        if not isinstance(item, dict):
            continue
        inputs.append({
            "type": _text(item.get("type"), 40),
            "id": _text(item.get("id"), 80),
            "name": _text(item.get("name"), 80),
            "disabled": bool(item.get("disabled")),
            "ariaInvalid": bool(item.get("ariaInvalid")),
            "valid": item.get("valid") if item.get("valid") in {True, False, None} else None,
            "valueLength": max(0, int(item.get("valueLength") or 0)),
            "message": _text(item.get("message"), 80),
        })
    buttons = []
    for item in list(captured.get("buttons") or [])[:8]:
        if not isinstance(item, dict):
            continue
        buttons.append({
            "id": _text(item.get("id"), 80),
            "type": _text(item.get("type"), 40),
            "disabled": bool(item.get("disabled")),
        })
    return {"path": _text(captured.get("path")), "inputs": inputs, "buttons": buttons}


async def _click_primary_submit(page):
    """Click the visible primary submit control. Its label is localized."""
    button = await _first_visible(page.locator(
        'button[type="submit"], input[type="submit"]'
    ))
    if button is None:
        return False
    try:
        await button.click()
        return True
    except Exception:
        return False


async def _recovery_code_boxes(page):
    """Return Microsoft's split code boxes in DOM order."""
    locator = page.locator('input[id^="codeEntry-"]')
    try:
        count = int(await locator.count())
    except Exception:
        return []
    boxes = []
    for index in range(min(count, 8)):
        item = locator.nth(index)
        try:
            if await item.is_visible():
                boxes.append(item)
        except Exception:
            continue
    return boxes


async def _return_to_recovery_email_form(page, state, tag):
    """Leave a code page whose address cannot receive the message."""
    if state.get("code_back_tried"):
        return False
    back = await _first_visible(page.locator(
        '#back-button, button[aria-label="Back" i]'
    ))
    if back is None:
        return False
    await back.click()
    state["code_back_tried"] = True
    state["email_submitted"] = False
    state["code_submitted"] = False
    state.pop("mailbox", None)
    state.pop("code_task", None)
    state.pop("code_requested_at", None)
    print(f"  {tag} [graph] left undeliverable code page")
    await asyncio.sleep(2)
    return True


_RECOVERY_CODE_REJECTION_MARKERS = (
    "that code didn't work", "check the code and try again",
    "the code you entered is incorrect", "that code is incorrect",
    "invalid code",
)


def _recovery_code_was_rejected(body):
    normalized = " ".join(str(body or "").lower().split())
    return any(marker in normalized for marker in _RECOVERY_CODE_REJECTION_MARKERS)


async def _resend_rejected_recovery_code(page, state, tag):
    """Request one replacement recovery code and exclude the rejected value."""
    retries = int(state.get("code_retry_count") or 0)
    if retries >= 1:
        state["recovery_code_rejected"] = True
        print(f"  {tag} [graph] recovery code was rejected after resend")
        return False
    old_task = state.pop("code_task", None)
    if old_task and old_task.done():
        with contextlib.suppress(Exception):
            old_code = str(old_task.result())
            state.setdefault("rejected_codes", []).append(old_code)
    clicked = await _click_microsoft_action(
        page,
        labels=("resend code", "resend", "send a new code", "resend verification code"),
        negative_labels=(),
        preferred_ids=("idSubmit_SAOTCResend", "idBtn_SAOTCResend", "resendCodeButton", "ResendCode"),
        include_links=True,
    )
    if not clicked:
        resend_link = await _first_visible(page.locator(
            'a:has-text("Resend code"), button:has-text("Resend code"), a:has-text("Resend"), #ResendCode, [aria-label*="resend" i]'
        ))
        if resend_link:
            with contextlib.suppress(Exception):
                await resend_link.click()
                clicked = "resend-text-link"
    if not clicked:
        return False
    state["code_submitted"] = False
    state["code_retry_count"] = retries + 1
    state["code_requested_at"] = time.time()
    state.pop("code_timeout_logged", None)
    print(f"  {tag} [graph] recovery code rejected; resent once")
    await asyncio.sleep(2)
    return True


async def _bind_required_recovery_email(page, state, idx=0, account_email=""):
    """Fill Microsoft's security-info email form and submit its mailbox code."""
    tag = f"[#{idx}]"
    enabled, provider, timeout, interval = _graph_recovery_settings()
    if not enabled:
        return False, False
    try:
        current_url = (page.url or "").lower()
        body = " ".join((await page.locator("body").inner_text(timeout=3000)).split()).lower()
    except Exception:
        return False, False
    if "reached your limit with this sign-in method" in body:
        return False, False
    markers = (
        "/proofs/add", "recovery email", "alternate email", "add an email address",
        "security info", "help us protect your account", "security information",
        "help protect your account", "add an email", "add email",
        "enter your code", "we sent a code", "code we sent",
        "アカウントの保護にご協力ください", "メール アドレスを追加", "メールの追加",
        "杈呭姪閭", "鎭㈠閭", "澶囩敤閭", "娣诲姞鐢靛瓙閭欢",
        "पुनर्प्राप्ति ईमेल", "वैकल्पिक ईमेल", "सुरक्षा जानकारी",
        "खाता सुरक्षित रखने में हमारी मदद करें",
        "email pemulihan", "email alternatif", "info keamanan",
        "bantu kami melindungi akun anda", "tambahkan alamat email",
    )
    if state.get("code_submitted") and _recovery_code_was_rejected(body):
        return True, await _resend_rejected_recovery_code(page, state, tag)
    radio_proof_page = (
        (
            "call us overprotective" in body
            or "where should we send your code" in body
            or "help us protect your account" in body
            or "something unusual about this sign-in" in body
            or "protect your account" in body
        )
        and await page.locator('input[type="radio"]').count() > 0
    )
    if radio_proof_page and not state.get("email_submitted"):
        if not state.get("mailbox") and account_email:
            from common.mailbox import restore_graph_recovery_mailbox
            state["mailbox"] = await asyncio.to_thread(
                restore_graph_recovery_mailbox, account_email
            )
        radios = page.locator('input[type="radio"]')
        rcount = await radios.count()
        target_radio = None
        mb_email = ((state.get("mailbox") or {}).get("email") or "").lower()
        for r_idx in range(rcount):
            r_elem = radios.nth(r_idx)
            try:
                if await r_elem.is_visible():
                    if mb_email:
                        p_text = " ".join((await r_elem.locator("xpath=..").inner_text(timeout=1000)).split()).lower()
                        if mb_email in p_text or mb_email.split("@")[0] in p_text:
                            target_radio = r_elem
                            break
                    if target_radio is None:
                        target_radio = r_elem
            except Exception:
                continue
        if target_radio is not None:
            try:
                await target_radio.evaluate(
                    "el => { el.checked = true; el.dispatchEvent(new Event('change', {bubbles: true})); el.dispatchEvent(new Event('input', {bubbles: true})); el.click(); }"
                )
            except Exception:
                pass
            with contextlib.suppress(Exception):
                p_label = target_radio.locator("xpath=ancestor::label[1]")
                if await p_label.count() > 0:
                    await p_label.first.click(timeout=1000)
                else:
                    await target_radio.locator("xpath=..").click(timeout=1000)
            await asyncio.sleep(0.5)
            clicked = await _click_primary_submit(page)
            if not clicked:
                clicked = await _click_microsoft_action(
                    page,
                    labels=("next", "send code", "continue", "下一步", "发送代码"),
                    preferred_ids=("iNext", "idSubmit_SAOTCSend", "idBtn_SAOTCSend", "continueButton"),
                    include_links=True,
                )
            if clicked:
                state["email_submitted"] = True
                state["code_requested_at"] = time.time()
                print(f"  {tag} [graph] selected existing recovery email radio; advancing")
                await asyncio.sleep(2)
                return True, True
    proof_input = await _first_visible(page.locator("#proof-confirmation-email-input"))
    if proof_input is not None:
        if not state.get("mailbox") and account_email:
            from common.mailbox import (
                restore_graph_recovery_mailbox,
                restore_graph_recovery_mailbox_from_mask,
            )

            state["mailbox"] = await asyncio.to_thread(
                restore_graph_recovery_mailbox, account_email
            )
            if not state["mailbox"]:
                masked = re.search(
                    r"[a-z0-9._+-]+\*+@[a-z0-9-]+(?:\.[a-z0-9-]+)+",
                    body,
                )
                if masked:
                    state["mailbox"] = await asyncio.to_thread(
                        restore_graph_recovery_mailbox_from_mask, masked.group(0)
                    )
                    if state["mailbox"]:
                        from common.mailbox import remember_graph_recovery_mailbox

                        await asyncio.to_thread(
                            remember_graph_recovery_mailbox,
                            account_email,
                            state["mailbox"],
                        )
        mailbox = state.get("mailbox")
        if mailbox and not state.get("email_submitted"):
            try:
                await proof_input.fill(mailbox["email"])
                clicked = await _click_microsoft_action(
                    page,
                    labels=(
                        "send code", "send a code", "email me a code",
                        "send verification code", "发送代码", "发送验证码",
                    ),
                    negative_labels=(),
                    preferred_ids=(
                        "idSubmit_SAOTCSend", "idBtn_SAOTCSend", "sendCodeButton",
                    ),
                    include_links=True,
                )
                if not clicked:
                    clicked = await _click_primary_submit(page)
                if not clicked:
                    await proof_input.press("Enter")
                state["email_submitted"] = True
                state["code_requested_at"] = time.time()
                print(f"  {tag} [graph] resumed saved recovery mailbox; sent code")
                await asyncio.sleep(2)
                return True, True
            except Exception as exc:
                print(f"  {tag} [graph] saved recovery mailbox submit failed: {str(exc)[:120]}")
                return True, False
        if not state.get("proof_confirmation_logged"):
            state["proof_confirmation_logged"] = True
            state["unrecoverable_proof"] = True
            print(
                f"  {tag} [graph] existing proof email confirmation is visible; "
                "no saved recovery mailbox is available"
            )
        return True, False
    on_recovery_page = (
        "/interrupt/credentialaction" in current_url
        or any(marker in current_url or marker in body for marker in markers)
    )
    # A submitted code must not keep claiming success after Microsoft has moved on.
    # Otherwise the device loop treats every later page as a completed recovery action
    # and never clicks the password, account, or consent controls.
    if state.get("code_submitted") and not on_recovery_page:
        return False, False
    if not (
        state.get("email_submitted") or state.get("code_task") or on_recovery_page
    ):
        return False, False
    state.setdefault("code_submitted", False)
    if state.get("code_submitted"):
        clicked = await _click_microsoft_action(
            page,
            labels=("continue", "next", "继续", "下一步", "ok", "done", "完成", "yes"),
            preferred_ids=("iNext", "idSIButton9", "continueButton", "idSubmit_SAOTC"),
            include_links=True,
        )
        if not clicked:
            clicked = await _click_primary_submit(page)
        if clicked:
            if not state.get("post_verify_logged"):
                state["post_verify_logged"] = True
                print(f"  {tag} [graph] continued after recovery email")
                await asyncio.sleep(2)
            return True, True
        return False, False

    email_form = (
        "we'll send codes" in body
        or "we will send codes" in body
        or "security alerts for your microsoft account" in body
    )
    code_page_markers = (
        "enter the code", "enter code", "security code", "verification code",
        "we sent a code", "code we sent", "check your email",
        "输入验证码", "输入代码", "验证码",
    )
    # Microsoft's email-entry step is titled "Enter your code" but its body says
    # "If <addr> matches the email address on your account, we'll send you a code".
    # Treating that as a code page skipped the email input, so the form never
    # advanced and no code was ever requested.
    email_entry_page = (
        "matches the email address on your account" in body
        or "we'll send you a code" in body
        or "we will send you a code" in body
        or "votre adresse e-mail correspond" in body
        or "le enviaremos un código" in body
    )
    code_page = (not email_entry_page) and any(
        marker in body for marker in code_page_markers
    )
    email_input = None
    if not (state.get("email_submitted") and code_page and not email_entry_page):
        email_input = await _first_visible(page.locator(
            'input[type="email"], input[name*="email" i], input[id*="email" i], '
            'input[name*="address" i], input[id*="address" i], '
            'input[id^="floatingLabelInput" i]'
        ))
    if email_input is None and email_form:
        email_input = await _first_visible(page.locator(
            'input[type="text"], input:not([type])'
        ))
    has_email = email_input is not None
    if has_email:
        if not state.get("mailbox"):
            try:
                from common.mailbox import (
                    create_graph_recovery_mailbox,
                    restore_graph_recovery_mailbox,
                )
                # Prefer the address already bound to this account; minting a
                # fresh mailbox each attempt leaves several extra recovery
                # addresses on the account and blocks the real one.
                if account_email:
                    state["mailbox"] = await asyncio.to_thread(
                        restore_graph_recovery_mailbox, account_email
                    )
                if not state.get("mailbox"):
                    state["mailbox"] = await asyncio.to_thread(
                        create_graph_recovery_mailbox,
                        provider,
                        _graph_recovery_outlook_mailbox(),
                    )
                if account_email:
                    from common.mailbox import remember_graph_recovery_mailbox

                    await asyncio.to_thread(
                        remember_graph_recovery_mailbox,
                        account_email,
                        state["mailbox"],
                    )
                print(f"  {tag} [graph] binding recovery email via {state['mailbox']['provider']}: "
                      f"{state['mailbox']['email']}")
            except Exception as exc:
                print(f"  {tag} [graph] recovery mailbox create failed: {str(exc)[:140]}")
                return True, False
        attempts = int(
            state.get("email_submit_attempts")
            or (1 if state.get("email_submitted") else 0)
        )
        if state.get("email_submitted") and attempts >= 3:
            state["recovery_email_submit_stalled"] = True
            diagnostics = await _recovery_email_form_diagnostics(page)
            print(
                f"  {tag} [graph] recovery email form stayed open after "
                f"{attempts} submissions"
            )
            print(f"  {tag} [graph] recovery email form diagnostics: {diagnostics}")
            return True, False
        try:
            await email_input.fill(state["mailbox"]["email"])
            clicked = await _click_microsoft_action(
                page,
                labels=(
                    "next", "send code", "send a code", "continue",
                    "下一步", "发送代码", "发送验证码", "email me a code",
                ),
                negative_labels=(),
                preferred_ids=(
                    "iNext", "idSubmit_SAOTCSend", "idBtn_SAOTCSend",
                    "idSubmit_SAOTC", "idBtn_SAOTC", "continueButton",
                ),
                include_links=True,
            )
            if not clicked:
                clicked = await _click_primary_submit(page)
            if not clicked:
                await email_input.press("Enter")
                clicked = "enter"
            state["email_submitted"] = True
            state["email_submit_attempts"] = attempts + 1
            state["email_submit_action"] = str(clicked or "")[:80]
            state["code_requested_at"] = time.time()
            if attempts:
                print(
                    f"  {tag} [graph] recovery email form did not advance; "
                    f"resubmitted ({attempts + 1}/3)"
                )
            await asyncio.sleep(2)
            return True, True
        except Exception as exc:
            print(f"  {tag} [graph] recovery email submit failed: {str(exc)[:120]}")
            return True, False

    code_input = await _first_visible(page.locator(
        'input[autocomplete="one-time-code"], input[name*="otc" i], input[id*="otc" i], '
        'input[name*="code" i], input[id*="code" i], input[name*="ott" i], input[id*="ott" i]'
    ))
    if (
        code_input is None
        and state.get("email_submitted")
        and not email_entry_page
        and (code_page or (not email_form and "code" in body))
    ):
        code_input = await _first_visible(page.locator(
            'input[id^="floatingLabelInput" i], input[type="text"]'
        ))
    has_code = code_input is not None
    add_email_intro = (
        "add an email" in body
        or "add email" in body
        or "help protect your account" in body
        or "pomagajte zascititi" in body
        or "pomagajte zaščititi" in body
        or "dodajte e-postni" in body
        or "dodajte e-poštni" in body
    )
    if not has_email and not state.get("email_submitted") and add_email_intro:
        clicked = await _click_microsoft_action(
            page,
            labels=(
                "add email", "add an email", "add an email address",
                "メールの追加", "メールアドレスを追加",
                "添加电子邮件", "添加邮箱",
            ),
            negative_labels=(),
            include_links=True,
        )
        if not clicked:
            clicked = await _click_primary_submit(page)
        if clicked:
            state["add_email_opened"] = True
            attempts = int(state.get("add_email_attempts") or 0) + 1
            state["add_email_attempts"] = attempts
            print(f"  {tag} [graph] opening add-email form (attempt {attempts})")
            await asyncio.sleep(2)
            return True, True

    if not has_code:
        return True, False
    if not state.get("code_task"):
        from common.mailbox import poll_graph_recovery_code
        mailbox = state.get("mailbox")
        if not mailbox:
            if await _return_to_recovery_email_form(page, state, tag):
                return True, True
            print(f"  {tag} [graph] recovery code page has no mailbox state")
            return True, False
        state["code_task"] = asyncio.create_task(asyncio.to_thread(
            poll_graph_recovery_code,
            mailbox,
            max_wait=timeout,
            poll_interval=interval,
            received_after=state.get("code_requested_at"),
            exclude_codes=state.get("rejected_codes", ()),
        ))
        return True, True
    task = state["code_task"]
    if not task.done():
        return True, True
    try:
        code = task.result()
    except Exception as exc:
        print(f"  {tag} [graph] recovery code poll failed: {str(exc)[:120]}")
        return True, False
    if not code:
        if int(state.get("code_retry_count") or 0) >= 1:
            state["recovery_code_delivery_timeout"] = True
            print(f"  {tag} [graph] recovery code delivery timed out after resend")
            return True, False
        if await _return_to_recovery_email_form(page, state, tag):
            return True, True
        if not state.get("code_timeout_logged"):
            print(f"  {tag} [graph] recovery code timed out")
            state["code_timeout_logged"] = True
        return True, False
    try:
        boxes = await _recovery_code_boxes(page)
        digits = "".join(ch for ch in str(code) if ch.isdigit())
        # A rejected code stays in Microsoft's boxes until cleared, so refilling
        # them is a no-op and the resent code keeps showing the old error.
        for box in boxes:
            with contextlib.suppress(Exception):
                await box.fill("")
        with contextlib.suppress(Exception):
            await code_input.fill("")
        if len(boxes) >= 4 and len(digits) >= len(boxes):
            try:
                await boxes[0].focus()
                await page.keyboard.type(digits, delay=60)
            except Exception:
                pass
            for box, digit in zip(boxes, digits):
                try:
                    if await box.input_value() != digit:
                        await box.fill(digit)
                except Exception:
                    pass
            clicked = await _click_primary_submit(page)
            if not clicked:
                clicked = await _click_microsoft_action(
                    page, preferred_ids=("iNext", "idSubmit_SAOTC", "idBtn_SAOTC", "continueButton")
                )
            if not clicked:
                with contextlib.suppress(Exception):
                    await boxes[-1].press("Enter", timeout=1000)
        else:
            # Single-field OTP forms do not always submit on fill(); when the
            # Enter/submit click is a no-op the loop used to return "verified"
            # on an unsubmitted code and then idle until the device code expired.
            await code_input.fill(str(code))
            clicked = await _click_microsoft_action(
                page, preferred_ids=("iNext", "idSubmit_SAOTC", "idBtn_SAOTC", "continueButton")
            )
            if not clicked:
                try:
                    await code_input.press("Enter")
                except Exception:
                    pass
        state["code_submitted"] = True
        print(f"  {tag} [graph] recovery email verified")
        await asyncio.sleep(2)
        try:
            page_text = " ".join(
                (await page.locator("body").inner_text(timeout=3000)).split()
            )
        except Exception:
            page_text = ""
        still_on_code_page = bool(
            _recovery_code_was_rejected(page_text)
            or re.search(r"enter your code|we sent a code|code we sent", page_text, re.I)
        )
        if still_on_code_page:
            state["code_submit_unconfirmed"] = int(state.get("code_submit_unconfirmed") or 0) + 1
            print(
                f"  {tag} [graph] recovery code not accepted yet "
                f"(attempt {state['code_submit_unconfirmed']}/2); page still shows the code form"
            )
            if state["code_submit_unconfirmed"] >= 2:
                return True, await _resend_rejected_recovery_code(page, state, tag)
            # Let the loop re-read the page and retry the submit.
            state["code_submitted"] = False
            state.pop("code_task", None)
            state["code_requested_at"] = time.time()
            return True, True
        return True, True
    except Exception as exc:
        print(f"  {tag} [graph] recovery code submit failed: {str(exc)[:120]}")
        return True, False


async def _skip_optional_passkey(page, idx=0):
    """Cancel optional Microsoft passkey enrollment without opening native UI."""
    tag = f"[#{idx}]"
    try:
        body = " ".join(
            (await page.locator("body").inner_text(timeout=3000)).split()
        ).lower()
    except Exception:
        return False, False
    try:
        current_url = (page.url or "").lower()
    except Exception:
        current_url = ""
    markers = (
        "setting up your passkey", "set up a passkey", "create a passkey",
        "passkey", "security key", "clé d’accès", "clave de acceso",
        "passschlüssel", "chave de acesso", "chiave di accesso",
        "wachtwoordsleutel", "klucz dostępu", "ключ доступа", "geçiş anahtarı",
        "通行密钥", "密碼金鑰", "パスキー", "패스키",
        "पासकी", "सुरक्षा कुंजी", "कुंजी सेट अप करना",
        "kunci sandi", "kunci keamanan", "buat kunci sandi",
    )
    detected = "passkey" in current_url or any(marker in body for marker in markers)
    if not detected:
        return False, False
    clicked = await _click_microsoft_action(
        page, labels=("cancel", "annuler", "cancelar", "abbrechen", "annulla",
                           "annuleren", "anuluj", "отмена", "iptal", "取消",
                           "キャンセル", "취소") + MS_SKIP_ACTION_LABELS,
        negative_labels=(),
        preferred_ids=("idBtn_Back", "iCancel", "cancelBtn", "skipBtn"),
    )
    if clicked:
        print(f"  {tag} [graph] skipped optional passkey setup")
        await asyncio.sleep(2)
        return True, True
    return True, False


async def _accept_microsoft_app_consent(page, idx=0):
    """Accept the Device Code app-consent interstitial without selecting Deny."""
    tag = f"[#{idx}]"
    try:
        current_url = (page.url or "").lower()
    except Exception:
        current_url = ""
    try:
        body = " ".join(
            (await page.locator("body").inner_text(timeout=3000)).split()
        ).lower()
    except Exception:
        body = ""
    detected = (
        "/consent/update" in current_url
        or "let this app access your info" in body
        or "needs your permission" in body
        or "允许此应用访问你的信息" in body
        or "讓此應用程式存取您的資訊" in body
        or "このアプリが情報にアクセスすることを許可" in body
        or "このアプリがあなたの情報にアクセスすることを許可" in body
        or "このアプリに情報へのアクセスを許可" in body
        or "이 앱이 사용자 정보에 액세스하도록 허용" in body
        or "autoriser cette application à accéder" in body
        or "permitir que esta aplicación acceda" in body
        or "dieser app den zugriff" in body
        or "permitir que este aplicativo acesse" in body
        or "consenti a questa app di accedere" in body
        or "deze app toegang geven" in body
        or "zezwolić tej aplikacji na dostęp" in body
        or "povolit této aplikaci přístup" in body
        or "tato aplikace potřebuje vaše oprávnění" in body
        or "разрешить этому приложению доступ" in body
        or "bu uygulamanın bilgilerinize erişmesine izin ver" in body
        or "هل تريد السماح لهذا التطبيق" in body
        or "يحتاج thunderbird للحصول على إذنك" in body
        or "इस ऐप को आपकी जानकारी एक्सेस करने दें" in body
        or "इस ऐप को आपकी जानकारी तक पहुंच की अनुमति दें" in body
        or "आपकी अनुमति आवश्यक है" in body
        or "izinkan aplikasi ini mengakses info anda" in body
        or "izinkan aplikasi ini mengakses informasi anda" in body
        or "aplikasi ini memerlukan izin anda" in body
    )
    if not detected:
        return False, False
    # The consent interstitial often paints its text before the Accept button is
    # enabled (it stays aria-disabled while the app metadata loads). Clicking once
    # and giving up leaves the device code to expire, so poll for up to ~15s.
    clicked = ""
    for wait_index in range(10):
        clicked = await _click_microsoft_action(
            page,
            preferred_ids=("idBtn_Accept", "acceptButton", "iAgree", "idSIButton9"),
            labels=(
                "accept", "allow", "continue", "agree",
                "accepter", "autoriser", "continuer", "aceptar", "permitir", "continuar",
                "akzeptieren", "zulassen", "weiter", "aceitar", "accetta", "consenti",
                "accepteren", "toestaan", "zaakceptuj", "принять", "продолжить",
                "kabul et", "接受", "同意", "继续", "承認", "동의", "계속",
                "izinkan", "lanjutkan", "sprejmi", "nadaljuj",
            ),
            include_links=False,
        )
        if clicked:
            break
        if wait_index == 0:
            print(f"  {tag} [graph] app consent detected; waiting for Accept control")
        await asyncio.sleep(1.5)
    if clicked:
        print(f"  {tag} [graph] accepted Microsoft app consent")
        await asyncio.sleep(2)
        return True, True
    print(f"  {tag} [graph] app consent detected; Accept control not ready")
    return True, False


async def _handle_microsoft_kmsi(page, idx=0):
    """Continue through Microsoft's localized Keep Me Signed In prompt."""
    tag = f"[#{idx}]"
    try:
        current_url = (page.url or "").lower()
    except Exception:
        current_url = ""
    try:
        body = " ".join(
            (await page.locator("body").inner_text(timeout=3000)).split()
        ).lower()
    except Exception:
        body = ""
    markers = (
        "stay signed in", "keep me signed in",
        "\u8981\u4fdd\u6301\u767b\u5165\u55ce",  # Traditional: keep signed in?
        "\u4fdd\u6301\u767b\u5165",              # Traditional: keep signed in
        "\u662f\u5426\u4fdd\u6301\u767b\u5f55",  # Simplified: keep signed in?
        "\u4fdd\u6301\u767b\u5f55",              # Simplified: keep signed in
        "rester connecté", "mantener la sesión iniciada",
        "angemeldet bleiben", "manter-me conectado",
        "rimanere connessi", "aangemeld blijven",
        "nie wylogowuj mnie", "оставаться в системе",
        "zůstat přihlášeni", "zůstat přihlášený",
        "oturumunuz açık kalsın",
        "هل تريد أن يظل دخولك مسجلاً", "هل تريد البقاء قيد تسجيل الدخول",
        "保持登录状态", "保持登入狀態", "サインインしたままにする",
        "\u30b5\u30a4\u30f3\u30a4\u30f3\u306e\u72b6\u614b\u3092\u7dad\u6301\u3057\u307e\u3059\u304b",
        "\u30b5\u30a4\u30f3\u30a4\u30f3\u306e\u72b6\u614b\u3092\u7dad\u6301",
        "로그인 상태를 유지",
        "साइन इन रहने दें", "साइन इन बनाए रखें", "साइन इन रहें",
        "क्या आप साइन इन रहना चाहते हैं",
        "tetap masuk", "biarkan saya tetap masuk",
        "ostati vpisani", "ostati prijavljeni",
    )
    detected = "/kmsi" in current_url or any(marker in body for marker in markers)
    if not detected:
        return False, False
    clicked = await _click_microsoft_action(
        page, preferred_ids=("idSIButton9", "acceptButton", "iNext"),
    )
    if clicked:
        print(f"  {tag} [graph] continued past stay-signed-in prompt")
        await asyncio.sleep(2)
        return True, True
    print(f"  {tag} [graph] stay-signed-in prompt detected; action not ready")
    return True, False



async def _accept_terms_update(page, tag):
    """Check a required box and continue Microsoft's terms-update interstitial."""
    try:
        body = " ".join((await page.locator("body").inner_text(timeout=2000)).split()).lower()
    except Exception:
        return False
    markers = (
        "updating our terms", "atnaujiname", "salygas", "paslaug",
        "posodabljamo", "pogoje uporabe",
        "conditions d'utilisation", "nutzungsbedingungen", "términos",
        "termos de uso", "условия использования", "服务条款", "使用条款",
        "更新我们的条款", "we're updating",
    )
    if not any(marker in body for marker in markers):
        return False
    boxes = page.locator('input[type="checkbox"], [role="checkbox"]')
    try:
        count = await boxes.count()
    except Exception:
        count = 0
    checked = 0
    for index in range(count):
        box = boxes.nth(index)
        try:
            if not await box.is_visible() or await box.is_checked():
                continue
            await box.click(force=True)
            checked += 1
        except Exception:
            continue
    clicked = await _click_microsoft_action(
        page, preferred_ids=("idSIButton9", "idBtn_Accept", "iNext", "acceptButton"),
    )
    if not clicked:
        submit = page.locator('button[type="submit"], input[type="submit"]').last
        try:
            if await submit.count() > 0 and await submit.is_visible() and await submit.is_enabled():
                await submit.click()
                clicked = "submit"
        except Exception:
            clicked = ""
    if checked or clicked:
        print(f"  {tag} [graph] accepted terms update")
        return True
    return False


async def _extract_graph_token_device(page, email, password, idx=0):
    """Authorize Graph by device code in the live Microsoft browser session."""
    tag = f"[#{idx}]"
    device = await asyncio.to_thread(_request_graph_device_code)
    if not device:
        return False
    verification_uri = _microsoft_url_with_locale(
        device.get("verification_uri") or "https://www.microsoft.com/link"
    )
    try:
        await page.context.add_init_script("""(() => {
            try {
                Object.defineProperty(CredentialsContainer.prototype, 'create', {
                    configurable: true,
                    value: () => Promise.reject(
                        new DOMException('Optional passkey enrollment disabled', 'NotAllowedError')
                    )
                });
            } catch (e) {}
        })();""")
    except Exception:
        pass
    try:
        await page.goto(verification_uri, timeout=45000, wait_until="domcontentloaded")
    except Exception as e:
        print(f"  {tag} [graph] device page navigation warning: {str(e)[:100]}")

    _, _, recovery_timeout, _ = _graph_recovery_settings()
    code_submitted = False
    email_submitted = False
    password_submitted = False
    recovery_state = {}
    idle_rounds = 0
    empty_response_hits = 0
    press_count = 0
    hold_unavailable = 0
    loop_deadline = time.monotonic() + max(180, recovery_timeout + 60)
    while time.monotonic() < loop_deadline:
        state, token_data = await asyncio.to_thread(
            _exchange_graph_device_code, device["device_code"]
        )
        if state == "ready":
            print(f"  {tag} [graph] device authorization OK! refresh_token="
                  f"{'yes' if token_data.get('refresh_token') else 'no'}")
            return token_data
        if state == "failed":
            error = token_data.get("error_description") or token_data.get("error") or ""
            print(f"  {tag} [graph] device authorization failed: {str(error)[:150]}")
            return None

        terminal_error, terminal_body = await _microsoft_page_terminal_error(page)
        if "all done" in terminal_body.lower() or "signed in to thunderbird" in terminal_body.lower():
            for _ in range(12):
                st, tok = await asyncio.to_thread(_exchange_graph_device_code, device["device_code"])
                if st == "ready":
                    print(f"  {tag} [graph] device authorization OK (confirmed on All-done page)! refresh_token=yes")
                    return tok
                await asyncio.sleep(1)
        if terminal_error:
            print(
                f"  {tag} [graph] terminal sign-in error ({terminal_error}): "
                f"{terminal_body[:180]}"
            )
            return {"terminal_error": terminal_error}
        if "ERR_EMPTY_RESPONSE" in terminal_body:
            empty_response_hits += 1
            if empty_response_hits >= 2:
                print(f"  {tag} [graph] device page empty response, giving up")
                return None
        else:
            empty_response_hits = 0

        if (
            recovery_state.get("code_submitted")
            and _recovery_code_was_rejected(terminal_body)
        ):
            retried = await _resend_rejected_recovery_code(
                page, recovery_state, tag
            )
            if recovery_state.get("recovery_code_rejected"):
                print(f"  {tag} [graph] recovery email verification failed after resend")
                return {"terminal_error": "recovery_code_rejected"}
            if retried:
                continue

        kmsi_page, kmsi_accepted = await _handle_microsoft_kmsi(page, idx)
        consent_page = consent_accepted = False
        if not kmsi_page:
            consent_page, consent_accepted = await _accept_microsoft_app_consent(
                page, idx
            )
        passkey_page = passkey_skipped = False
        if not kmsi_page and not consent_page:
            passkey_page, passkey_skipped = await _skip_optional_passkey(page, idx)
        recovery_page = recovery_bound = False
        if not kmsi_page and not consent_page and not passkey_page:
            recovery_enabled, _, _, _ = _graph_recovery_settings()
            if recovery_enabled:
                recovery_page, recovery_bound = await _bind_required_recovery_email(
                    page, recovery_state, idx, email
                )
                if recovery_state.get("unrecoverable_proof"):
                    print(f"  {tag} [graph] existing recovery mailbox cannot be restored")
                    return {"terminal_error": "recovery_mailbox_unavailable"}
                if recovery_state.get("recovery_code_rejected"):
                    print(f"  {tag} [graph] recovery email verification failed after resend")
                    return {"terminal_error": "recovery_code_rejected"}
                if recovery_state.get("recovery_code_delivery_timeout"):
                    print(f"  {tag} [graph] recovery code was not delivered after resend")
                    return {"terminal_error": "recovery_code_delivery_timeout"}
                if recovery_state.get("recovery_email_submit_stalled"):
                    print(f"  {tag} [graph] recovery email form did not advance")
                    return {"terminal_error": "recovery_email_submit_stalled"}
            if not recovery_page:
                recovery_page, recovery_bound = await _skip_optional_recovery_email(
                    page, idx
                )
        acted = kmsi_accepted or consent_accepted or passkey_skipped or recovery_bound
        if acted:
            loop_deadline = max(loop_deadline, time.monotonic() + 90)
        optional_setup_page = kmsi_page or consent_page or passkey_page or recovery_page
        # Microsoft issues a PerimeterX / Arkose hold challenge after the
        # device code.  Without the shared hold helper this branch never
        # fires and the device code silently expires.
        hold_visible = (
            press_count < 4
            and not optional_setup_page
            and await _outlook_press.captcha_visible(page)
        )
        if hold_visible and not acted:
            hold_result = await _outlook_press.press_and_hold(
                page, label=tag, press_number=press_count + 1,
            )
            if hold_result:
                press_count += 1
                acted = bool(hold_result.get("passed"))
                if not acted:
                    if press_count >= 4:
                        body = ""
                        try:
                            body = " ".join(
                                (await page.locator("body").inner_text(timeout=3000)).split()
                            )
                        except Exception:
                            pass
                        print(
                            f"  {tag} [graph] hold challenge failed {press_count} times; "
                            f"stopping without waiting for device-code expiry: {body[:160]}"
                        )
                        return {"terminal_error": "hold_challenge_failed", "body": body[:240]}
                    await asyncio.sleep(random.uniform(2.5, 4.5))
            else:
                hold_unavailable += 1
                if hold_unavailable >= 3:
                    print(f"  {tag} [graph] hold challenge has no target; skipping")
                    return {"terminal_error": "hold_challenge_unavailable"}
                await asyncio.sleep(2)
            continue
        if hold_visible:
            # Do not fight the hold frame by submitting the credential form
            # behind it; wait for the next round instead.
            await asyncio.sleep(1.5)
            continue

        if not acted and not optional_setup_page and not email_submitted:
            email_input = page.locator('input[type="email"], input[name="loginfmt"]').first
            try:
                if await email_input.count() > 0 and await email_input.is_visible():
                    await email_input.fill(email)
                    await page.keyboard.press("Enter")
                    email_submitted = True
                    acted = True
            except Exception:
                pass

        if not acted and not optional_setup_page and not password_submitted:
            password_input = page.locator('input[type="password"]').first
            try:
                if await password_input.count() > 0 and await password_input.is_visible():
                    await password_input.fill(password)
                    await page.keyboard.press("Enter")
                    password_submitted = True
                    acted = True
            except Exception:
                pass

        if not acted and not optional_setup_page and not code_submitted:
            for selector in (
                'input[name="otc"]', '#otc', 'input[autocomplete="one-time-code"]',
                'input[placeholder*="code" i]', 'input[type="text"]',
            ):
                code_input = page.locator(selector).first
                try:
                    if await code_input.count() > 0 and await code_input.is_visible():
                        await code_input.fill(device["user_code"])
                        await page.keyboard.press("Enter")
                        code_submitted = True
                        acted = True
                        print(f"  {tag} [graph] device code submitted")
                        break
                except Exception:
                    pass

        if not acted and not optional_setup_page:
            try:
                account = page.get_by_text(email, exact=False).first
                if await account.count() > 0 and await account.is_visible():
                    await account.click(timeout=3000)
                    acted = True
            except Exception:
                pass

        if not acted and not optional_setup_page:
            acted = await _accept_terms_update(page, tag)
        if not acted and not optional_setup_page:
            clicked = await _click_microsoft_action(
                page, preferred_ids=("idSIButton9", "idBtn_Accept", "iNext", "acceptButton"),
            )
            acted = bool(clicked)

        try:
            page_body = " ".join(
                (await page.locator("body").inner_text(timeout=3000)).split()
            ).lower()
        except Exception:
            page_body = ""
        if "reached your limit with this sign-in method" in page_body:
            password_route = await _click_microsoft_action(
                page,
                labels=("use your password", "sign in with your password",
                        "use a password", "use password", "password"),
                negative_labels=(),
                preferred_ids=("idA_PWD_SwitchToPassword", "switchToPassword"),
                include_links=True,
            )
            if not password_route:
                pwd_link = await _first_visible(page.locator(
                    'a:has-text("Use your password"), button:has-text("Use your password"), [aria-label*="password" i]'
                ))
                if pwd_link:
                    with contextlib.suppress(Exception):
                        await pwd_link.click()
                        password_route = "pwd-link"
            if password_route:
                print(f"  {tag} [graph] sign-in method limited; switched to password")
                password_submitted = False
                recovery_state.clear()
                await asyncio.sleep(2)
                continue
            print(f"  {tag} [graph] sign-in method limited; no password route")
            return {"terminal_error": "signin_method_limited",
                    "body": page_body[:240]}
        idle_rounds = 0 if acted else idle_rounds + 1
        if idle_rounds >= 3:
            try:
                body = " ".join(
                    (await page.locator("body").inner_text(timeout=3000)).split()
                )
            except Exception:
                body = ""
            if body:
                print(f"  {tag} [graph] device page waiting: {body[:180]}")
            if recovery_state.get("code_submitted") and not optional_setup_page:
                try:
                    inputs_count = await page.locator("input:visible, button:visible").count()
                    if inputs_count <= 2:
                        print(f"  {tag} [graph] blank/stalled card after recovery code; reloading...")
                        await page.reload(wait_until="domcontentloaded", timeout=20000)
                        await asyncio.sleep(2)
                except Exception as exc:
                    print(f"  {tag} [graph] card reload error: {exc}")
            idle_rounds = 0
        await asyncio.sleep(2)
    try:
        body = " ".join(
            (await page.locator("body").inner_text(timeout=3000)).split()
        )
    except Exception:
        body = ""
    print(f"  {tag} [graph] device authorization timed out: {body[:180]}")
    try:
        os.makedirs(SCREENSHOT_DIR, exist_ok=True)
        await _safe_screenshot(
            page, f"{SCREENSHOT_DIR}/outlook_{idx}_graph_device_timeout.png"
        )
    except Exception:
        pass
    return None


def extract_graph_token_http(email, password, idx=0, attempts=1):
    """Extract Graph refresh_token through the shared pure-HTTP OAuth flow."""
    try:
        from tools.extract_graph_tokens import get_graph_token
    except Exception as exc:
        print(f"  [#{idx}] [graph] import error: {exc}")
        return None

    for attempt in range(attempts):
        try:
            res = get_graph_token(email, password, idx)
        except Exception as exc:
            print(f"  [#{idx}] [graph] attempt {attempt + 1}/{attempts} error: {exc}")
            res = None
        if res and res.get("refresh_token"):
            return {
                "refresh_token": res["refresh_token"],
                "client_id": res.get("client_id") or "",
            }
        if attempt < attempts - 1:
            print(f"  [#{idx}] [graph] no refresh_token, retrying...")
            time.sleep(3 * (attempt + 1))
    return None


async def _extract_graph_token_authorization_code(page, context, email, password, idx=0):
    """Extract Microsoft Graph API refresh_token after registration.
    Uses OAuth2 authorization code flow with a native client (no secret needed).
    Uses 'consumers' tenant for personal Microsoft accounts (Outlook.com).
    Returns dict with access_token, refresh_token, or None on failure.
    """
    tag = f"[#{idx}]"
    try:
        auth_url = (
            f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
            f"?client_id={GRAPH_CLIENT_ID}"
            f"&response_type=code"
            f"&redirect_uri={urllib.parse.quote(GRAPH_REDIRECT_URI, safe='')}"
            f"&scope={urllib.parse.quote(GRAPH_SCOPE)}"
            f"&prompt=consent"
        )
        auth_url = _microsoft_url_with_locale(auth_url)
        print(f"  {tag} [graph] navigating to OAuth consent...")
        try:
            await page.goto(auth_url, timeout=30000, wait_until="domcontentloaded")
        except Exception:
            # A desktop OAuth callback has no local listener. Chromium reports
            # connection refused while preserving the code in page.url.
            if "code=" not in page.url and "error=" not in page.url:
                raise
        await asyncio.sleep(3)

        # May need to click accept/consent buttons. Submit each credential once;
        # quickly retrying a rejected login triggers Microsoft's sign-in throttle.
        email_submitted = False
        password_submitted = False
        for attempt in range(15):
            current_url = page.url
            # Check if redirected with auth code
            if GRAPH_REDIRECT_URI in current_url and "code=" in current_url:
                break

            terminal_error, terminal_body = await _microsoft_page_terminal_error(page)
            if terminal_error:
                print(
                    f"  {tag} [graph] terminal sign-in error ({terminal_error}): "
                    f"{terminal_body[:180]}"
                )
                return {"terminal_error": terminal_error}

            # Login if needed (shouldn't be since we just registered)
            email_input = page.locator('input[type="email"], input[name="loginfmt"]').first
            try:
                if (
                    not email_submitted
                    and await email_input.count() > 0
                    and await email_input.is_visible()
                ):
                    await email_input.fill(email)
                    await page.keyboard.press("Enter")
                    email_submitted = True
                    await asyncio.sleep(3)
                    continue
            except Exception:
                pass

            pwd_input = page.locator('input[type="password"]').first
            try:
                if (
                    not password_submitted
                    and await pwd_input.count() > 0
                    and await pwd_input.is_visible()
                ):
                    await pwd_input.fill(password)
                    await page.keyboard.press("Enter")
                    password_submitted = True
                    await asyncio.sleep(3)
                    continue
            except Exception:
                pass

            clicked = await _click_microsoft_action(
                page, preferred_ids=("idBtn_Accept", "idSIButton9", "acceptButton", "iAgree"),
            )
            if clicked:
                print(f"  {tag} [graph] clicked: {clicked}")
                await asyncio.sleep(3)

            await asyncio.sleep(2)

        current_url = page.url
        if "code=" not in current_url:
            parsed_error = urllib.parse.parse_qs(
                urllib.parse.urlparse(current_url).query
            )
            oauth_error = parsed_error.get("error_description", [""])[0]
            if oauth_error:
                print(f"  {tag} [graph] OAuth error: {oauth_error[:160]}")
            else:
                try:
                    body = " ".join(
                        (await page.locator("body").inner_text(timeout=3000)).split()
                    )
                except Exception:
                    body = ""
                print(f"  {tag} [graph] no auth code: {body[:160] or current_url[:120]}")
            await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_graph_fail.png")
            return None

        # Extract authorization code
        parsed = urllib.parse.urlparse(current_url)
        params = urllib.parse.parse_qs(parsed.query)
        auth_code = params.get("code", [None])[0]
        if not auth_code:
            print(f"  {tag} [graph] could not parse auth code")
            return None

        print(f"  {tag} [graph] got auth code: {auth_code[:30]}...")

        # Exchange code for tokens (consumers tenant for personal accounts)
        token_session = _microsoft_direct_session()
        try:
            token_resp = token_session.post(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                data={
                    "client_id": GRAPH_CLIENT_ID,
                    "grant_type": "authorization_code",
                    "code": auth_code,
                    "redirect_uri": GRAPH_REDIRECT_URI,
                    "scope": GRAPH_SCOPE,
                },
                timeout=30,
            )
        finally:
            token_session.close()
        token_data = token_resp.json()

        if "access_token" in token_data:
            print(f"  {tag} [graph] OK! refresh_token={('yes' if token_data.get('refresh_token') else 'no')}")
            return {
                "access_token": token_data["access_token"],
                "refresh_token": token_data.get("refresh_token"),
                "expires_in": token_data.get("expires_in"),
                "client_id": GRAPH_CLIENT_ID,
            }
        else:
            print(f"  {tag} [graph] token error: {token_data.get('error_description', token_data.get('error', '?'))[:100]}")
            return None

    except Exception as e:
        print(f"  {tag} [graph] error: {e}")
        return None


async def extract_graph_token(page, context, email, password, idx=0):
    """Prefer device-code OAuth; retain authorization-code flow as fallback."""
    result = await _extract_graph_token_device(page, email, password, idx)
    if result and result.get("refresh_token"):
        return result
    if result and result.get("terminal_error"):
        return result
    if result is not False:
        return None
    print(f"  [#{idx}] [graph] device flow unavailable; trying authorization-code fallback")
    return await _extract_graph_token_authorization_code(
        page, context, email, password, idx
    )


# ======================== Outlook Registration ========================


def _env_truthy(name, default="0"):
    return (os.environ.get(name, default) or "").strip().lower() in {"1", "true", "yes", "on"}


async def _maybe_confirm_before_register(page, tag, captcha_early_abort=False):
    """Auto-click a confirmation/consent gate shown before the signup form."""
    if captcha_early_abort or not _env_truthy("OUTLOOK_CONFIRM_BEFORE_REGISTER"):
        return
    try:
        title = await page.title()
    except Exception:
        title = ""
    print(f"  {tag} signup page opened: {page.url}")
    if title:
        print(f"  {tag} page title: {title[:100]}")

    # 只有真出现「数据确认/许可」页时才点允许接受；正常直接进注册表单的不点，
    # 否则会误点页面上别的 OK/确定链接(如 cookie 条、页脚)打乱流程。
    # 先按内容判定：body 文本含数据许可关键词、或已在 privacynotice 页，才继续找按钮。
    try:
        page_text = await page.evaluate("() => document.body.innerText")
    except Exception:
        page_text = ""
    ptl = (page_text or "").lower()
    curl = (page.url or "").lower()
    consent_hit = (
        any(kw in page_text for kw in ["同意并继续", "个人数据", "数据导出", "数据确认",
                                       "資料", "個人資料", "同意並繼續",
                                       "\u540c\u610f\u3057\u3066\u7d9a\u884c", "\u540c\u610f\u3057\u3066\u6b21\u3078",
                                       "\u500b\u4eba\u30c7\u30fc\u30bf", "\u500b\u4eba\u60c5\u5831",
                                       "\u30c7\u30fc\u30bf\u306e\u30a8\u30af\u30b9\u30dd\u30fc\u30c8",
                                       "\u30d7\u30e9\u30a4\u30d0\u30b7\u30fc\u306b\u95a2\u3059\u308b\u901a\u77e5"])
        or any(kw in ptl for kw in ["agree and continue", "consent", "data export",
                                    "accepter et continuer", "consentement",
                                    "your data", "personal data",
                                    "aceptar y continuar", "consentimiento", "datos personales",
                                    "akzeptieren und fortfahren", "einwilligung", "personenbezogene daten",
                                    "aceitar e continuar", "consentimento", "dados pessoais",
                                    "accetta e continua", "consenso", "dati personali",
                                    "accepteren en doorgaan", "toestemming", "persoonsgegevens",
                                    "zaakceptuj i kontynuuj", "zgoda", "dane osobowe",
                                    "přijmout a pokračovat", "souhlas", "export dat",
                                    "vaše data", "osobní údaje", "ochrana osobních údajů",
                                    "принять и продолжить", "согласие", "личные данные",
                                    "kabul et ve devam et", "onay", "kişisel veriler",
                                    "सहमत होकर जारी रखें", "सहमति", "व्यक्तिगत डेटा",
                                    "डेटा निर्यात", "आपका डेटा",
                                    "setujui dan lanjutkan", "persetujuan", "data pribadi",
                                    "ekspor data", "data anda"])
        or "privacynotice" in curl
    )
    if not consent_hit:
        print(f"  {tag} auto-confirm: no data-consent gate, skip (进正常表单)")
        return

    for _ in range(3):
        clicked = await _click_microsoft_action(
            page, preferred_ids=("acceptButton", "iAgree", "idBtn_Accept", "iNext"),
        )
        if clicked:
            print(f"  {tag} auto-confirm clicked: {clicked}")
            await asyncio.sleep(2)
            return
        await asyncio.sleep(1)
    print(f"  {tag} auto-confirm: no confirmation button found")
    return


async def register_outlook(page, context, idx=0, captcha_early_abort=False):
    """
    Register a new Outlook email account.
    Returns (email, password) on success, (None, None) on failure.

    captcha_early_abort: when True (headless mode), abort immediately after captcha
    solvers fail so the caller can fall back faster. When False (browser/BitBrowser
    mode), keep the loop running — PX presses sometimes pass after 10–30 s naturally.
    """
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    tag = f"[#{idx}]"

    try:
        print(f"  {tag} navigating to signup page...")
        signup_url = _microsoft_url_with_locale("https://signup.live.com/signup?lic=1")
        await _navigate_to_signup(page, signup_url, tag)
        await asyncio.sleep(3)
        await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_start.png")
        await _maybe_confirm_before_register(page, tag, captcha_early_abort)

        # Handle privacy/consent pages (Chinese "个人数据导出许可", "同意并继续", etc.)
        for _consent_try in range(5):
            page_text = await page.evaluate("() => document.body.innerText")
            current_url = page.url.lower()
            # Check if on a consent/privacy page (not the actual signup form)
            # Only trigger for actual privacy/consent standalone pages, not signup pages with footer links
            is_signup_form = "signup.live.com" in current_url and "privacynotice" not in current_url
            if not is_signup_form and (
                any(kw in page_text for kw in ["同意并继续", "个人数据", "数据导出",
                                               "\u540c\u610f\u3057\u3066\u7d9a\u884c", "\u540c\u610f\u3057\u3066\u6b21\u3078",
                                               "\u500b\u4eba\u30c7\u30fc\u30bf", "\u500b\u4eba\u60c5\u5831",
                                               "\u30c7\u30fc\u30bf\u306e\u30a8\u30af\u30b9\u30dd\u30fc\u30c8",
                                               "\u30d7\u30e9\u30a4\u30d0\u30b7\u30fc\u306b\u95a2\u3059\u308b\u901a\u77e5"]) or \
                any(kw in page_text.lower() for kw in [
                    "agree and continue", "consent", "data export",
                    "accepter et continuer", "consentement", "aceptar y continuar",
                    "akzeptieren und fortfahren", "aceitar e continuar",
                    "accetta e continua", "accepteren en doorgaan",
                    "zaakceptuj i kontynuuj", "přijmout a pokračovat",
                    "souhlas", "osobní údaje", "ochrana osobních údajů", "принять и продолжить",
                    "kabul et ve devam et",
                    "सहमत होकर जारी रखें", "सहमति", "व्यक्तिगत डेटा", "डेटा निर्यात", "आपका डेटा",
                    "setujui dan lanjutkan", "persetujuan", "data pribadi", "ekspor data", "data anda",
                ]) or "privacynotice" in current_url
            ):
                print(f"  {tag} privacy/consent page detected, clicking accept...")
                clicked = await _click_microsoft_action(
                    page, preferred_ids=("acceptButton", "iAgree", "idBtn_Accept", "iNext"),
                )
                if clicked:
                    print(f"  {tag} clicked consent: {clicked}")
                else:
                    print(f"  {tag} consent action not ready")
                await asyncio.sleep(3)
                await _safe_screenshot(
                    page,
                    f"{SCREENSHOT_DIR}/outlook_{idx}_after_consent_{_consent_try}.png",
                )
            else:
                break

        # Generate the alias after loading the page.  The network exit may
        # expose a regional domain picker (for example outlook.jp).
        email, password, prefix = generate_email_password()
        selected_domain = _preferred_outlook_domain()
        print(f"  {tag} registering: {email}")

        # Step 1: Enter email
        email_ok = False
        for retry in range(5):
            email_input = _signup_email_input(page)
            if await email_input.count() == 0:
                print(f"  {tag} email input not found")
                await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_no_email.png")
                return None, None

            domain_dropdown = page.locator(
                'select[id="LiveDomainBoxList"], select[name="LiveDomainBoxList"], #LiveDomainBoxList'
            ).first
            has_domain_dropdown = await domain_dropdown.count() > 0
            suffix_domains = await _signup_email_suffix_domains(email_input)
            page_manages_domain = has_domain_dropdown or bool(suffix_domains)

            if has_domain_dropdown:
                available_domains = await _signup_domain_options(domain_dropdown)
                selected_domain = _preferred_outlook_domain(
                    available_domains,
                    locale=urllib.parse.parse_qs(
                        urllib.parse.urlsplit(page.url).query
                    ).get("mkt", [MICROSOFT_UI_LOCALE])[0],
                )
                entry_value = _signup_email_entry_value(
                    prefix, selected_domain, page_manages_domain
                )
                committed = await react_fill(
                    page,
                    _SIGNUP_EMAIL_SELECTOR,
                    entry_value,
                    tries=3,
                    check_validity=False,
                )
                selected = await _select_signup_domain(domain_dropdown, selected_domain)
                email = f"{prefix}@{selected_domain}"
                print(f"  {tag} filled prefix: {prefix} ({selected_domain}, picker={selected})")
            elif suffix_domains:
                selected_domain = suffix_domains[0]
                email = f"{prefix}@{selected_domain}"
                entry_value = _signup_email_entry_value(
                    prefix, selected_domain, page_manages_domain
                )
                committed = await react_fill(
                    page,
                    _SIGNUP_EMAIL_SELECTOR,
                    entry_value,
                    tries=3,
                    check_validity=False,
                )
                print(f"  {tag} filled prefix: {prefix} ({selected_domain}, inline suffix)")
            else:
                selected_domain = _preferred_outlook_domain()
                email = f"{prefix}@{selected_domain}"
                entry_value = _signup_email_entry_value(
                    prefix, selected_domain, page_manages_domain
                )
                committed = await react_fill(
                    page,
                    _SIGNUP_EMAIL_SELECTOR,
                    entry_value,
                    tries=3,
                )
                print(f"  {tag} filled full email: {entry_value}")

            # The current Microsoft control can start as a plain type=email
            # field, then split into alias + @outlook.com only after blur. If
            # that happens, rewrite the left side before clicking Next so the
            # suffix is not submitted twice.
            if not page_manages_domain and committed:
                rendered_domains = await _signup_email_domains_after_blur(email_input)
                if rendered_domains:
                    selected_domain = rendered_domains[0]
                    email = f"{prefix}@{selected_domain}"
                    page_manages_domain = True
                    entry_value = _signup_email_entry_value(
                        prefix, selected_domain, page_manages_domain
                    )
                    committed = await react_fill(
                        page,
                        _SIGNUP_EMAIL_SELECTOR,
                        entry_value,
                        tries=3,
                        check_validity=False,
                    )
                    print(
                        f"  {tag} normalized dynamic suffix: "
                        f"{entry_value} ({selected_domain})"
                    )

            await asyncio.sleep(0.5)
            email_input = _signup_email_input(page)
            expected_value = entry_value
            actual_value = (
                (await email_input.input_value()).strip()
                if await email_input.count() > 0
                else ""
            )
            if not committed or actual_value != expected_value:
                print(
                    f"  {tag} email input did not commit "
                    f"(expected={expected_value!r}, actual={actual_value!r}); retrying"
                )
                continue
            for sel in ['input[type="submit"]', 'button[type="submit"]', '#iSignupAction', 'button[id="iSignupAction"]']:
                btn = page.locator(sel).first
                if await btn.count() > 0:
                    await btn.click(timeout=3000)
                    break
            await asyncio.sleep(3)

            page_text = await page.evaluate("() => document.body.innerText")
            page_lower = page_text.lower()
            submission_result = await _signup_email_submission_result(page)
            if submission_result == "pending":
                await asyncio.sleep(2)
                submission_result = await _signup_email_submission_result(page)
            if submission_result == "accepted":
                email_ok = True
                break
            rejection = submission_result

            if rejection == "taken":
                prefix = random.choice(string.ascii_lowercase) + "".join(
                    random.choices(string.ascii_lowercase + string.digits, k=11)
                )
                email = f"{prefix}@{selected_domain}"
                print(f"  {tag} email taken, retry: {email}")
                continue

            if rejection == "format" or "needs to start" in page_lower or "in the format" in page_lower or "enter a valid" in page_lower or "use letters" in page_lower:
                prefix = random.choice(string.ascii_lowercase) + "".join(
                    random.choices(string.ascii_lowercase + string.digits, k=9)
                )
                email = f"{prefix}@{selected_domain}"
                print(f"  {tag} format error, retry: {email}")
                continue

            email_ok = True
            break

        if not email_ok:
            print(f"  {tag} all email attempts failed")
            await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_email_fail.png")
            return None, None

        await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_after_email.png")

        # Step 2: Enter password
        await asyncio.sleep(2)
        pwd_input = None
        for _ in range(10):
            pwd_input = _signup_password_input(page)
            if await pwd_input.count() > 0:
                break
            await asyncio.sleep(1)

        if pwd_input and await pwd_input.count() > 0:
            await pwd_input.fill(password)
            print(f"  {tag} password filled")
            await asyncio.sleep(0.5)

            clicked_next = await _click_microsoft_action(
                page, preferred_ids=("iSignupAction", "iNext", "idSIButton9"),
            )
            if not clicked_next:
                await page.keyboard.press("Enter")

            await asyncio.sleep(3)
            await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_after_pwd.png")
        else:
            print(f"  {tag} password input not found")
            return None, None

        # Step 3: Country + Birthday
        year, month, day = generate_birthday()
        await asyncio.sleep(2)

        # Wait for the structural birth-date controls; labels vary by exit locale.
        for _ in range(10):
            birth_controls = page.locator(
                '[id*="Birth" i], [name*="Birth" i], '
                + 'select, [role="combobox"], input[type="number"]'
            )
            if await birth_controls.count() >= 2:
                break
            await asyncio.sleep(1)

        await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_bday_page.png")

        # Debug: dump all form elements
        form_debug = await page.evaluate("""() => {
            const els = document.querySelectorAll('input, select, button[role="combobox"], [role="combobox"], [role="listbox"]');
            return Array.from(els).filter(e => e.offsetParent !== null).map(e => ({
                tag: e.tagName, id: e.id, name: e.name, type: e.type || '',
                role: e.getAttribute('role') || '',
                ariaLabel: e.getAttribute('aria-label') || '',
                text: e.textContent ? e.textContent.trim().substring(0, 30) : '',
                placeholder: e.placeholder || '',
            }));
        }""")
        print(f"  {tag} form elements: {json.dumps(form_debug, ensure_ascii=False)[:600]}")

        all_selects = page.locator('select')
        select_count = await all_selects.count()
        print(f"  {tag} found {select_count} select elements")

        if select_count >= 2:
            # Traditional <select> dropdowns, classified by stable metadata.
            for select_index in range(select_count):
                select = all_selects.nth(select_index)
                metadata = {
                    "id": await select.get_attribute("id") or "",
                    "name": await select.get_attribute("name") or "",
                    "ariaLabel": await select.get_attribute("aria-label") or "",
                    "text": (await select.text_content() or "")[:80],
                }
                kind = _birthdate_field_kind(metadata)
                if not kind:
                    inferred = ("country", "month", "day") if select_count >= 3 else ("month", "day")
                    kind = inferred[select_index] if select_index < len(inferred) else ""
                if kind == "country":
                    try:
                        await select.select_option("US")
                        print(f"  {tag} country: US")
                    except Exception:
                        pass
                elif kind == "month":
                    await _select_native_numeric_option(select, month)
                elif kind == "day":
                    await _select_native_numeric_option(select, day)

            year_input = page.locator(
                'input[id*="BirthYear" i], input[name*="BirthYear" i], '
                'input[id*="Year" i], input[name*="Year" i], input[type="number"]'
            ).first
            if await year_input.count() > 0:
                await year_input.fill(str(year))
        else:
            # New UI with combobox/dropdown.
            print(f"  {tag} no <select>, trying new UI (combobox)...")

            # Find all visible comboboxes
            combos = page.locator('button[role="combobox"], [role="combobox"]')
            combo_count = await combos.count()
            print(f"  {tag} found {combo_count} comboboxes")

            # Strategy: identify combos by their text/aria-label/position
            # Typically order is: Country, Month, Day (country may already be set)
            month_filled = False
            day_filled = False

            for ci in range(combo_count):
                combo = combos.nth(ci)
                try:
                    box = await combo.bounding_box()
                    if not box or box['width'] < 10:
                        continue
                    combo_text = (await combo.text_content() or "").strip()
                    combo_label = (await combo.get_attribute("aria-label") or "").lower()
                    combo_id = (await combo.get_attribute("id") or "").lower()
                    combo_name = (await combo.get_attribute("name") or "").lower()
                    combo_placeholder = (await combo.get_attribute("placeholder") or "").lower()
                    info = f"text='{combo_text}' label='{combo_label}' id='{combo_id}'"
                    print(f"  {tag} combo[{ci}]: {info}")

                    kind = _birthdate_field_kind({
                        "id": combo_id, "name": combo_name, "ariaLabel": combo_label,
                        "placeholder": combo_placeholder, "text": combo_text,
                    })
                    if not kind:
                        inferred = ("country", "month", "day") if combo_count >= 3 else ("month", "day")
                        kind = inferred[ci] if ci < len(inferred) else ""

                    if kind == "month" and not month_filled:
                        await _select_birthdate_combo_option(
                            page, combo, month, kind="month"
                        )
                        month_filled = True
                        print(f"  {tag} month: {month}")
                    elif kind == "day" and not day_filled:
                        await _select_birthdate_combo_option(
                            page, combo, day, kind="day"
                        )
                        day_filled = True
                        print(f"  {tag} day: {day}")
                except Exception as e:
                    print(f"  {tag} combo[{ci}] error: {e}")

            if not month_filled or not day_filled:
                raise RuntimeError(
                    f"birthdate dropdown incomplete: month={month_filled}, "
                    f"day={day_filled}"
                )

            # Year input (text field)
            year_input = page.locator(
                '#BirthYearInput, [aria-label*="year" i], [aria-label*="年" i], '
                '[id*="Year" i], [id*="year" i], [placeholder*="年" i], '
                'input[type="text"][inputmode="numeric"], input[type="number"]'
            ).first
            # Fallback: find the text input that's NOT already filled
            if await year_input.count() == 0:
                all_text = page.locator('input[type="text"]')
                for ti in range(await all_text.count()):
                    inp = all_text.nth(ti)
                    val = await inp.input_value()
                    if not val:  # empty text input = likely year
                        year_input = inp
                        break
            if await year_input.count() > 0:
                await year_input.fill(str(year))
                print(f"  {tag} year: {year}")

        await asyncio.sleep(0.5)
        clicked = await _click_microsoft_action(
            page, preferred_ids=("iSignupAction", "iNext", "idSIButton9"),
        )
        if clicked:
            print(f"  {tag} clicked next (bday): {clicked}")
        await asyncio.sleep(3)
        await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_after_bday.png")

        # Step 4: Optional Username/Gamertag. Stable field attributes are locale-free.
        await asyncio.sleep(2)
        username_input = page.locator(
            'input[id*="displayName" i], input[id*="gamertag" i], '
            'input[name*="displayName" i], input[name*="gamertag" i]'
        ).first
        if await username_input.count() > 0:
            username = prefix[:8] + str(random.randint(100, 999))
            await username_input.fill(username)
            print(f"  {tag} username: {username}")
            await asyncio.sleep(0.5)
            await _click_microsoft_action(
                page, preferred_ids=("iSignupAction", "iNext", "idSIButton9"),
            )
            await asyncio.sleep(3)

        # Step 5: First/Last Name + checkbox (Chinese: 姓/名)
        first_name, last_name = generate_name()
        await asyncio.sleep(2)

        for _ in range(10):
            fname_input = page.locator(
                'input[name="FirstName"], input[id="FirstName"], input[name="firstNameInput"], '
                'input[id="firstNameInput"], input[aria-label*="first" i], input[placeholder*="first" i], '
                'input[aria-label*="名" i], input[placeholder*="名" i], '
                'input[aria-label*="prénom" i], input[placeholder*="prénom" i], '
                'input[aria-label*="nombre" i], input[placeholder*="nombre" i], '
                'input[aria-label*="vorname" i], input[placeholder*="vorname" i], '
                'input[aria-label*="nome" i], input[placeholder*="nome" i], '
                'input[aria-label*="पहला नाम" i], input[placeholder*="पहला नाम" i], '
                'input[aria-label*="nama depan" i], input[placeholder*="nama depan" i]'
            ).first
            lname_input = page.locator(
                'input[name="LastName"], input[id="LastName"], input[name="lastNameInput"], '
                'input[id="lastNameInput"], input[aria-label*="last" i], input[aria-label*="surname" i], '
                'input[placeholder*="last" i], input[aria-label*="姓" i], input[placeholder*="姓" i], '
                'input[aria-label*="nom de famille" i], input[placeholder*="nom de famille" i], '
                'input[aria-label*="apellido" i], input[placeholder*="apellido" i], '
                'input[aria-label*="nachname" i], input[placeholder*="nachname" i], '
                'input[aria-label*="cognome" i], input[placeholder*="cognome" i], '
                'input[aria-label*="उपनाम" i], input[placeholder*="उपनाम" i], '
                'input[aria-label*="अंतिम नाम" i], input[placeholder*="अंतिम नाम" i], '
                'input[aria-label*="nama belakang" i], input[placeholder*="nama belakang" i], '
                'input[aria-label*="nama keluarga" i], input[placeholder*="nama keluarga" i]'
            ).first
            if await fname_input.count() > 0 or await lname_input.count() > 0:
                break
            all_text_inputs = page.locator('input[type="text"]')
            if await all_text_inputs.count() >= 2:
                break
            await asyncio.sleep(1)

        if await fname_input.count() > 0:
            if await lname_input.count() > 0:
                await lname_input.fill(last_name)
            await fname_input.fill(first_name)
            print(f"  {tag} name: {first_name} {last_name}")
        else:
            all_text_inputs = page.locator('input[type="text"]')
            count = await all_text_inputs.count()
            if count >= 2:
                await all_text_inputs.nth(0).fill(last_name)
                await all_text_inputs.nth(1).fill(first_name)
                print(f"  {tag} name (generic): {first_name} {last_name}")

        checkbox = page.locator('input[type="checkbox"], [role="checkbox"]').first
        if await checkbox.count() > 0:
            try:
                checked = await checkbox.is_checked()
            except Exception:
                checked = False
            if not checked:
                await checkbox.click(force=True)
                print(f"  {tag} checkbox checked")

        await asyncio.sleep(0.5)
        clicked = await _click_microsoft_action(
            page, preferred_ids=("iSignupAction", "iNext", "idSIButton9"),
        )
        if clicked:
            print(f"  {tag} clicked next (name): {clicked}")
        await asyncio.sleep(3)
        await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_after_name.png")

        # Step 6: CAPTCHA handling
        print(f"  {tag} checking for captcha...")
        await asyncio.sleep(3)

        arkose_solved = False
        press_count = 0
        # headless: 5 presses max (abort quickly on fail)
        # browser: 15 presses max (keep trying; PX sometimes passes after retries)
        max_press = 5 if captcha_early_abort else 15
        # Allow caller to cap presses tighter via env (e.g. bs_register_step1
        # sets this to 3 so failed PX checks fail-fast and we move on to
        # lqqq/backup instead of burning ~3 min per dud signup).
        _env_max_press = os.environ.get("OUTLOOK_REG_MAX_PRESS", "").strip()
        if _env_max_press.isdigit():
            max_press = min(max_press, int(_env_max_press))
        no_btn_rounds = 0
        had_captcha = False          # 是否真的出现过 captcha（避免一上来误判已通过）
        gone_rounds = 0              # captcha 消失后连续多少轮仍停在 signup（等跳转）
        registration_confirmed = False

        async def _captcha_visible():
            return await _outlook_press.captcha_visible(page)

        # headless: 90 s captcha window; browser: 240 s (multiple press rounds)
        _captcha_rounds = 30 if captcha_early_abort else 80
        # When max_press is small, shrink the wait loop too — otherwise we'd
        # exhaust presses then idle for the remaining captcha window.
        # Rough budget: ~10s per press cycle. +20s slack for first solver call.
        _capped_rounds = max(8, max_press * 4 + 8)
        _captcha_rounds = min(_captcha_rounds, _capped_rounds)

        for wait_round in range(_captcha_rounds):
            try:
                page_text = (await page.evaluate("() => document.body.innerText")).lower()
                current_url = page.url.lower()
            except Exception:
                await asyncio.sleep(3)
                try:
                    page_text = (await page.evaluate("() => document.body.innerText")).lower()
                    current_url = page.url.lower()
                except Exception:
                    current_url = page.url.lower()
                    if "signup" not in current_url:
                        break
                    continue

            terminal_state, terminal_reason = outlook_registration_terminal_state(
                current_url, page_text
            )
            if terminal_state == "error":
                print(f"  {tag} registration rejected by Microsoft: {terminal_reason}")
                return None, None
            if terminal_state == "confirmed":
                registration_confirmed = True
                print(f"  {tag} registration complete -> {current_url[:70]}")
                break
            if terminal_reason == "privacy_notice":
                await _click_microsoft_action(
                    page, preferred_ids=("acceptButton", "iAgree", "iNext", "idSIButton9"),
                )
                await asyncio.sleep(3)
                continue

            # captcha 消失判定：过验证后页面变 "Loading..." 转圈、按住按钮/iframe 消失，
            # 但 URL 可能还没跳转（异步）。此时不该再按压/超时 —— 标记已过，进入等跳转模式。
            if had_captcha:
                if await _captcha_visible():
                    gone_rounds = 0
                else:
                    gone_rounds += 1
                    if gone_rounds == 1:
                        print(f"  {tag} captcha 元素已消失（验证通过/Loading），等待页面跳转…")
                    # 轻推一下提交按钮，催收尾
                    if gone_rounds % 3 == 0:
                        for sel in ['#iSignupAction', 'input[type="submit"]', 'button[type="submit"]']:
                            try:
                                b = page.locator(sel).first
                                if await b.count() > 0 and await b.is_visible():
                                    await b.click(timeout=3000); break
                            except Exception:
                                pass
                    # Captcha disappearance is not an account-creation receipt.
                    if gone_rounds >= 20:
                        print(f"  {tag} captcha disappeared but signup never completed")
                        await _safe_screenshot(
                            page, f"{SCREENSHOT_DIR}/outlook_{idx}_signup_unconfirmed.png"
                        )
                        return None, None
                    await asyncio.sleep(3)
                    continue

            # Account blocked detection across common Microsoft markets.
            if any(kw in page_text for kw in [
                "帐户创建已被阻止", "已被阻止", "阻止创建",
                "account creation has been blocked", "has been blocked", "account has been suspended",
                "création de compte a été bloquée", "a été bloquée", "bloquée",
                "creación de la cuenta se ha bloqueado", "cuenta bloqueada",
                "kontoerstellung wurde blockiert", "konto wurde gesperrt",
                "criação da conta foi bloqueada", "conta bloqueada",
                "creazione dell'account è stata bloccata", "account bloccato",
                "account maken is geblokkeerd", "account geblokkeerd",
                "tworzenie konta zostało zablokowane", "konto zablokowane",
                "создание учетной записи заблокировано", "учетная запись заблокирована",
                "hesap oluşturma engellendi", "hesap engellendi",
                "खाता बनाने पर रोक लगा दी गई है", "खाता अवरुद्ध", "असामान्य गतिविधि",
                "pembuatan akun telah diblokir", "akun diblokir", "aktivitas tidak biasa",
                "unusual activity", "异常活动", "activité inhabituelle",
            ]):
                print(f"  {tag} BLOCKED: account creation blocked by Microsoft")
                await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_blocked.png")
                return None, None

            # FIDO/passkey - skip
            if "fido" in current_url or "passkey" in current_url:
                await _skip_optional_passkey(page, idx)
                await asyncio.sleep(3)
                continue

            # Privacy notice
            if "privacynotice" in current_url:
                await asyncio.sleep(2)
                await _click_microsoft_action(
                    page, preferred_ids=("acceptButton", "iAgree", "iNext", "idSIButton9"),
                )
                await asyncio.sleep(3)
                continue

            # PerimeterX press-and-hold
            if press_count < max_press:
                pressed = False
                hold_result = await _outlook_press.press_and_hold(
                    page, label=f"  {tag}", press_number=press_count + 1,
                )
                if hold_result:
                    press_count += 1
                    pressed = True
                    had_captcha = True   # 出现过 captcha，供「消失=已通过」判定使用
                    await asyncio.sleep(random.uniform(2, 4))

                    try:
                        await _safe_screenshot(
                            page, f"{SCREENSHOT_DIR}/outlook_{idx}_hold_{press_count}.png"
                        )
                    except Exception:
                        pass
                else:
                    no_btn_rounds += 1
                    # Scan frames for clickable buttons
                    try:
                        for f in page.frames:
                            if f == page.main_frame:
                                continue
                            frame_url = f.url.lower()
                            if frame_url == "about:blank" or "cfp.microsoft.com" in frame_url:
                                continue
                            try:
                                btns = f.locator('button, [role="button"], input[type="button"], input[type="submit"]')
                                for bi in range(await btns.count()):
                                    box = await btns.nth(bi).bounding_box()
                                    if box and box['width'] > 30 and box['height'] > 20:
                                        x = box['x'] + box['width'] / 2
                                        y = box['y'] + box['height'] / 2
                                        press_count += 1
                                        await page.mouse.move(x, y)
                                        await asyncio.sleep(0.3)
                                        await page.mouse.down()
                                        await asyncio.sleep(18)
                                        await page.mouse.up()
                                        pressed = True
                                        await asyncio.sleep(5)
                                        break
                                if pressed:
                                    break
                            except Exception:
                                continue
                    except Exception:
                        pass

                if pressed:
                    no_btn_rounds = 0

            # Main page captcha buttons
            if press_count < max_press and no_btn_rounds >= 3:
                try:
                    main_btns = page.locator('#hipTemplateContainer button, #HipPaneForm button, [id*="hip"] button')
                    for bi in range(await main_btns.count()):
                        box = await main_btns.nth(bi).bounding_box()
                        if box and box['width'] > 20:
                            press_count += 1
                            await main_btns.nth(bi).click(timeout=3000)
                            await asyncio.sleep(5)
                            no_btn_rounds = 0
                            break
                except Exception:
                    pass

            # Try submit
            if no_btn_rounds >= 8 and no_btn_rounds % 8 == 0:
                try:
                    for sel in ['#iSignupAction', 'input[type="submit"]', 'button[type="submit"]']:
                        submit = page.locator(sel).first
                        if await submit.count() > 0 and await submit.is_visible():
                            await submit.click(timeout=3000)
                            await asyncio.sleep(5)
                            break
                except Exception:
                    pass

            # 按满次数：两个打码器(capsolver-px/ezcaptcha-px)对 MS 这个 PerimeterX
            # 按住验证都没用(类型不支持/解不出)，已移除。按满后给一个短观察窗等跳转：
            # 若手动按住其实已过，循环顶部「captcha 消失=已通过」会接管收尾；若仍可见(没过)，
            # 观察窗内不再按压、等满 ~24s 就快速放弃，不空等到 captcha timeout。
            if press_count >= max_press and not arkose_solved:
                arkose_solved = True
                arkose_wait_start = wait_round
                print(f"  {tag} 按满 {max_press} 次，停止按压，等待页面跳转")
            if arkose_solved and had_captcha:
                # 仍能看到 captcha = 没过；给 8 轮(~24s)缓冲后快速放弃
                if await _captcha_visible():
                    if wait_round - arkose_wait_start >= 8:
                        print(f"  {tag} 按满仍未通过，快速放弃本号")
                        await _safe_screenshot(
                            page, f"{SCREENSHOT_DIR}/outlook_{idx}_press_fail.png"
                        )
                        return None, None

            if wait_round % 5 == 0:
                await _safe_screenshot(
                    page, f"{SCREENSHOT_DIR}/outlook_{idx}_wait_{wait_round}.png"
                )
                print(f"  {tag} waiting... ({wait_round * 3}s)")

            await asyncio.sleep(3)
        else:
            print(f"  {tag} captcha timeout")
            await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_timeout.png")
            return None, None

        # Post-captcha pages
        for retry in range(10):
            current_url = page.url.lower()
            try:
                page_text = await page.locator("body").inner_text(timeout=3000)
            except Exception:
                page_text = ""
            terminal_state, terminal_reason = outlook_registration_terminal_state(
                current_url, page_text
            )
            if terminal_state == "error":
                print(f"  {tag} registration rejected by Microsoft: {terminal_reason}")
                return None, None
            if terminal_state == "confirmed":
                registration_confirmed = True
                break
            await _click_microsoft_action(
                page, preferred_ids=("acceptButton", "iAgree", "iNext", "idSIButton9"),
            )
            await asyncio.sleep(3)

        if not registration_confirmed:
            print(f"  {tag} registration not confirmed; account will not be exported")
            await _safe_screenshot(
                page, f"{SCREENSHOT_DIR}/outlook_{idx}_signup_unconfirmed.png"
            )
            return None, None

        verification = verify_registered_outlook(email, password, tag)
        if verification is False:
            print(f"  {tag} verification failed, discarding account")
            return None, None

        print(f"  {tag} OK: {email} / {password}")
        return email, password

    except Exception as e:
        print(f"  {tag} FAILED: {e}")
        try:
            await _safe_screenshot(page, f"{SCREENSHOT_DIR}/outlook_{idx}_error.png")
        except Exception:
            pass
        return None, None


# ======================== Protocol Mode (pure HTTP) ========================

def _proxy_for_requests(proxy_str):
    """Convert proxy string to requests proxies dict."""
    if not proxy_str:
        return None
    p = BitBrowserClient._parse_proxy(proxy_str)
    if not p:
        return None
    auth = f"{p['username']}:{p['password']}@" if p.get("username") else ""
    url = f"{p.get('type', 'http')}://{auth}{p['host']}:{p['port']}"
    return {"http": url, "https": url}


def _proxy_for_playwright(proxy_str):
    """Convert proxy string to Playwright proxy dict."""
    if not proxy_str:
        return None
    p = BitBrowserClient._parse_proxy(proxy_str)
    if not p:
        return None
    result = {"server": f"{p.get('type', 'http')}://{p['host']}:{p['port']}"}
    if p.get("username"):
        result["username"] = p["username"]
        result["password"] = p["password"]
    return result


def register_outlook_protocol(proxy_str=None, idx=0):
    """
    Register Outlook via pure HTTP requests — no browser, ~50KB per attempt.
    Returns (email, password) on success, (None, None) on failure/captcha.
    """
    tag = f"[#{idx}][proto]"
    session = requests.Session()
    proxies = _proxy_for_requests(proxy_str)
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/130.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": f"{MICROSOFT_UI_LOCALE},en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    })

    try:
        print(f"  {tag} GET signup page...")
        signup_url = _microsoft_url_with_locale("https://signup.live.com/signup?lic=1")
        resp = session.get(
            signup_url,
            proxies=proxies, timeout=30, allow_redirects=True,
        )
        if resp.status_code != 200:
            print(f"  {tag} HTTP {resp.status_code}")
            return None, None

        html = resp.text

        # Microsoft signup is a React SPA — form fields rendered via JS.
        # Protocol mode only works if the server-side rendered form is present.
        # Detect availability by checking for MemberName field.
        if "MemberName" not in html and "iSignupAction" not in html:
            print(f"  {tag} SPA form not in HTML (JS-rendered) — protocol N/A")
            return None, None

        # Detect immediate bot-block
        if any(kw in html.lower() for kw in ["perimeterx", "px-block", "_px.init", "bot protection"]):
            print(f"  {tag} PerimeterX blocked on load")
            return None, None

        # Extract PPFT (CSRF token)
        ppft = None
        for pat in [
            r'name="PPFT"[^>]*value="([^"]+)"',
            r'"sFT"\s*:\s*"([^"]+)"',
            r"sFT\s*:\s*'([^']+)'",
        ]:
            m = re.search(pat, html)
            if m:
                ppft = m.group(1)
                break
        if not ppft:
            print(f"  {tag} no PPFT token found")
            return None, None

        # Extract uaid and action URL
        uaid_m = re.search(r'[?&]uaid=([A-Za-z0-9\-]+)', html)
        uaid = uaid_m.group(1) if uaid_m else ""
        action_m = re.search(r'action="(https://signup\.live\.com[^"]+)"', html)
        action_url = action_m.group(1) if action_m else f"{signup_url}&uaid={uaid}"

        # Extract canary token (CSRF #2, optional)
        canary_name_m = re.search(r'"sCanaryTokenName"\s*:\s*"([^"]+)"', html)
        canary_val_m = re.search(r'"sCanaryToken"\s*:\s*"([^"]+)"', html)
        canary_name = canary_name_m.group(1) if canary_name_m else ""
        canary_val = canary_val_m.group(1) if canary_val_m else ""

        # Server-rendered forms expose the same domain choices as the browser
        # picker.  Restrict protocol mode to domains present in that response.
        available_domains = _domains_from_values((html,))
        selected_domain = _preferred_outlook_domain(available_domains)
        email, password, prefix = generate_email_password(selected_domain)
        first_name, last_name = generate_name()
        year, month, day = generate_birthday()
        print(f"  {tag} trying: {email}")

        form_data = {
            "MemberName": email,
            "Password": password,
            "FirstName": first_name,
            "LastName": last_name,
            "BirthDate": str(day),
            "BirthMonth": str(month),
            "BirthYear": str(year),
            "Country": "US",
            "LiveDomainBoxList": selected_domain,
            "LcId": "1033",
            "PPFT": ppft,
            "lic": "1",
            "sErrorCode": "",
            "iSignupFlow": "2",
        }
        if canary_name and canary_val:
            form_data[canary_name] = canary_val

        resp2 = session.post(
            action_url,
            data=form_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": signup_url,
                "Origin": "https://signup.live.com",
            },
            proxies=proxies, timeout=30, allow_redirects=True,
        )

        final_url = resp2.url.lower()
        body = resp2.text.lower()

        terminal_state, terminal_reason = outlook_registration_terminal_state(final_url, body)
        if terminal_state == "error":
            print(f"  {tag} registration rejected by Microsoft: {terminal_reason}")
            return None, None

        # Success requires a recognized post-signup Microsoft destination.
        if terminal_state == "confirmed":
            verification = verify_registered_outlook(email, password, tag)
            if verification is False:
                print(f"  {tag} verification failed, discarding proto account")
                return None, None
            print(f"  {tag} OK (proto): {email}")
            return email, password

        # Captcha / bot detection → fall back
        if any(kw in body for kw in ["captcha", "perimeterx", "challenge", "press and hold",
                                      "verify you're human", "unusual activity", "_pxhd"]):
            print(f"  {tag} captcha/bot detected — proto failed")
            return None, None

        # Email taken
        if ("already" in body and "email" in body) or "taken" in body:
            print(f"  {tag} email taken")
            return None, None

        # Blocked
        if "blocked" in body or "suspended" in body:
            print(f"  {tag} account blocked")
            return None, None

        print(f"  {tag} unknown result: {resp2.url[:80]}")
        return None, None

    except Exception as e:
        print(f"  {tag} error: {e}")
        return None, None


# ======================== Headless Mode (Playwright, no BitBrowser) ========================

# Headless: block everything heavy (CSS too, since rendering doesn't matter for detection)
_BLOCK_TYPES_HEADLESS = {"image", "stylesheet", "font", "media", "other"}

# Browser mode: keep CSS so PerimeterX doesn't detect missing stylesheets (captcha check)
_BLOCK_TYPES_BROWSER = {"image", "font", "media"}

# Domains that must NOT be blocked even for heavy resource types
_ALLOW_DOMAINS = {
    "fpt.live.com",          # PerimeterX DFP iframe — generates fptctx2 cookie
    "hsprotect.net",         # PerimeterX human challenge iframe
    "px-cloud.net",          # PerimeterX CDN
    "px-cdn.net",            # PerimeterX CDN alt
    "client.px-cloud.net",   # PerimeterX client
}


def _make_block_handler(block_types):
    """Return a route handler that blocks the given resource types.
    Always allows PerimeterX/captcha domains through.
    """
    async def _handler(route):
        url = route.request.url
        for domain in _ALLOW_DOMAINS:
            if domain in url:
                await route.continue_()
                return
        if route.request.resource_type in block_types:
            await route.abort()
        else:
            await route.continue_()
    return _handler


_block_heavy_resources = _make_block_handler(_BLOCK_TYPES_HEADLESS)   # headless: aggressive
_block_browser_resources = _make_block_handler(_BLOCK_TYPES_BROWSER)   # browser: keep CSS


async def _browser_page(context, fresh=False):
    """Use one tab; registration gets a clean tab while Graph keeps its session tab."""
    pages = list(getattr(context, "pages", []) or [])
    live_pages = []
    for page in pages:
        try:
            if page.is_closed() is True:
                continue
        except Exception:
            pass
        live_pages.append(page)
    if fresh:
        try:
            page = await asyncio.wait_for(context.new_page(), timeout=20)
        except asyncio.TimeoutError:
            if live_pages:
                print("  [browser] new tab timed out; reusing the startup tab")
                return live_pages[0]
            raise RuntimeError("BitBrowser did not create a registration tab within 20 seconds")
        for extra in live_pages:
            try:
                await asyncio.wait_for(extra.close(), timeout=5)
            except Exception:
                pass
        return page
    if not live_pages:
        return await context.new_page()
    page = live_pages[0]
    for extra in live_pages[1:]:
        try:
            await extra.close()
        except Exception:
            pass
    return page


async def _navigate_to_signup(page, signup_url, tag, attempts=3):
    """Leave a stale startup tab and retry transient signup navigation failures."""
    attempts = max(1, int(attempts))
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            await page.goto(signup_url, timeout=45000, wait_until="domcontentloaded")
            current_url = str(getattr(page, "url", "") or "").lower()
            if current_url and not current_url.startswith(("about:blank", "chrome-error://")):
                return
            raise RuntimeError(f"navigation remained on {current_url or 'an empty URL'}")
        except Exception as exc:
            last_error = exc
            current_url = str(getattr(page, "url", "") or "")
            normalized_url = current_url.lower()
            if normalized_url and not normalized_url.startswith(("about:blank", "chrome-error://")):
                print(
                    f"  {tag} signup page committed despite {type(exc).__name__}; continuing"
                )
                return
            if attempt >= attempts:
                break
            print(
                f"  {tag} signup navigation retry {attempt}/{attempts - 1}: "
                f"{type(exc).__name__}: {str(exc)[:100]} (url={current_url[:100]})"
            )
            try:
                await page.evaluate("() => window.stop()")
            except Exception:
                pass
            await asyncio.sleep(min(4, attempt * 2))
    raise RuntimeError(
        f"signup page did not open after {attempts} attempts: {last_error}"
    )


async def _safe_screenshot(page, path):
    """Keep diagnostics from turning a healthy registration into a failure."""
    try:
        await page.screenshot(path=path, timeout=5000)
        return True
    except Exception as exc:
        print(f"  [screenshot] skipped: {type(exc).__name__}: {str(exc)[:80]}")
        return False


async def _register_one_headless(idx, proxy_str):
    """
    Register via truly headless Chrome (no window shown to user).
    Uses headless=True with comprehensive fingerprint patches to compensate
    for the missing headed-browser signals that PerimeterX checks.
    Resource blocking saves ~70% bandwidth vs full BitBrowser.
    Returns (email, password) or (None, None).
    """
    tag = f"[#{idx}][headless]"
    try:
        async with async_playwright() as pw:
            args = [
                "--no-sandbox", "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--disable-default-apps",
                "--disable-extensions",
                "--no-first-run",
                "--no-default-browser-check",
                "--window-size=1280,800",
            ]
            try:
                # Prefer real Chrome binary (better fingerprint than bundled Chromium)
                browser = await pw.chromium.launch(
                    channel="chrome",
                    headless=True,
                    proxy=_proxy_for_playwright(proxy_str),
                    args=args,
                )
                print(f"  {tag} using real Chrome (headless, no window)")
            except Exception:
                # Fallback to bundled Playwright Chromium
                browser = await pw.chromium.launch(
                    headless=True,
                    proxy=_proxy_for_playwright(proxy_str),
                    args=args,
                )
                print(f"  {tag} using Playwright Chromium (headless, no window)")

            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                locale="en-US",
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/136.0.0.0 Safari/537.36"
                ),
            )
            page = await _browser_page(context, fresh=True)

            # playwright-stealth: patches navigator.webdriver, plugins, languages, etc.
            if _HAS_STEALTH:
                await _stealth_obj.apply_stealth_async(page)

            # Additional patches for properties PX checks that stealth misses
            # in headless mode (document.hidden, visibilityState, chrome.runtime, etc.)
            await context.add_init_script("""
                // --- Headless detection fixes ---
                // PX checks document.hidden and visibilityState
                try {
                    Object.defineProperty(document, 'hidden', {get: () => false});
                    Object.defineProperty(document, 'visibilityState', {get: () => 'visible'});
                } catch(e){}

                // PX checks document.hasFocus()
                try {
                    document.hasFocus = function(){ return true; };
                } catch(e){}

                // screen dimensions (headless often returns 0x0)
                try {
                    if (!screen.width || screen.width < 100) {
                        Object.defineProperty(screen, 'width',       {get: () => 1920});
                        Object.defineProperty(screen, 'height',      {get: () => 1080});
                        Object.defineProperty(screen, 'availWidth',  {get: () => 1920});
                        Object.defineProperty(screen, 'availHeight', {get: () => 1040});
                        Object.defineProperty(screen, 'colorDepth',  {get: () => 24});
                        Object.defineProperty(screen, 'pixelDepth',  {get: () => 24});
                    }
                } catch(e){}

                // --- chrome.runtime stub (PX checks window.chrome.runtime) ---
                if (!window.chrome) window.chrome = {};
                if (!window.chrome.runtime) {
                    window.chrome.runtime = {
                        id: undefined,
                        connect: function(){},
                        sendMessage: function(){},
                        onMessage: {addListener: function(){}, removeListener: function(){}},
                        onConnect: {addListener: function(){}, removeListener: function(){}},
                        getManifest: function(){ return {}; },
                        getURL: function(p){ return 'chrome-extension://invalid/' + p; },
                        PlatformOs: {MAC:'mac',WIN:'win',ANDROID:'android',CROS:'cros',LINUX:'linux',OPENBSD:'openbsd'},
                        PlatformArch: {ARM:'arm',X86_32:'x86-32',X86_64:'x86-64'},
                    };
                }

                // --- deviceMemory ---
                try {
                    if (!navigator.deviceMemory) {
                        Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
                    }
                } catch(e){}

                // --- WebGL vendor/renderer ---
                (function() {
                    var _gp = WebGLRenderingContext.prototype.getParameter;
                    WebGLRenderingContext.prototype.getParameter = function(p) {
                        if (p === 37445) return 'NVIDIA Corporation';
                        if (p === 37446) return 'NVIDIA GeForce GTX 750 Ti/PCIe/SSE2';
                        return _gp.call(this, p);
                    };
                    try {
                        var _gp2 = WebGL2RenderingContext.prototype.getParameter;
                        WebGL2RenderingContext.prototype.getParameter = function(p) {
                            if (p === 37445) return 'NVIDIA Corporation';
                            if (p === 37446) return 'NVIDIA GeForce GTX 750 Ti/PCIe/SSE2';
                            return _gp2.call(this, p);
                        };
                    } catch(e){}
                })();

                // --- Remove CDP/Playwright leaks ---
                delete window.__playwright;
                delete window.__pwInitScripts;
                try { delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array; } catch(e){}
                try { delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise; } catch(e){}
            """)
            print(f"  {tag} headless browser ready (stealth+patches, no window)")

            # Block heavy resources to save bandwidth (headless doesn't need CSS for rendering)
            await page.route("**/*", _block_heavy_resources)

            # Abort early when captcha solvers fail so auto-mode falls back to BitBrowser fast
            email, password = await register_outlook(page, context, idx, captcha_early_abort=True)

            try:
                await browser.close()
            except Exception:
                pass

            return email, password

    except Exception as e:
        print(f"  {tag} error: {e}")
        return None, None


# ======================== Browser Mode (BitBrowser, full GUI) ========================

async def _register_one_browser(bb, idx, proxy_str, keep_profile=False):
    """
    Register via BitBrowser full browser (highest traffic, most reliable).
    Returns (email, password) or (email, password, profile_id, ws) when
    keep_profile=True.
    """
    tag = f"[#{idx}][browser]"
    profile_id = None
    ws = ""

    def _result(email, password, retained_id=None, retained_ws=""):
        if keep_profile:
            return email, password, retained_id, retained_ws
        return email, password
    try:
        ts = datetime.now().strftime("%m%d_%H%M%S")
        name = f"outlook_{ts}_{idx}"

        for _retry in range(5):
            try:
                browser_options = {"proxy_str": proxy_str} if proxy_str else {"proxyType": "noproxy"}
                profile_id = bb.create_browser(name=name, **browser_options)
                break
            except Exception as e:
                err_msg = str(e)
                if '最大创建窗口数' in err_msg or '超过' in err_msg:
                    print(f"  {tag} browser quota full, cleaning up...")
                    bb.cleanup_browsers(keep=2)
                    await asyncio.sleep(3)
                    continue
                elif 'TLS' in err_msg or 'socket' in err_msg or 'ECONNRESET' in err_msg:
                    print(f"  {tag} BitBrowser TLS error (retry {_retry + 1}/5)")
                    await asyncio.sleep(5 + _retry * 3)
                    continue
                elif _retry < 4:
                    print(f"  {tag} create browser error (retry {_retry + 1}): {err_msg[:80]}")
                    await asyncio.sleep(3)
                    continue
                else:
                    raise

        if not profile_id:
            print(f"  {tag} create browser failed")
            return _result(None, None)

        info = bb.open_browser(profile_id)
        ws = info.get("ws", "")
        if not ws:
            print(f"  {tag} no WebSocket URL")
            return _result(None, None)

        print(f"  {tag} browser connected")
        async with async_playwright() as p:
            browser = await p.chromium.connect_over_cdp(ws)
            context = browser.contexts[0] if browser.contexts else await browser.new_context()
            await install_traffic_saver(context)
            page = await _browser_page(context, fresh=True)
            email, password = await register_outlook(page, context, idx)

        if keep_profile and email and password:
            retained_id = profile_id
            profile_id = None
            print(f"  {tag} keeping browser profile for Graph authorization")
            return _result(email, password, retained_id, ws)
        return _result(email, password)

    except Exception as e:
        print(f"  {tag} error: {e}")
        return _result(None, None)
    finally:
        if profile_id:
            try:
                bb.close_browser(profile_id)
                await asyncio.sleep(2)
                bb.delete_browser(profile_id)
                print(f"  {tag} browser cleaned up")
            except Exception:
                pass


async def extract_graph_token_browser(
    bb, email, password, idx=0, proxy_str=None, profile_id=None, ws=""
):
    """Authorize Graph via Device Code, reusing a live registration profile when supplied."""
    tag = f"[#{idx}][graph-browser]"
    reused_profile = bool(profile_id)
    try:
        if not profile_id:
            name = f"outlook_graph_{datetime.now().strftime('%m%d_%H%M%S')}_{idx}"
            for attempt in range(3):
                try:
                    profile_id = bb.create_browser(name=name, proxy_str=proxy_str)
                    break
                except Exception as e:
                    if attempt >= 2:
                        raise
                    print(f"  {tag} create retry {attempt + 1}/3: {str(e)[:80]}")
                    await asyncio.sleep(3 + attempt)
            if not profile_id:
                return None
        print(f"  {tag} using {'registration' if reused_profile else 'new'} browser profile for Graph")
        if not ws:
            info = bb.open_browser(profile_id)
            ws = info.get("ws", "")
        if not ws:
            print(f"  {tag} no WebSocket URL")
            return None
        async with async_playwright() as p:
            browser = await p.chromium.connect_over_cdp(ws)
            context = browser.contexts[0] if browser.contexts else await browser.new_context()
            page = await _browser_page(context)
            await install_traffic_saver(context)
            return await extract_graph_token(page, context, email, password, idx)
    except Exception as e:
        print(f"  {tag} error: {str(e)[:140]}")
        return None
    finally:
        if profile_id:
            try:
                bb.close_browser(profile_id)
                await asyncio.sleep(2)
                bb.delete_browser(profile_id)
                print(f"  {tag} browser cleaned up")
            except Exception:
                pass


# ======================== Main ========================

async def register_one(bb, idx, proxy_str, results, results_lock, live_fh=None, mode="auto"):
    """
    Register one Outlook account with fallback across three modes.
      mode="auto"     — protocol → headless → browser (fallback chain)
      mode="protocol" — HTTP only, fastest, lowest traffic
      mode="headless" — headless Playwright, no BitBrowser, ~70% less traffic
      mode="browser"  — BitBrowser full GUI, highest traffic, most reliable
    """
    tag = f"[#{idx}]"
    email, password = None, None
    used_mode = None
    registration_profile_id = None
    registration_ws = ""

    try:
        # ── 1. Protocol mode (pure HTTP, ~50KB) ──────────────────
        if mode in ("auto", "protocol"):
            print(f"  {tag} [1/3] protocol mode...")
            loop = asyncio.get_event_loop()
            email, password = await loop.run_in_executor(
                None, register_outlook_protocol, proxy_str, idx
            )
            if email:
                used_mode = "protocol"

        # ── 2. Headless mode (~70% less traffic than browser) ────
        # Use shorter timeout so we fall back to browser faster on captcha stall
        HEADLESS_TIMEOUT = min(REGISTER_TIMEOUT, 180)
        if not email and mode in ("auto", "headless"):
            print(f"  {tag} [2/3] headless mode (timeout={HEADLESS_TIMEOUT}s)...")
            try:
                email, password = await asyncio.wait_for(
                    _register_one_headless(idx, proxy_str),
                    timeout=HEADLESS_TIMEOUT,
                )
            except asyncio.TimeoutError:
                print(f"  {tag} headless timeout → falling back to browser")
            if email:
                used_mode = "headless"

        # ── 3. Browser mode (BitBrowser, full GUI) ───────────────
        if not email and mode in ("auto", "browser"):
            print(f"  {tag} [3/3] fingerprint browser mode...")
            try:
                browser_result = await asyncio.wait_for(
                    _register_one_browser(bb, idx, proxy_str, keep_profile=True),
                    timeout=REGISTER_TIMEOUT,
                )
                email, password, registration_profile_id, registration_ws = browser_result
            except asyncio.TimeoutError:
                print(f"  {tag} browser timeout")
            if email:
                used_mode = "browser"

    except Exception as e:
        print(f"  {tag} FATAL: {e}")

    graph = None
    if email:
        print(f"  {tag} [graph] extracting refresh_token via Device Code...")
        if registration_profile_id:
            graph = await extract_graph_token_browser(
                bb, email, password, idx, proxy_str,
                profile_id=registration_profile_id, ws=registration_ws,
            )
        else:
            graph = await extract_graph_token_browser(bb, email, password, idx, proxy_str)
        terminal_graph_error = (graph or {}).get("terminal_error")
        if (
            microsoft_auth_allows_http_fallback(terminal_graph_error)
            and (not graph or not graph.get("refresh_token"))
        ):
            print(f"  {tag} [graph] browser authorization failed; trying HTTP fallback")
            loop = asyncio.get_event_loop()
            fallback_graph = await loop.run_in_executor(
                None, extract_graph_token_http, email, password, idx
            )
            if fallback_graph and fallback_graph.get("refresh_token"):
                graph = fallback_graph
                terminal_graph_error = ""

    # ── Save result ───────────────────────────────────────────────
    async with results_lock:
        if email:
            if graph and graph.get("refresh_token"):
                results.append({
                    "index": idx, "email": email, "password": password,
                    "status": "OK", "proxy": proxy_str, "mode": used_mode,
                    "graph": graph,
                })
                if live_fh:
                    live_fh.write(
                        f"{email}----{password}----{graph['refresh_token']}----{graph.get('client_id', '')}\n"
                    )
                    live_fh.flush()
                print(f"  {tag} SUCCESS [{used_mode} +graph]: {email}")
            else:
                results.append({
                    "index": idx, "email": email, "password": password,
                    "status": "GRAPH_FAIL", "proxy": proxy_str, "mode": used_mode,
                    "terminal_error": terminal_graph_error,
                })
                if terminal_graph_error:
                    print(
                        f"  {tag} graph stopped ({terminal_graph_error}); "
                        f"credentials were not retried: {email}"
                    )
                else:
                    print(f"  {tag} REGISTERED but graph RT missing; not saved: {email}")
        else:
            results.append({
                "index": idx, "email": None, "password": None,
                "status": "FAIL", "proxy": proxy_str,
            })
            print(f"  {tag} FAILED all modes")


async def main():
    parser = argparse.ArgumentParser(description="Standalone Outlook Registration — multi-mode with fallback")
    parser.add_argument("--count", "-n", type=int, default=10, help="Number of accounts to register")
    parser.add_argument("--concurrency", "-c", type=int, default=2, help="Parallel registrations")
    parser.add_argument("--proxy-file", "-p", type=str, help="Proxy file (one per line: user:pass@host:port)")
    parser.add_argument("--no-proxy", action="store_true", default=False, help="No proxy")
    parser.add_argument("--timeout", "-t", type=int, default=300, help="Per-account timeout (seconds)")
    parser.add_argument("--mode", "-m", type=str, default="auto",
                        choices=["auto", "protocol", "headless", "browser"],
                        help="auto=protocol→headless→browser fallback; or fix to one mode")
    parser.add_argument("--no-verify", action="store_true",
                        help="Do not verify Outlook login before writing successful accounts")
    parser.add_argument("--confirm-before-register", action="store_true",
                        help="Auto-click confirmation on the signup page before filling")
    args = parser.parse_args()

    global REGISTER_TIMEOUT, VERIFY_AFTER_REGISTER
    REGISTER_TIMEOUT = args.timeout
    VERIFY_AFTER_REGISTER = not args.no_verify
    if args.confirm_before_register:
        os.environ["OUTLOOK_CONFIRM_BEFORE_REGISTER"] = "1"
    proxy_env = ensure_clash_proxy_env()
    if proxy_env:
        print(f"  proxy env ready: {proxy_env}")

    # Load proxies
    proxy_pool = []
    if args.proxy_file:
        with open(args.proxy_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    proxy_pool.append(line)
        if not proxy_pool:
            print("  WARNING: proxy file is empty, falling back to DEFAULT_PROXIES")

    if not proxy_pool and not args.no_proxy:
        proxy_pool = list(DEFAULT_PROXIES)

    count = args.count
    if args.no_proxy:
        # noproxy mode: fill with None
        proxies = [None] * count
    elif proxy_pool:
        # Cycle proxies: assign round-robin to each account
        proxies = [proxy_pool[i % len(proxy_pool)] for i in range(count)]
    else:
        proxies = [None] * count

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    bb = BitBrowserClient()

    proxy_mode = "noproxy" if args.no_proxy else f"{len(proxy_pool)} unique proxies (cycling for {count} accounts)"
    mode_desc = {
        "auto":     "protocol → headless → browser (fallback chain)",
        "protocol": "protocol only (pure HTTP, lowest traffic)",
        "headless": "headless only (no BitBrowser, -70% traffic)",
        "browser":  "selected fingerprint browser only (full GUI)",
    }
    print("=" * 60)
    print("  Outlook Registration - Multi-mode")
    print(f"  count={count}  concurrency={args.concurrency}  timeout={args.timeout}s")
    print(f"  mode:  {args.mode} — {mode_desc[args.mode]}")
    print(f"  proxy: {proxy_mode}")
    print("=" * 60)

    results = []
    results_lock = asyncio.Lock()
    sem = asyncio.Semaphore(args.concurrency)

    # Real-time incremental output files
    ts_live = datetime.now().strftime('%Y%m%d_%H%M%S')
    live_file = os.path.join(OUTPUT_DIR, f"accounts_{ts_live}.txt")
    live_fh = open(live_file, "a", encoding="utf-8", buffering=1)
    print(f"  Live output: {live_file}")

    async def run_one(i):
        async with sem:
            if i > 0:
                await asyncio.sleep(random.uniform(2, 5))
            proxy = proxies[i]
            print(f"\n{'#' * 50}")
            print(f"  Account #{i + 1}/{count}")
            print(f"{'#' * 50}")
            await register_one(bb, i + 1, proxy, results, results_lock, live_fh, mode=args.mode)

    await asyncio.gather(*[run_one(i) for i in range(count)])
    live_fh.close()

    # Summary
    print(f"\n{'=' * 60}")
    print(f"  RESULTS: {len(results)} total")
    print(f"{'=' * 60}")

    ok_count = 0
    graph_count = 0
    mode_counts = {"protocol": 0, "headless": 0, "browser": 0}
    ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(OUTPUT_DIR, f"accounts_{ts_str}.txt")
    token_file = os.path.join(OUTPUT_DIR, f"graph_tokens_{ts_str}.json")

    all_tokens = []
    with open(output_file, "w", encoding="utf-8") as f:
        for r in sorted(results, key=lambda x: x['index']):
            if r['status'] == "OK":
                ok_count += 1
                line = f"{r['email']}----{r['password']}"
                graph = r.get("graph")
                if graph and graph.get("refresh_token"):
                    graph_count += 1
                    line += f"----{graph['refresh_token']}----{graph.get('client_id', '')}"
                    all_tokens.append({
                        "email": r['email'],
                        "password": r['password'],
                        "access_token": graph.get('access_token'),
                        "refresh_token": graph.get('refresh_token'),
                        "client_id": graph.get('client_id'),
                        "expires_in": graph.get('expires_in'),
                    })
                f.write(line + "\n")
                used = r.get("mode", "?")
                mode_counts[used] = mode_counts.get(used, 0) + 1
                gt = " +graph" if graph and graph.get("refresh_token") else ""
                print(f"  #{r['index']} [OK/{used}{gt}] {r['email']} / {r['password']}")
            else:
                print(f"  #{r['index']} [{r['status']}] -")

    if all_tokens:
        with open(token_file, "w", encoding="utf-8") as f:
            json.dump(all_tokens, f, indent=2, ensure_ascii=False)

    mode_str = "  |  ".join(f"{m}:{c}" for m, c in mode_counts.items() if c > 0)
    print(f"\n  Success: {ok_count}/{len(results)}  |  {mode_str}  |  Graph tokens: {graph_count}")
    if ok_count > 0:
        print(f"  Accounts: {output_file}")
    if graph_count > 0:
        print(f"  Tokens:   {token_file}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
