"""CloakBrowser adapter used by the existing async registration flow.

The reference project launches Cloak's native fingerprint Chromium directly
instead of creating a second Playwright CDP client.  This small handle keeps
the BitBrowser-compatible lifecycle expected by ``common.browser`` while
letting Cloak own the browser context and fingerprint.
"""

from __future__ import annotations

import os
import uuid

from config import (
    CLOAK_EXTRA_ARGS,
    CLOAK_FINGERPRINT_SEED,
    CLOAK_GEOIP,
    CLOAK_HEADLESS,
    CLOAK_HUMANIZE,
    CLOAK_LICENSE_KEY,
    CLOAK_LOCALE,
    CLOAK_TIMEZONE,
    CLOAK_USER_DATA_DIR,
)

def _launch_geoip_fallback(exc: Exception) -> tuple[str | None, str | None] | None:
    """Resolve locale/timezone without cloakbrowser's GeoIP module.

    The bundled resolver uses third-party IP echo endpoints with a hard 20 s
    deadline.  Residential gateways frequently stall those calls even though
    the proxy itself works, which aborts the whole launch.  This fallback
    queries the exit IP through the same proxy (several providers) and then
    reads the bundled MaxMind database directly.
    """
    message = str(exc).lower()
    if "geoip" not in message and "exit ip" not in message:
        return None
    import config as cfg

    try:
        from common import direct_proxy

        proxy = direct_proxy.configured_proxy()
        proxy_url = proxy.url if proxy else None
    except Exception:
        proxy_url = None
    import requests

    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    ip = None
    for url in (
        "https://api.ipify.org?format=json",
        "https://ipinfo.io/json",
        "https://ipwho.is/",
        "https://checkip.amazonaws.com",
        "https://api.ipify.org",
    ):
        try:
            resp = requests.get(url, proxies=proxies, timeout=8)
            resp.raise_for_status()
            body = resp.text.strip()
            if body.startswith("{"):
                import json

                payload = json.loads(body)
                ip = payload.get("ip") or payload.get("query") or payload.get("IP")
            else:
                ip = body.split()[0]
            if ip:
                break
        except Exception:
            continue
    if not ip:
        print("  CloakBrowser GeoIP fallback: exit IP unavailable; using fixed locale")
        return ("America/Los_Angeles" if not proxy_url else None, "en-US")
    try:
        from cloakbrowser import geoip as cloak_geoip

        db_path = cloak_geoip._ensure_geoip_db()  # type: ignore[attr-defined]
        import geoip2.database

        with geoip2.database.Reader(str(db_path)) as reader:
            resp = reader.city(ip)
            timezone = resp.location.time_zone
            country = resp.country.iso_code
            locale = cloak_geoip.COUNTRY_LOCALE_MAP.get(country)  # type: ignore[attr-defined]
        print(f"  CloakBrowser GeoIP fallback: {ip} -> {country} {timezone or ''}")
        return timezone, locale or "en-US"
    except Exception as inner:
        print(f"  CloakBrowser GeoIP fallback failed: {type(inner).__name__}; using fixed locale")
        return (None, "en-US")


def _proxy_url(browser_options: dict | None = None) -> str | None:
    options = dict(browser_options or {})
    if str(options.get("proxyType") or "").lower() == "noproxy":
        return None
    raw = options.get("proxy_str") or options.get("proxyUrl") or options.get("proxy")
    if raw:
        return str(raw).replace("socks5h://", "socks5://")
    try:
        from common import proxy_switch

        value = proxy_switch.effective_proxy_url()
        return str(value or "").replace("socks5h://", "socks5://") or None
    except Exception:
        return None


class CloakBrowserHandle:
    provider_name = "cloak"

    def __init__(self, context, *, profile_id: str, name: str):
        self.context = context
        self.profile_id = str(profile_id)
        self.name = str(name)
        self.browser = getattr(context, "browser", None) or context

    async def close_browser_async(self, profile_id: str | None = None):
        if profile_id and str(profile_id) != self.profile_id:
            return {"success": True}
        try:
            await self.context.close()
        except Exception:
            pass
        return {"success": True}

    def close_browser(self, profile_id: str | None = None):
        # common.browser.teardown prefers the async method for this provider.
        return {"success": True}

    def delete_browser(self, profile_id: str | None = None):
        try:
            from common.browser_registry import unregister

            unregister(profile_id or self.profile_id)
        except Exception:
            pass
        return {"success": True}

    async def launch(self, name: str, browser_options: dict | None = None):
        try:
            from cloakbrowser import launch_context_async, launch_persistent_context_async
        except ImportError as exc:
            raise RuntimeError(
                "未安装 CloakBrowser，请执行：pip install \"cloakbrowser[geoip]>=0.4.10\""
            ) from exc

        args = list(CLOAK_EXTRA_ARGS or [])
        if CLOAK_FINGERPRINT_SEED:
            args.append(f"--fingerprint={CLOAK_FINGERPRINT_SEED.strip()}")
        proxy = _proxy_url(browser_options)
        locale = CLOAK_LOCALE.strip() or "en-US"
        language_header = f"{locale},en;q=0.9"
        options = {
            "headless": bool(CLOAK_HEADLESS),
            "humanize": bool(CLOAK_HUMANIZE),
            "geoip": bool(CLOAK_GEOIP),
            "locale": locale,
            "extra_http_headers": {"Accept-Language": language_header},
        }
        if proxy:
            options["proxy"] = proxy
        if args:
            options["args"] = args
        if CLOAK_TIMEZONE.strip():
            options["timezone"] = CLOAK_TIMEZONE.strip()
        if CLOAK_LICENSE_KEY.strip():
            options["license_key"] = CLOAK_LICENSE_KEY.strip()

        user_data_dir = CLOAK_USER_DATA_DIR.strip()

        async def _launch(**opts):
            if user_data_dir:
                return await launch_persistent_context_async(user_data_dir, **opts)
            return await launch_context_async(**opts)

        try:
            context = await _launch(**options)
        except RuntimeError as exc:
            # cloakbrowser's GeoIP resolver aborts the launch when its IP echo
            # services stall behind the residential gateway. Resolve the
            # locale ourselves and keep the native fingerprint.
            fallback = _launch_geoip_fallback(exc) if options.get("geoip") else None
            if fallback is None:
                raise
            timezone, resolved_locale = fallback
            options["geoip"] = False
            if resolved_locale:
                options["locale"] = resolved_locale
                options["extra_http_headers"] = {
                    "Accept-Language": resolved_locale + ",en;q=0.9"
                }
            if timezone:
                options["timezone"] = timezone
            context = await _launch(**options)
        except ImportError as exc:
            # geoip2 is optional. Cloak's native fingerprint remains usable
            # without automatic language/timezone lookup.
            if not options.get("geoip") or "geoip" not in str(exc).lower():
                raise
            options["geoip"] = False
            print("  CloakBrowser geoip2 unavailable; continuing with native fingerprint")
            if user_data_dir:
                context = await launch_persistent_context_async(user_data_dir, **options)
            else:
                context = await launch_context_async(**options)
        profile_id = f"cloak-{uuid.uuid4().hex}"
        handle = CloakBrowserHandle(context, profile_id=profile_id, name=name)
        try:
            from common.browser_registry import register

            register(profile_id, name=name, provider="cloak")
        except Exception:
            pass
        print(f"  CloakBrowser profile created: {name} ({profile_id})")
        return handle, profile_id, context
