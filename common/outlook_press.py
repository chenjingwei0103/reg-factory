# -*- coding: utf-8 -*-
"""Shared Outlook PerimeterX press-and-hold behavior.

Registration and recovery must use this module together. Keeping target
selection and the physical press sequence in one place prevents the two flows
from slowly diverging as Microsoft's challenge markup changes.
"""

from __future__ import annotations

import asyncio
import random

from common import human_mouse


async def _viewport_size(page):
    try:
        value = await page.evaluate(
            "() => ({width: window.innerWidth, height: window.innerHeight})"
        )
        if isinstance(value, dict):
            width = float(value.get("width") or 0)
            height = float(value.get("height") or 0)
            if width > 0 and height > 0:
                return width, height
    except Exception:
        pass
    return None


def _box_in_viewport(box, viewport, *, min_width=0, min_height=0):
    if (
        not box
        or box.get("width", 0) <= min_width
        or box.get("height", 0) <= min_height
    ):
        return False
    if not viewport:
        return box.get("x", 0) >= 0 and box.get("y", 0) >= 0
    width, height = viewport
    center_x = float(box.get("x", 0)) + float(box.get("width", 0)) / 2
    center_y = float(box.get("y", 0)) + float(box.get("height", 0)) / 2
    return 0 <= center_x < width and 0 <= center_y < height


async def captcha_visible(page):
    """Return whether an interactive Outlook hold challenge is still visible."""
    viewport = await _viewport_size(page)
    try:
        for selector in (
            'button:has-text("Press and hold")',
            'button:has-text("Appuyer et maintenir")',
            'button:has-text("按住")',
            'button:has-text("长按")',
            'button:has-text("Halten")',
            '#px-captcha',
        ):
            element = page.locator(selector).first
            if await element.count() > 0:
                box = await element.bounding_box()
                if _box_in_viewport(box, viewport, min_width=30, min_height=8):
                    return True

        frames = page.locator(
            'iframe[src*="hsprotect.net"], '
            'iframe[src*="arkose"], '
            'iframe[src*="funcaptcha"]'
        )
        for index in range(await frames.count()):
            box = await frames.nth(index).bounding_box()
            if _box_in_viewport(box, viewport, min_width=50, min_height=30):
                return True

        # Some sessions render the hold target without any #px-captcha node.
        # Text on the visible challenge frame is enough to say "still pending".
        for frame in page.frames:
            try:
                if "hsprotect.net" not in (frame.url or ""):
                    continue
                text = (await frame.evaluate("() => document.body ? document.body.innerText : ''")) or ""
            except Exception:
                continue
            lowered = text.lower()
            if any(marker in lowered for marker in (
                "press and hold", "appuyer et maintenir", "halten",
                "\u6309\u4f4f", "\u9577\u6309", "\u957f\u6309",
                "\u62bc\u3057\u7d9a\u3051", "\ub204\ub974\uace0",
            )):
                return True
    except Exception:
        pass
    return False


async def find_hold_target(page):
    """Locate the interactive hold button inside the live challenge frame.

    The challenge is rendered inside one or more hsprotect.net frames at an
    offset that bounding_box() does not translate.  The button geometry is
    read inside the frame itself and converted to page coordinates, so the
    physical press lands on the button rather than the frame edge.
    """
    viewport = await _viewport_size(page)
    refresh_frames = getattr(page, "_refresh_frames", None)
    if refresh_frames:
        try:
            await refresh_frames(force=True)
        except Exception:
            pass

    markers = (
        "press and hold", "appuyer et maintenir", "halten",
        "\u6309\u4f4f", "\u9577\u6309", "\u957f\u6309",
        "\u62bc\u3057\u7d9a\u3051", "\ub204\ub974\uace0",
    )
    for frame in page.frames:
        try:
            if "hsprotect.net" not in (frame.url or ""):
                continue
            found = await frame.evaluate(r"""() => {
                const nodes = [...document.querySelectorAll(
                    '#px-captcha, button, [role="button"], div, span'
                )];
                let best = null;
                for (const node of nodes) {
                    const rect = node.getBoundingClientRect();
                    if (rect.width < 40 || rect.height < 10) continue;
                    const style = getComputedStyle(node);
                    if (style.display === 'none' || style.visibility === 'hidden') continue;
                    if (Number(style.opacity || '1') < 0.2) continue;
                    const cursor = String(style.cursor || '').toLowerCase();
                    const label = String(node.innerText || node.textContent || '')
                        .trim().toLowerCase();
                    const idMatch = node.id === 'px-captcha';
                    const textMatch = label.includes('press and hold')
                        || label.includes('appuyer')
                        || label.includes('halten');
                    if (!idMatch && !textMatch && cursor !== 'pointer') continue;
                    const area = rect.width * rect.height;
                    if (!best || area < best.area) {
                        best = {
                            x: rect.x, y: rect.y,
                            width: rect.width, height: rect.height,
                            area,
                        };
                    }
                }
                return best;
            }""")
            if not isinstance(found, dict):
                continue
            page_box = await _frame_page_box(page, frame)
            if not page_box:
                print("  [hold] frame without page box: " + (frame.url or "")[:70])
                continue
            box = {
                "x": page_box["x"] + float(found["x"]),
                "y": page_box["y"] + float(found["y"]),
                "width": float(found["width"]),
                "height": float(found["height"]),
            }
            print(
                "  [hold] frame=({:.0f},{:.0f} {:.0f}x{:.0f}) elem=({:.0f},{:.0f} {:.0f}x{:.0f}) "
                "page=({:.0f},{:.0f} {:.0f}x{:.0f}) viewport={} url={}".format(
                    page_box["x"], page_box["y"], page_box["width"], page_box["height"],
                    float(found["x"]), float(found["y"]),
                    float(found["width"]), float(found["height"]),
                    box["x"], box["y"], box["width"], box["height"],
                    viewport, (frame.url or "")[:60],
                )
            )
            if _box_in_viewport(box, viewport, min_width=10, min_height=4):
                return box, True
            print("  [hold] target outside viewport, rescanning")
        except Exception:
            continue
    return None, False


async def _frame_page_box(page, frame):
    """Return the page-coordinate rectangle of a frame element."""
    try:
        handle = await frame.frame_element()
        box = await handle.bounding_box()
        if box and box.get("width", 0) > 0 and box.get("height", 0) > 0:
            return box
    except Exception:
        pass
    try:
        return await frame.evaluate(r"""() => {
            try {
                const rect = window.frameElement.getBoundingClientRect();
                return {x: rect.x, y: rect.y, width: rect.width, height: rect.height};
            } catch (e) {
                return null;
            }
        }""")
    except Exception:
        return None


async def press_and_hold(page, *, label="", press_number=1):
    """Run one registration-style hold attempt, or return None without a target."""
    target_box, box_is_button = await find_hold_target(page)
    if not target_box:
        return None

    bx = target_box["x"]
    by = target_box["y"]
    bw = target_box["width"]
    bh = target_box["height"]
    if box_is_button:
        cx = bx + bw * random.uniform(0.40, 0.60)
        cy = by + bh * random.uniform(0.40, 0.60)
    else:
        cx = bx + bw * random.uniform(0.42, 0.58)
        cy = by + bh * random.uniform(0.48, 0.62)

    suffix = " [btn]" if box_is_button else " [box]"
    print(f"{label} press #{press_number}: ({cx:.0f},{cy:.0f}){suffix}")

    async def hold_done():
        return not await captcha_visible(page)

    try:
        held, passed = await human_mouse.human_press_and_hold(
            page,
            cx,
            cy,
            is_done=hold_done,
            max_hold=random.uniform(11.0, 15.0),
            min_hold=1.5,
        )
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"
        print(f"{label} human_press_and_hold err: {message}")
        message_lower = message.lower()
        if "out of bounds" in message_lower or "outside viewport" in message_lower:
            print(f"{label} discarded off-screen captcha target; rescanning")
            return None
        if "closed" in message_lower or "targetclosed" in message_lower:
            print(f"{label} page/context 已关闭，跳过重按，交外层判定")
            held, passed = 0.0, False
        else:
            try:
                await page.mouse.down()
                await asyncio.sleep(random.uniform(11.0, 14.0))
                await page.mouse.up()
            except Exception:
                pass
            held, passed = 12.0, False

    try:
        still_visible = await captcha_visible(page)
    except Exception:
        still_visible = None
    print(
        f"{label} held {held:.1f}s{' (passed)' if passed else ''}"
        f" challenge_visible_after={still_visible}"
    )
    return {
        "held": held,
        "passed": passed,
        "box_is_button": box_is_button,
        "x": cx,
        "y": cy,
    }
