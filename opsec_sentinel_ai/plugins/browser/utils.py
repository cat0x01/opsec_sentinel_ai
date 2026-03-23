from __future__ import annotations

from typing import Any, Tuple


async def get_playwright_page(user_agent: str, width: int, height: int):
    try:
        from playwright.async_api import async_playwright
    except Exception as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("Playwright is not installed. Install with pip install -e .[browser]") from exc

    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(headless=True)
    context = await browser.new_context(user_agent=user_agent, viewport={"width": width, "height": height})
    page = await context.new_page()
    await page.goto("about:blank")
    return playwright, browser, context, page


async def close_playwright(playwright: Any, browser: Any, context: Any) -> None:
    try:
        await context.close()
    except Exception:
        pass
    try:
        await browser.close()
    except Exception:
        pass
    try:
        await playwright.stop()
    except Exception:
        pass
