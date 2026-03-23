from __future__ import annotations

from datetime import datetime, timezone
import hashlib

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin
from opsec_sentinel_ai.plugins.browser.utils import close_playwright, get_playwright_page
from opsec_sentinel_ai.utils.entropy import shannon_entropy


class CanvasFingerprintPlugin(ScannerPlugin):
    plugin_id = "browser.canvas_entropy"
    name = "Canvas Fingerprint Entropy"
    category = "browser_privacy"
    resource_lock = "browser"
    timeout_seconds = 30

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        status = ScanStatus.ok
        findings = []
        data = {"hash": None, "entropy": 0.0}

        playwright = browser = context = None
        try:
            playwright, browser, context, page = await get_playwright_page(
                ctx.config.browser.user_agent,
                ctx.config.browser.viewport_width,
                ctx.config.browser.viewport_height,
            )
            script = """
            () => {
              const canvas = document.createElement('canvas');
              const ctx = canvas.getContext('2d');
              canvas.width = 400;
              canvas.height = 120;
              ctx.textBaseline = 'top';
              ctx.font = "16px 'Arial'";
              ctx.fillStyle = '#f60';
              ctx.fillRect(125, 1, 62, 20);
              ctx.fillStyle = '#069';
              ctx.fillText('OPSEC Sentinel AI', 2, 15);
              ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
              ctx.fillText('Fingerprint Test', 4, 45);
              return canvas.toDataURL();
            }
            """
            data_url = await page.evaluate(script)
            if data_url:
                digest = hashlib.sha256(data_url.encode("utf-8")).hexdigest()
                data["hash"] = digest
                data["entropy"] = shannon_entropy(digest)
        except Exception as exc:
            status = ScanStatus.error
            findings.append(
                Finding(
                    id="canvas.failed",
                    title="Canvas fingerprint check failed",
                    severity=Severity.medium,
                    description=f"Canvas evaluation failed: {exc}",
                    recommendation="Verify Playwright installation and browser permissions.",
                )
            )
        finally:
            if playwright and browser and context:
                await close_playwright(playwright, browser, context)

        if data["entropy"] > 4.0:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="canvas.entropy",
                    title="Canvas fingerprint entropy detected",
                    severity=Severity.low,
                    description="Canvas rendering produced a stable fingerprint with measurable entropy.",
                    recommendation="Use browser hardening to reduce canvas fingerprinting surface.",
                    evidence={"entropy": data["entropy"]},
                )
            )

        return ScanResult(
            plugin_id=self.plugin_id,
            name=self.name,
            category=self.category,
            status=status,
            data=data,
            findings=findings,
            started_at=started_at,
        )
