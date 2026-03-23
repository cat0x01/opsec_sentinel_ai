from __future__ import annotations

from datetime import datetime, timezone

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin
from opsec_sentinel_ai.plugins.browser.utils import close_playwright, get_playwright_page


class WebGLFingerprintPlugin(ScannerPlugin):
    plugin_id = "browser.webgl_fingerprint"
    name = "WebGL Vendor Fingerprint"
    category = "browser_privacy"
    resource_lock = "browser"
    timeout_seconds = 30

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        status = ScanStatus.ok
        findings = []
        data = {"vendor": None, "renderer": None, "unmasked_vendor": None, "unmasked_renderer": None}

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
              const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
              if (!gl) return null;
              const vendor = gl.getParameter(0x1F00);
              const renderer = gl.getParameter(0x1F01);
              const ext = gl.getExtension('WEBGL_debug_renderer_info');
              let unmaskedVendor = null;
              let unmaskedRenderer = null;
              if (ext) {
                unmaskedVendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);
                unmaskedRenderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
              }
              return {
                vendor,
                renderer,
                unmaskedVendor,
                unmaskedRenderer,
              };
            }
            """
            result = await page.evaluate(script)
            if result:
                data["vendor"] = result.get("vendor")
                data["renderer"] = result.get("renderer")
                data["unmasked_vendor"] = result.get("unmaskedVendor")
                data["unmasked_renderer"] = result.get("unmaskedRenderer")
        except Exception as exc:
            status = ScanStatus.error
            findings.append(
                Finding(
                    id="webgl.failed",
                    title="WebGL fingerprint check failed",
                    severity=Severity.medium,
                    description=f"WebGL evaluation failed: {exc}",
                    recommendation="Verify Playwright installation and GPU availability.",
                )
            )
        finally:
            if playwright and browser and context:
                await close_playwright(playwright, browser, context)

        if data["unmasked_renderer"] or data["renderer"]:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="webgl.exposed",
                    title="WebGL fingerprintable data detected",
                    severity=Severity.low,
                    description="WebGL exposes vendor/renderer values useful for fingerprinting.",
                    recommendation="Consider browser hardening to reduce WebGL fingerprint surface.",
                    evidence=data,
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
