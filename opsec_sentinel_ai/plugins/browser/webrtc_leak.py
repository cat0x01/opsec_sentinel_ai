from __future__ import annotations

from datetime import datetime, timezone

from opsec_sentinel_ai.core.models import Finding, ScanResult, ScanStatus, Severity
from opsec_sentinel_ai.core.plugin import ScannerPlugin
from opsec_sentinel_ai.plugins.browser.utils import close_playwright, get_playwright_page


class WebRTCLeakPlugin(ScannerPlugin):
    plugin_id = "browser.webrtc_leak"
    name = "WebRTC Leak Detection"
    category = "browser_privacy"
    resource_lock = "browser"
    timeout_seconds = 30

    async def run(self, ctx) -> ScanResult:
        started_at = datetime.now(timezone.utc).isoformat()
        status = ScanStatus.ok
        findings = []
        data = {"candidates": []}

        playwright = browser = context = None
        try:
            playwright, browser, context, page = await get_playwright_page(
                ctx.config.browser.user_agent,
                ctx.config.browser.viewport_width,
                ctx.config.browser.viewport_height,
            )
            script = r"""
            async () => {
              const ips = new Set();
              const pc = new RTCPeerConnection({iceServers: []});
              pc.createDataChannel('test');
              const offer = await pc.createOffer();
              await pc.setLocalDescription(offer);
              return new Promise((resolve) => {
                pc.onicecandidate = (event) => {
                  if (!event.candidate) {
                    pc.close();
                    resolve(Array.from(ips));
                    return;
                  }
                  const cand = event.candidate.candidate;
                  const parts = cand.split(' ');
                  for (const token of parts) {
                    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(token);
                    const ipv6 = /^[0-9a-fA-F:]+$/.test(token) && token.includes(':') && token.length > 3;
                    const mdns = token.endsWith('.local');
                    if (ipv4 || ipv6 || mdns) {
                      ips.add(token);
                    }
                  }
                };
              });
            }
            """
            candidates = await page.evaluate(script)
            data["candidates"] = candidates
        except Exception as exc:
            status = ScanStatus.error
            findings.append(
                Finding(
                    id="webrtc.failed",
                    title="WebRTC check failed",
                    severity=Severity.medium,
                    description=f"WebRTC evaluation failed: {exc}",
                    recommendation="Verify Playwright installation and browser permissions.",
                )
            )
        finally:
            if playwright and browser and context:
                await close_playwright(playwright, browser, context)

        if data["candidates"]:
            status = ScanStatus.warning
            findings.append(
                Finding(
                    id="webrtc.ip_detected",
                    title="WebRTC candidates exposed",
                    severity=Severity.medium,
                    description="WebRTC exposed ICE candidates which may include local or public IPs.",
                    recommendation="Disable WebRTC or use browser settings/extensions to prevent leaks.",
                    evidence={"candidates": data["candidates"]},
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
