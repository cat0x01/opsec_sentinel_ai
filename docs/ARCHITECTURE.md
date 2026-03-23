# OPSEC Sentinel AI v2 Architecture

## Mission Profile

`OPSEC Sentinel AI` is upgraded from a point-in-time privacy scanner into a mode-aware adversary-simulation framework that models how an external observer can correlate infrastructure, browser, timing, and environment signals to deanonymize an operator.

The design keeps active exploitation out of scope. Instead, it emulates offensive tradecraft as deterministic scoring and attack-path correlation so defenders can harden anonymity posture without launching real attacks.

## Core Pipeline

1. `Plugin discovery`
   Load built-in plugins plus optional dynamic plugins from `OPSEC_PLUGIN_DIRS`.
2. `Concurrent collection`
   Run network, browser, system, behavioral, environment, and recon plugins with bounded concurrency.
3. `Correlation layer`
   Aggregate findings into attack-path scenarios, fingerprint coherence scoring, and behavioral automation estimates.
4. `Live monitoring`
   Optionally run a monitoring daemon snapshot to catch DNS or route leaks in near-real time.
5. `Recommendation engine`
   Convert findings into exact commands, files, and configuration actions.
6. `Visualization synthesis`
   Emit graph and heatmap payloads for HTML, API, or dashboard consumption.
7. `Reporting`
   Produce JSON, Markdown, HTML, and optional PDF outputs.

## Modes

### `normal`
- Balanced thresholds for everyday privacy hygiene.
- Recon and browser checks enabled.
- Lower alert sensitivity to reduce noise.

### `bugbounty`
- Assumes mixed manual and automated workflows.
- Enables live monitoring by default.
- Accepts some automation signatures but still penalizes exposure and inconsistency.

### `darknet`
- Strictest profile.
- Treats public DNS, exposed services, and fingerprint mismatches as high-confidence deanonymization paths.
- Raises scenario confidence and fingerprint integrity floors.

## Attack Simulation Engine

The attack simulator correlates plugin outputs into adversary-relevant scenarios:

- `Identity Correlation Collision`
  IP geography, timezone, headers, and host claims.
- `Persistent Browser Tracking`
  WebGL, canvas, fonts, and session-level browser consistency.
- `Network Leak Chaining`
  DNS, WebRTC, IPv6, and clearnet path leakage.
- `Traffic Timing Correlation`
  Low jitter, burst behavior, and consistent request cadence.

Each scenario includes:

- `risk_score`
- `success_probability`
- `supporting_findings`
- `mode`

## Plugin Architecture

Each check remains a `ScannerPlugin`, but the registry now supports:

- built-in plugins
- mode filtering by category
- external plugin directories via dynamic loading

This allows teams to add organization-specific OPSEC checks without editing the core engine.

## Monitoring Daemon

`MonitoringDaemon` performs repeated snapshots of high-signal leak indicators:

- public DNS resolvers
- future clearnet egress checks
- future IPv6 route exposure
- future per-process connection attribution

The daemon output is normalized as timestamped alerts with severity and contextual evidence, making it easy to feed a dashboard or SIEM.

## Behavioral Analysis

Behavioral scoring estimates whether activity patterns resemble automation:

- low-jitter request intervals
- burst density
- session consistency markers
- human-like versus bot-like cadence

This closes a common OPSEC blind spot: the operator may hide transport well but still expose themselves through machine-like timing.

## Fingerprint Integrity

The v2 integrity model scores internal coherence rather than only raw entropy:

- UA versus OS claims
- timezone versus IP geography
- WebGL versus plausible hardware profile
- fonts and display anomalies
- browser leak overlap with network traits

This is closer to how mature anti-abuse systems evaluate identities in practice.

## Visualization Payload

The reporting layer now emits:

- graph `nodes`
- graph `edges`
- risk `heatmap`

These payloads are intentionally simple JSON structures so a future FastAPI dashboard, Sigma-style exporter, or frontend graph library can consume them directly.

## Recommended Next Step

The next meaningful upgrade is a dedicated API service:

- `FastAPI` backend for report retrieval and live monitoring streams
- SSE/WebSocket channel for alerts
- D3 or Cytoscape-based graph view
- historical diffing between scans
