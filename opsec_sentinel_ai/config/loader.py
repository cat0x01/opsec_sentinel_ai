from __future__ import annotations

import os
import re
from dataclasses import replace
from pathlib import Path
from typing import Optional

from dotenv import find_dotenv, load_dotenv

from opsec_sentinel_ai.analysis.modes import resolve_mode_config
from opsec_sentinel_ai.config.settings import AppConfig


def load_config(dotenv_path: Optional[str] = None, mode_name: Optional[str] = None) -> AppConfig:
    env_path: Optional[str] = None
    if dotenv_path:
        load_dotenv(dotenv_path, override=True)
        env_path = dotenv_path
    else:
        found = find_dotenv(usecwd=True)
        if found:
            load_dotenv(found, override=True)
            env_path = found
        else:
            root_env = Path(__file__).resolve().parents[2] / ".env"
            if root_env.exists():
                load_dotenv(root_env, override=True)
                env_path = str(root_env)

    cfg = AppConfig()
    ai_enabled = os.getenv("OPSEC_AI_ENABLED", "true").lower() == "true"
    api_key = _clean_api_key(os.getenv("ANTHROPIC_API_KEY") or os.getenv("CEREBRAS_API_KEY"))
    model = os.getenv("ANTHROPIC_MODEL") or os.getenv("CEREBRAS_MODEL", cfg.ai.model)
    cfg.ai = replace(cfg.ai, enabled=ai_enabled, api_key=api_key, model=model)
    cfg.env_path = env_path

    tor_url = os.getenv("OPSEC_TOR_CHECK_URL")
    cfg.network = replace(cfg.network, tor_check_url=tor_url)

    geoip_url = os.getenv("OPSEC_GEOIP_URL")
    header_url = os.getenv("OPSEC_HEADER_CHECK_URL")
    cfg.fingerprint = replace(cfg.fingerprint, geoip_url=geoip_url, header_check_url=header_url)

    browser_enabled = os.getenv("OPSEC_BROWSER_ENABLED", "true").lower() == "true"
    cfg.browser = replace(cfg.browser, enabled=browser_enabled)

    plugin_dirs = [item.strip() for item in os.getenv("OPSEC_PLUGIN_DIRS", "").split(",") if item.strip()]
    cfg.engine = replace(cfg.engine, plugin_directories=plugin_dirs)

    monitoring_enabled = os.getenv("OPSEC_MONITORING_ENABLED", "false").lower() == "true"
    cfg.monitoring = replace(cfg.monitoring, enabled=monitoring_enabled)

    recon_enabled = os.getenv("OPSEC_RECON_ENABLED", "true").lower() == "true"
    cfg.recon = replace(cfg.recon, enabled=recon_enabled)

    selected_mode = mode_name or os.getenv("OPSEC_MODE", cfg.mode.name)
    cfg.mode = resolve_mode_config(selected_mode)
    if cfg.mode.live_monitoring_enabled:
        cfg.monitoring = replace(cfg.monitoring, enabled=True)
    if not cfg.mode.external_recon_enabled:
        cfg.recon = replace(cfg.recon, enabled=False)

    return cfg


def _clean_api_key(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    cleaned = value.strip()
    match = re.match(r"^(['\"])(.*)\\1$", cleaned)
    if match:
        cleaned = match.group(2).strip()
    return cleaned or None
