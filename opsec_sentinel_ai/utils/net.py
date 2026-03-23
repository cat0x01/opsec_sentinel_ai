from __future__ import annotations

import os
import platform
import re
import socket
import subprocess
from ipaddress import ip_address
from typing import Dict, List, Tuple


def is_private_ip(value: str) -> bool:
    try:
        return ip_address(value).is_private
    except ValueError:
        return False


def is_global_ip(value: str) -> bool:
    try:
        ip = ip_address(value)
        return ip.is_global
    except ValueError:
        return False


def _parse_resolv_conf(path: str = "/etc/resolv.conf") -> List[str]:
    nameservers: List[str] = []
    if not os.path.exists(path):
        return nameservers
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    nameservers.append(parts[1])
    return nameservers


def resolve_nameservers() -> List[str]:
    system = platform.system().lower()
    if system in {"linux", "darwin"}:
        nameservers = _parse_resolv_conf()
        if nameservers:
            return nameservers
        if system == "darwin":
            return _parse_macos_dns()
        return []
    if system == "windows":
        return _parse_windows_dns()
    return []


def _parse_macos_dns() -> List[str]:
    try:
        output = subprocess.check_output(["scutil", "--dns"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return []
    return _extract_ips(output)


def _parse_windows_dns() -> List[str]:
    try:
        output = subprocess.check_output(["ipconfig", "/all"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return []
    return _extract_ips(output)


def _extract_ips(text: str) -> List[str]:
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    return list({match.group(0) for match in ip_re.finditer(text)})


def get_ipv6_addresses() -> List[str]:
    addresses: List[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET6):
            addr = info[4][0]
            if addr not in addresses:
                addresses.append(addr)
    except Exception:
        return []
    return addresses


def check_local_port(host: str, port: int, timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def detect_proxy_env() -> Dict[str, str]:
    keys = ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"]
    found: Dict[str, str] = {}
    for key in keys:
        if key in os.environ:
            found[key] = os.environ[key]
    return found
