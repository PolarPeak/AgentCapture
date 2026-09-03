"""
JSONP counter-reconnaissance service.

Extracts detailed browser/device fingerprints from attackers
via JSONP callbacks, including WebRTC local IP discovery to
reveal attacker's real IP behind proxies/VPNs.
"""

import hashlib
import json
from dataclasses import dataclass, field


@dataclass(slots=True)
class FingerprintResult:
    fingerprint_hash: str = ""
    webrtc_ips: list[str] = field(default_factory=list)
    canvas_hash: str = ""
    webgl_vendor: str = ""
    webgl_renderer: str = ""
    plugins: list[str] = field(default_factory=list)
    fonts: list[str] = field(default_factory=list)
    timezone: str = ""
    language: str = ""
    platform: str = ""
    cores: int = 0
    memory_gb: int = 0
    screen_width: int = 0
    screen_height: int = 0
    pixel_ratio: float = 1.0
    touch_points: int = 0
    webdriver: bool = False
    headless_hint: bool = False
    is_agent: bool = False


def compute_fingerprint_hash(data: dict) -> str:
    raw = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def sanitize_webrtc_ips(values: list[str] | None) -> tuple[list[str], list[str]]:
    """Keep only real IPv4/IPv6 addresses from collected WebRTC candidates.

    Modern Chrome/Safari replace host candidates with mDNS hostnames
    (``<uuid>.local``). Those are browser-noise, not IPs — the sanitized
    list is what detection/display should consume, while dropped entries
    (capped) double as an "mDNS obfuscation" environment signal.
    """
    import ipaddress

    clean: list[str] = []
    dropped: list[str] = []
    for value in values or []:
        raw = str(value or "").strip()
        if not raw:
            continue
        try:
            ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            dropped.append(raw[:64])
            continue
        if raw not in clean:
            clean.append(raw)
    return clean, dropped[:16]


def process_fingerprint(payload: dict) -> FingerprintResult:
    result = FingerprintResult(
        webrtc_ips=payload.get("webrtc_ips") or [],
        canvas_hash=payload.get("canvas_hash") or "",
        webgl_vendor=payload.get("webgl_vendor") or "",
        webgl_renderer=payload.get("webgl_renderer") or "",
        plugins=payload.get("plugins") or [],
        fonts=payload.get("fonts") or [],
        timezone=payload.get("timezone") or "",
        language=payload.get("language") or "",
        platform=payload.get("platform") or "",
        cores=payload.get("cores") or 0,
        memory_gb=payload.get("memory_gb") or 0,
        screen_width=payload.get("screen_width") or 0,
        screen_height=payload.get("screen_height") or 0,
        pixel_ratio=payload.get("pixel_ratio") or 1.0,
        touch_points=payload.get("touch_points") or 0,
        webdriver=payload.get("webdriver") or False,
        headless_hint=payload.get("headless_hint") or False,
    )
    result.is_agent = result.webdriver or result.headless_hint or bool(result.webrtc_ips)
    result.fingerprint_hash = compute_fingerprint_hash(payload)

    return result


def generate_jsonp_response(payload: dict, callback: str = "reconCallback") -> bytes:
    body = f""";{callback}({json.dumps(payload)});"""
    return body.encode("utf-8")


def analyze_threat_level(fp: FingerprintResult) -> dict:
    level = "low"
    indicators: list[str] = []

    if fp.headless_hint:
        level = "high"
        indicators.append("headless_browser")
    if fp.webdriver:
        level = "high"
        indicators.append("webdriver_flag")
    if fp.webrtc_ips:
        indicators.append("webrtc_ip_leaked")
    if not fp.fonts and not fp.plugins:
        level = "medium" if level == "low" else level
        indicators.append("minimal_fingerprint")

    return {"level": level, "indicators": indicators}
