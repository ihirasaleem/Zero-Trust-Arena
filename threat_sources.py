"""ThreatLens data sources: input validation, VirusTotal, WHOIS and the source registry.

This module never imports from app.py. To add a new source, write ONE function
decorated with @register_source("Name"); nothing else needs to change.

Every source function has the signature ``(value, ioc_type) -> dict`` and returns:
    {
      "status":   "ok" | "not_found" | "unsupported" | "error",
      "findings": {...},        # normalized data for display and for the AI prompt
      "error":    str | None,   # user-safe message
      "signals":  [ {"severity": "high|medium|low|info|positive",
                     "text": str, "points": int}, ... ],  # feeds the verdict
    }
"""
from __future__ import annotations

import base64
import ipaddress
import os
import re
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable
from urllib.parse import quote, urlsplit

import requests

IP, DOMAIN, URL = "IP address", "Domain", "URL"
IOC_TYPES = (IP, DOMAIN, URL)

REQUEST_TIMEOUT = (5, 15)  # (connect, read) seconds
SOURCES: dict[str, Callable[[str, str], dict]] = {}


# --------------------------------------------------------------------------- #
# Registry and shared helpers
# --------------------------------------------------------------------------- #
def make_result(status: str, findings: dict | None = None, error: str | None = None,
                signals: list | None = None) -> dict:
    return {"status": status, "findings": findings or {}, "error": error,
            "signals": signals or []}


def signal(severity: str, text: str, points: int = 0) -> dict:
    return {"severity": severity, "text": text, "points": points}


def register_source(name: str):
    """Decorator: register a source function in SOURCES and guarantee a consistent result."""
    def decorator(func):
        @wraps(func)
        def wrapper(value: str, ioc_type: str) -> dict:
            try:
                res = func(value, ioc_type)
            except Exception:  # never let one source break the others
                return make_result("error", error=f"{name} failed unexpectedly.")
            if not isinstance(res, dict) or "status" not in res:
                return make_result("error", error=f"{name} returned an invalid result.")
            res.setdefault("findings", {})
            res.setdefault("error", None)
            res.setdefault("signals", [])
            return res
        SOURCES[name] = wrapper
        return wrapper
    return decorator


def get_secret(name: str) -> str | None:
    """Read a key from environment variables, then Streamlit secrets. Never logged or shown."""
    val = os.environ.get(name)
    if val and val.strip():
        return val.strip()
    try:
        import streamlit as st
        val = st.secrets.get(name)
        return str(val).strip() if val else None
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")


def _to_ascii_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    labels = domain.split(".")
    return all(_LABEL_RE.match(l) for l in labels) and bool(_TLD_RE.match(labels[-1]))


def _parse_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def normalize_ioc(value: str, ioc_type: str) -> str:
    """Trim input and apply light, type-specific normalization."""
    value = (value or "").strip()
    if ioc_type == DOMAIN:
        return _to_ascii_host(value)
    return value


def detect_ioc_type(value: str) -> str | None:
    """Return IP, DOMAIN, URL, or None if the value looks like none of them."""
    v = (value or "").strip()
    if not v:
        return None
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", v):
        return URL
    if _parse_ip(v):
        return IP
    if any(c in v for c in "/?#"):
        return URL
    return DOMAIN if _valid_domain(_to_ascii_host(v)) else None


def is_valid_ioc(value: str, ioc_type: str) -> tuple[bool, str]:
    """Validate a (normalized) value against the selected type. Returns (ok, message)."""
    v = (value or "").strip()
    if not v:
        return False, "Please enter a value to analyze."

    if ioc_type == IP:
        ip = _parse_ip(v)
        if ip is None:
            return False, "That is not a valid IPv4 or IPv6 address (example: 8.8.8.8)."
        if not ip.is_global:
            return False, "Private, loopback and reserved addresses cannot be looked up. Enter a public IP."
        return True, ""

    if ioc_type == DOMAIN:
        if "://" in v or "/" in v or " " in v:
            return False, "Enter only a domain name such as example.com (no http:// and no path)."
        if _parse_ip(v):
            return False, "That is an IP address. Switch the type to 'IP address'."
        if not _valid_domain(_to_ascii_host(v)):
            return False, "That is not a valid domain name (example: example.com)."
        return True, ""

    if ioc_type == URL:
        if len(v) > 2048 or re.search(r"[\s\x00-\x1f]", v):
            return False, "That is not a valid URL (too long, or contains spaces/control characters)."
        try:
            parts = urlsplit(v)
            host = parts.hostname
            _ = parts.port  # raises ValueError if the port is invalid
        except ValueError:
            return False, "That is not a valid URL (check the host and port)."
        if parts.scheme.lower() not in ("http", "https"):
            return False, "A URL must start with http:// or https:// (example: https://example.com/path)."
        if not host:
            return False, "The URL has no hostname."
        ip = _parse_ip(host)
        if ip is not None:
            if not ip.is_global:
                return False, "The URL points to a private or reserved IP address."
            return True, ""
        if not _valid_domain(_to_ascii_host(host)):
            return False, "The URL's hostname is not a valid domain name."
        return True, ""

    return False, "Unknown indicator type."


def extract_domain(value: str) -> tuple[str | None, str]:
    """Return (domain, note). domain is None when WHOIS domain lookup is not applicable."""
    v = (value or "").strip()
    if not v:
        return None, "No value provided."
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", v):
        try:
            host = urlsplit(v).hostname
        except ValueError:
            host = None
    elif _parse_ip(v):
        return None, "The target is an IP address; domain WHOIS is not applicable."
    else:
        host = v.split("/")[0]
    if not host:
        return None, "Could not extract a hostname."
    if _parse_ip(host):
        return None, "The URL's host is an IP address; domain WHOIS is not applicable."
    host = _to_ascii_host(host)
    if not _valid_domain(host):
        return None, "Could not extract a valid domain name."
    return host, "ok"


# --------------------------------------------------------------------------- #
# VirusTotal
# --------------------------------------------------------------------------- #
_VT_BASE = "https://www.virustotal.com/api/v3"


def _fmt_ts(ts: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


@register_source("VirusTotal")
def get_virustotal(value: str, ioc_type: str) -> dict:
    key = get_secret("VIRUSTOTAL_API_KEY")
    if not key:
        return make_result("error", error="VirusTotal API key is not configured (set VIRUSTOTAL_API_KEY).")

    if ioc_type == IP:
        path = f"ip_addresses/{quote(value, safe=':')}"
    elif ioc_type == DOMAIN:
        path = f"domains/{quote(value, safe='')}"
    elif ioc_type == URL:
        url_id = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
        path = f"urls/{url_id}"
    else:
        return make_result("error", error="Unsupported indicator type.")

    # Only a GET against VirusTotal's API; the submitted URL itself is never fetched or scanned by us.
    try:
        resp = requests.get(f"{_VT_BASE}/{path}", headers={"x-apikey": key, "accept": "application/json"},
                            timeout=REQUEST_TIMEOUT)
    except requests.Timeout:
        return make_result("error", error="VirusTotal did not respond in time. Try again shortly.")
    except requests.RequestException:
        return make_result("error", error="Could not reach VirusTotal (network error).")

    if resp.status_code == 404:
        return make_result("not_found", error="VirusTotal has no record of this indicator.",
                           signals=[signal("info", "VirusTotal has no existing analysis for this indicator.")])
    if resp.status_code == 429:
        return make_result("error", error="VirusTotal rate limit reached. Wait a minute and try again.")
    if resp.status_code in (401, 403):
        return make_result("error", error="VirusTotal rejected the API key (invalid or lacking permission).")
    if resp.status_code != 200:
        return make_result("error", error=f"VirusTotal returned HTTP {resp.status_code}.")

    try:
        attrs = resp.json()["data"]["attributes"]
    except (ValueError, KeyError, TypeError):
        return make_result("error", error="VirusTotal returned an unexpected response.")

    stats = attrs.get("last_analysis_stats") or {}
    mal, sus = _int(stats.get("malicious")), _int(stats.get("suspicious"))
    harm, und = _int(stats.get("harmless")), _int(stats.get("undetected"))
    total = mal + sus + harm + und

    flagged = []
    for engine, r in (attrs.get("last_analysis_results") or {}).items():
        if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious"):
            flagged.append(f"{engine}: {r.get('result') or r['category']}")

    findings: dict[str, Any] = {
        "detections": {"malicious": mal, "suspicious": sus, "harmless": harm,
                       "undetected": und, "timeout": _int(stats.get("timeout")),
                       "engines_with_verdict": total},
        "flagged_by": sorted(flagged)[:15],
        "reputation": attrs.get("reputation"),
        "community_votes": attrs.get("total_votes"),
        "last_analysis_date": _fmt_ts(attrs.get("last_analysis_date")),
        "categories": sorted({str(c) for c in (attrs.get("categories") or {}).values()})[:10],
        "tags": [str(t) for t in (attrs.get("tags") or [])][:15],
        "threat_names": [str(t) for t in (attrs.get("threat_names") or [])][:10],
    }
    if ioc_type == IP:
        findings.update({"owner": attrs.get("as_owner"), "asn": attrs.get("asn"),
                         "country": attrs.get("country"), "network": attrs.get("network")})
    elif ioc_type == DOMAIN:
        findings.update({"registrar": attrs.get("registrar"), "tld": attrs.get("tld"),
                         "creation_date": _fmt_ts(attrs.get("creation_date"))})
    else:
        findings.update({"title": attrs.get("title"), "final_url": attrs.get("last_final_url"),
                         "times_submitted": attrs.get("times_submitted"),
                         "first_submission": _fmt_ts(attrs.get("first_submission_date"))})

    signals = []
    if not stats or total == 0:
        signals.append(signal("info", "VirusTotal returned no engine results for this indicator."))
    else:
        if mal >= 3:
            signals.append(signal("high", f"{mal} security engines flagged it as malicious.", 5))
        elif mal >= 1:
            signals.append(signal("medium", f"{mal} security engine(s) flagged it as malicious.", 3))
        if sus >= 1:
            signals.append(signal("low", f"{sus} engine(s) flagged it as suspicious.", 2))
        if isinstance(attrs.get("reputation"), int) and attrs["reputation"] < 0:
            signals.append(signal("low", f"Negative community reputation score ({attrs['reputation']}).", 1))
        if mal == 0 and sus == 0 and total >= 10:
            signals.append(signal("positive",
                                  f"0 of {total} engines flagged it (this is not proof of safety)."))
        elif mal == 0 and sus == 0:
            signals.append(signal("info", f"Only {total} engines returned a verdict; too few to rely on."))
    return make_result("ok", findings, signals=signals)


# --------------------------------------------------------------------------- #
# WHOIS
# --------------------------------------------------------------------------- #
def _as_list(v: Any) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def _dates(v: Any) -> list[datetime]:
    out = []
    for item in _as_list(v):
        if isinstance(item, datetime):
            out.append(item if item.tzinfo else item.replace(tzinfo=timezone.utc))
    return sorted(out)


def _fmt_dt(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d") if dt else None


def _text(v: Any) -> str | None:
    for item in _as_list(v):
        if item is not None and str(item).strip():
            return str(item).strip()
    return None


@register_source("WHOIS")
def get_whois(value: str, ioc_type: str) -> dict:
    if ioc_type == IP:
        return make_result("unsupported", error="WHOIS here covers domains only; IP address ownership "
                                                 "lookups are not supported. See VirusTotal's network owner data.")
    domain, note = extract_domain(value)
    if not domain:
        return make_result("unsupported", error=note)

    try:
        import whois  # python-whois
    except ImportError:
        return make_result("error", error="The python-whois package is not installed.")

    try:
        record = whois.whois(domain, timeout=10)
    except Exception as exc:
        msg = str(exc).lower()
        if "no match" in msg or "not found" in msg or "no whois" in msg:
            return make_result("not_found", error="No WHOIS record was found for this domain.",
                               findings={"queried_domain": domain})
        return make_result("error", error="The WHOIS lookup failed or timed out.")

    data = dict(record) if record else {}
    created, expires = _dates(data.get("creation_date")), _dates(data.get("expiration_date"))
    updated = _dates(data.get("updated_date"))
    if not (data.get("domain_name") or data.get("registrar") or created):
        return make_result("not_found", error="WHOIS data is unavailable for this domain.",
                           findings={"queried_domain": domain})

    now = datetime.now(timezone.utc)
    creation = created[0] if created else None
    expiry = expires[0] if expires else None
    age_days = (now - creation).days if creation else None

    findings = {
        "queried_domain": domain,
        "registrar": _text(data.get("registrar")),
        "organization": _text(data.get("org")),
        "country": _text(data.get("country")),
        "creation_date": _fmt_dt(creation),
        "expiration_date": _fmt_dt(expiry),
        "last_updated": _fmt_dt(updated[-1] if updated else None),
        "domain_age_days": age_days,
        "name_servers": sorted({str(n).lower() for n in _as_list(data.get("name_servers"))})[:10],
        "status": [str(s).split()[0] for s in _as_list(data.get("status"))][:6],
        "dnssec": _text(data.get("dnssec")),
    }

    signals = []
    if age_days is None:
        signals.append(signal("info", "Domain creation date is not available in WHOIS."))
    elif age_days < 30:
        signals.append(signal("medium", f"Domain was registered only {max(age_days, 0)} days ago "
                                        "(new domains are often abused, but many are legitimate).", 2))
    elif age_days < 180:
        signals.append(signal("low", f"Domain is fairly new ({age_days} days old).", 1))
    else:
        signals.append(signal("info", f"Domain has been registered for about {age_days // 365} year(s) "
                                      f"({age_days} days)."))
    if expiry and expiry < now:
        signals.append(signal("low", "The WHOIS expiration date has already passed.", 1))
    return make_result("ok", findings, signals=signals)
