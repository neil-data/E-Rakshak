"""
backend/app/geoip.py — Offline GeoIP lookups on extracted IP indicators.

Uses MaxMind's GeoLite2-City database via the geoip2 library, kept fully
offline/local (no outbound API calls per lookup) — consistent with this
suite's air-gapped design goal. The database itself is not shipped in this
repo (MaxMind requires a free account + license key to download it); set
GEOIP_DB_PATH to wherever you've placed GeoLite2-City.mmdb and lookups
activate automatically. Left unset, `lookup()` simply returns None for
every IP — callers already treat a missing geo result as "no location
available" rather than an error, so this never blocks analysis.

To obtain the database:
  1. Create a free account at https://www.maxmind.com/en/geolite2/signup
  2. Generate a license key under Account -> My License Keys
  3. Download GeoLite2-City.mmdb (or use `geoipupdate` for automatic
     refreshes) and set GEOIP_DB_PATH to its path.

Optionally, download GeoLite2-ASN.mmdb as well and set GEOIP_ASN_DB_PATH
to its path. When both databases are available, every lookup also returns
the ASN + ISP/ASN organization for richer network attribution (this backs
the detailed Geo-IP section of the forensic PDF report).

The detailed Geo-IP report fields are all kept optional: any field that
cannot be resolved (no City DB, no ASN DB, a private/non-routable address,
or a database that doesn't cover the address) comes back as None and the
PDF renderer falls back to a Gujarati "not available" string — never an
error.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

_LOGGER = logging.getLogger(__name__)

_city_reader = None
_asn_reader = None
_load_attempted = False

try:
    import geoip2.database
    import geoip2.errors
except ImportError:  # pragma: no cover - package listed in requirements.txt, guarded for dev-without-install
    geoip2 = None  # type: ignore[assignment]


def _ensure_loaded() -> None:
    global _city_reader, _asn_reader, _load_attempted
    if _load_attempted:
        return
    _load_attempted = True

    if geoip2 is None:
        _LOGGER.info("geoip2 package not installed — GeoIP lookups disabled")
        return

    city_db_path = os.environ.get("GEOIP_DB_PATH")
    if city_db_path:
        if os.path.isfile(city_db_path):
            try:
                _city_reader = geoip2.database.Reader(city_db_path)
                _LOGGER.info("GeoIP City database loaded from %s", city_db_path)
            except Exception as error:
                _LOGGER.warning("Failed to open GeoIP City database at %s (%s) — GeoIP lookups disabled", city_db_path, error)
        else:
            _LOGGER.warning("GEOIP_DB_PATH=%s does not exist — GeoIP lookups disabled", city_db_path)
    else:
        _LOGGER.info("GEOIP_DB_PATH not set — GeoIP lookups disabled (see backend/app/geoip.py for setup steps)")

    asn_db_path = os.environ.get("GEOIP_ASN_DB_PATH")
    if asn_db_path:
        if os.path.isfile(asn_db_path):
            try:
                _asn_reader = geoip2.database.Reader(asn_db_path)
                _LOGGER.info("GeoIP ASN database loaded from %s", asn_db_path)
            except Exception as error:
                _LOGGER.warning("Failed to open GeoIP ASN database at %s (%s) — ASN lookups disabled", asn_db_path, error)
        else:
            _LOGGER.warning("GEOIP_ASN_DB_PATH=%s does not exist — ASN lookups disabled", asn_db_path)


def is_available() -> bool:
    _ensure_loaded()
    return _city_reader is not None


def _region_name(subdivisions) -> Optional[str]:
    """Best-effort region/state name from the city DB's subdivision list."""
    if subdivisions:
        try:
            return subdivisions[0].name
        except Exception:
            return None
    return None


# Hosting/cloud provider keywords used to derive `is_hosting` from the ASN
# organization name when an ASN database is configured. Not exhaustive, but
# covers the providers this platform most commonly sees in scam/Android
# banking-fraud samples. Everything stays a heuristic — the field is reported
# as a flag alongside raw ASN data, never as a certainty.
_HOSTING_KEYWORDS = (
    "amazon", "aws", "google", "cloudflare", "microsoft", "azure", "digitalocean",
    "ovh", "hetzner", "linode", "vultr", "akamai", "fastly", "oracle cloud",
    "alibaba", "tencent", "huawei", "contabo", "vps", "datacenter", "colocrossing",
    "hosting", "server", "idc", "colo",
)


def _is_hosting_org(org: Optional[str]) -> Optional[bool]:
    """True when the ASN org name smells like a hosting/cloud provider."""
    if not org:
        return None
    lowered = org.lower()
    return any(kw in lowered for kw in _HOSTING_KEYWORDS)


def _lookup_city(ip: str) -> Optional[dict]:
    """Resolve one IP to an approximate location, or None if unavailable/not found."""
    if _city_reader is None:
        return None

    try:
        response = _city_reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return None
    except (ValueError, geoip2.errors.GeoIP2Error):
        return None
    except Exception:
        _LOGGER.exception("Unexpected GeoIP lookup failure for %s", ip)
        return None

    country = response.country.name if response.country else None
    country_iso = response.country.iso_code if response.country else None
    city = response.city.name if response.city else None
    region = _region_name(response.subdivisions)
    postal = response.postal.code if response.postal else None
    timezone = response.location.time_zone if response.location else None
    accuracy_radius = response.location.accuracy_radius if response.location else None
    latitude = response.location.latitude if response.location else None
    longitude = response.location.longitude if response.location else None

    return {
        "ip": ip,
        "country": country,
        "country_iso": country_iso,
        "city": city,
        "region": region,
        "postal_code": postal,
        "timezone": timezone,
        "latitude": latitude,
        "longitude": longitude,
        "accuracy_radius": accuracy_radius,
        "asn": None,
        "asn_org": None,
        "isp": None,
        "is_hosting": None,
        "is_proxy": None,
        "threat_level": None,
    }


def _enrich_asn(record: dict) -> dict:
    """Attach ASN/ISP attribution to a city record when an ASN DB is available."""
    if _asn_reader is None:
        return record

    try:
        response = _asn_reader.asn(record["ip"])
        org = response.autonomous_system_organization or None
        record["asn"] = response.autonomous_system_number
        record["asn_org"] = org
        record["isp"] = org
        record["is_hosting"] = _is_hosting_org(org)
    except geoip2.errors.AddressNotFoundError:
        pass
    except (ValueError, geoip2.errors.GeoIP2Error):
        pass
    except Exception:
        _LOGGER.exception("Unexpected GeoIP ASN lookup failure for %s", record["ip"])
    return record


def lookup(ip: str) -> Optional[dict]:
    """Resolve one IP to detailed geolocation + ASN attribution, or None."""
    _ensure_loaded()
    record = _lookup_city(ip)
    if record is None:
        return None
    return _enrich_asn(record)


def lookup_many(ips: list[str]) -> list[dict]:
    """Resolve a list of IPs, silently skipping any that can't be resolved."""
    if not ips:
        return []
    results = []
    for ip in ips:
        result = lookup(ip)
        if result is not None:
            results.append(result)
    return results
