
import os
import base64
import ipaddress
from urllib.parse import urlparse

import requests
import whois


# =========================================================
# HELPERS
# =========================================================

def _target_type(target):
    target = target.strip()

    if target.startswith(("http://", "https://")):
        return "url"

    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def _clean_value(value):
    if value is None:
        return "Not available"

    if isinstance(value, (list, tuple, set)):
        values = []

        for item in value:
            if item is None:
                continue

            text = str(item).strip()

            if text and text not in values:
                values.append(text)

        return ", ".join(values) if values else "Not available"

    return str(value).strip() or "Not available"


def _clean_date(value):
    if value is None:
        return "Not available"

    if isinstance(value, (list, tuple)):
        if not value:
            return "Not available"
        value = value[0]

    try:
        return value.strftime("%d %B %Y")
    except Exception:
        return str(value)


def _domain_from_target(target):
    target = target.strip()

    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or ""

    return target.split("/")[0].split(":")[0].strip()


# =========================================================
# VIRUSTOTAL
# =========================================================

def get_virustotal(target):

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    if not api_key:
        return {
            "status": "error",
            "message": "VirusTotal API key is not configured."
        }

    target = target.strip()
    target_type = _target_type(target)

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:

        if target_type == "ip":

            endpoint = (
                "https://www.virustotal.com/api/v3/"
                f"ip_addresses/{target}"
            )

        elif target_type == "domain":

            endpoint = (
                "https://www.virustotal.com/api/v3/"
                f"domains/{target}"
            )

        else:

            url_id = base64.urlsafe_b64encode(
                target.encode()
            ).decode().rstrip("=")

            endpoint = (
                "https://www.virustotal.com/api/v3/"
                f"urls/{url_id}"
            )

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=20
        )

        if response.status_code == 401:
            return {
                "status": "error",
                "message": "VirusTotal rejected the API key."
            }

        if response.status_code == 404:
            return {
                "status": "error",
                "message": (
                    "VirusTotal has no report available "
                    "for this target."
                )
            }

        if response.status_code != 200:
            return {
                "status": "error",
                "message": (
                    f"VirusTotal request failed "
                    f"(HTTP {response.status_code})."
                )
            }

        payload = response.json()

        attributes = (
            payload
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        return {
            "status": "success",
            "target_type": target_type,
            "stats": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            },
            "reputation": attributes.get("reputation")
        }

    except requests.RequestException:
        return {
            "status": "error",
            "message": "Unable to connect to VirusTotal."
        }

    except Exception:
        return {
            "status": "error",
            "message": "VirusTotal data could not be processed."
        }


# =========================================================
# WHOIS
# =========================================================

def get_whois(target):

    try:

        domain = _domain_from_target(target)

        if not domain:
            return {
                "status": "error",
                "message": "No valid domain was found."
            }

        try:
            ipaddress.ip_address(domain)

            return {
                "status": "error",
                "message": (
                    "WHOIS domain registration data is "
                    "not applicable to IP address targets."
                )
            }

        except ValueError:
            pass

        if "." not in domain:
            return {
                "status": "error",
                "message": (
                    "WHOIS information is available "
                    "for domain-based targets."
                )
            }

        result = whois.whois(domain)

        return {
            "status": "success",
            "data": {
                "domain_name": _clean_value(
                    getattr(result, "domain_name", None)
                ),
                "registrar": _clean_value(
                    getattr(result, "registrar", None)
                ),
                "creation_date": _clean_date(
                    getattr(result, "creation_date", None)
                ),
                "expiration_date": _clean_date(
                    getattr(result, "expiration_date", None)
                ),
                "name_servers": _clean_value(
                    getattr(result, "name_servers", None)
                )
            }
        }

    except Exception:
        return {
            "status": "error",
            "message": "WHOIS information is unavailable."
        }


# =========================================================
# SOURCE REGISTRY
# =========================================================

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois
}
