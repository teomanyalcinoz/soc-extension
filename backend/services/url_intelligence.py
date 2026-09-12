"""
TracePoint v2.0 — URL / Domain İstihbaratı
Desteklenen servisler:
  • VirusTotal
  • URLhaus (abuse.ch)
  • Sucuri SiteCheck
  • URLScan.io
  • USOM (Türkiye)
  • PhishTank
  • Pulsedive
"""
import httpx
import asyncio
import base64
import os
import logging
from typing import Dict, Any
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

logger = logging.getLogger(__name__)

# ── API Key'ler (.env üzerinden okunur) ───────────────────────────
VT_API_KEY            = os.getenv("VT_API_KEY", "")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "")
URLSCAN_API_KEY       = os.getenv("URLSCAN_API_KEY", "")
PULSEDIVE_API_KEY     = os.getenv("PULSEDIVE_API_KEY", "")

# SSL doğrulaması .env'den okunur (iç ağ sertifikası yoksa False)
_VERIFY_SSL: bool = os.getenv("URL_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
_TIMEOUT = 15.0


def _extract_domain(url: str) -> str:
    """URL veya domain string'inden domain kısmını çıkarır."""
    raw = url if url.startswith("http") else f"http://{url}"
    return urlparse(raw).netloc.split(":")[0]


# ──────────────────────────────────────────────────────────────────
# VirusTotal — URL
# ──────────────────────────────────────────────────────────────────
async def check_virustotal_url(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {"source": "VirusTotal", "success": False, "error": "VT_API_KEY ayarlanmamış"}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}
        resp = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            return {"source": "VirusTotal", "success": True, "data": resp.json()}
        if resp.status_code == 404:
            return {"source": "VirusTotal", "success": True, "data": {"message": "Not found"}}
        return {"source": "VirusTotal", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("VirusTotal URL sorgusu başarısız: %s", e)
        return {"source": "VirusTotal", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# URLhaus (abuse.ch)
# ──────────────────────────────────────────────────────────────────
async def check_urlhaus(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    headers = {"Auth-Key": MALWAREBAZAAR_API_KEY} if MALWAREBAZAAR_API_KEY else {}
    try:
        resp = await client.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers=headers,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            return {"source": "URLhaus", "success": True, "data": resp.json()}
        return {"source": "URLhaus", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("URLhaus sorgusu başarısız: %s", e)
        return {"source": "URLhaus", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Sucuri SiteCheck
# ──────────────────────────────────────────────────────────────────
async def check_sucuri(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    try:
        resp = await client.get(
            f"https://sitecheck.sucuri.net/api/v3/?scan={url}",
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            return {"source": "Sucuri SiteCheck", "success": True, "data": resp.json()}
        return {"source": "Sucuri SiteCheck", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("Sucuri sorgusu başarısız: %s", e)
        return {"source": "Sucuri SiteCheck", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# URLScan.io — Search (geçmiş tarama sonuçları)
# ──────────────────────────────────────────────────────────────────
async def check_urlscan(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    domain = _extract_domain(url)
    headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else {}
    try:
        resp = await client.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
            headers=headers,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            return {"source": "urlscan.io", "success": True, "data": resp.json()}
        return {"source": "urlscan.io", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("URLScan sorgusu başarısız: %s", e)
        return {"source": "urlscan.io", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# USOM (Türkiye Ulusal Siber Olaylara Müdahale Merkezi)
# ──────────────────────────────────────────────────────────────────
async def check_usom(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    domain = _extract_domain(url)
    try:
        resp = await client.get(
            f"https://www.usom.gov.tr/api/address/index?q={domain}",
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            return {"source": "USOM", "success": True, "data": resp.json()}
        return {"source": "USOM", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("USOM sorgusu başarısız: %s", e)
        return {"source": "USOM", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# PhishTank
# ──────────────────────────────────────────────────────────────────
async def check_phishtank(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    """
    PhishTank URL kontrol API'si.
    Ücretsiz ve API key gerektirmez (key olursa rate limit artar).
    """
    try:
        resp = await client.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json"},
            headers={"User-Agent": "TracePoint-SOC/2.0"},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", {})
            return {
                "source": "PhishTank",
                "success": True,
                "data": {
                    "in_database": results.get("in_database", False),
                    "phish_detail_page": results.get("phish_detail_page"),
                    "valid": results.get("valid", False),
                    "verified": results.get("verified", False),
                },
            }
        return {"source": "PhishTank", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("PhishTank sorgusu başarısız: %s", e)
        return {"source": "PhishTank", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Pulsedive — URL / Domain
# ──────────────────────────────────────────────────────────────────
async def check_pulsedive_url(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    params = {"indicator": url, "pretty": "1"}
    if PULSEDIVE_API_KEY:
        params["key"] = PULSEDIVE_API_KEY
    try:
        resp = await client.get("https://pulsedive.com/api/info.php", params=params, timeout=_TIMEOUT)
        if resp.status_code == 200:
            return {"source": "Pulsedive", "success": True, "data": resp.json()}
        return {"source": "Pulsedive", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("Pulsedive URL sorgusu başarısız: %s", e)
        return {"source": "Pulsedive", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Ana Analiz Fonksiyonu
# ──────────────────────────────────────────────────────────────────
async def analyze_url(url: str) -> Dict[str, Any]:
    """
    Tüm URL istihbarat servislerine eşzamanlı istek atar.
    SSL doğrulaması .env URL_VERIFY_SSL parametresiyle kontrol edilir.
    """
    async with httpx.AsyncClient(verify=_VERIFY_SSL) as client:
        tasks = [
            check_virustotal_url(url, client),
            check_urlhaus(url, client),
            check_sucuri(url, client),
            check_urlscan(url, client),
            check_usom(url, client),
            check_phishtank(url, client),
            check_pulsedive_url(url, client),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    valid_results = []
    for r in results:
        if isinstance(r, Exception):
            valid_results.append({"success": False, "source": "Bilinmeyen Kaynak", "error": str(r)})
        elif isinstance(r, dict):
            valid_results.append(r)
        else:
            valid_results.append({"success": False, "source": "Unknown", "error": "Bilinmeyen yanıt tipi"})

    return {"target": url, "type": "url", "results": valid_results}
