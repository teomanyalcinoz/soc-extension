"""
TracePoint v2.5 — IP Adresi İstihbaratı
Desteklenen servisler:
  • VirusTotal
  • AlienVault OTX
  • AbuseIPDB
  • Shodan
  • GreyNoise
  • IPInfo.io
  • ipapi.co (geo/ASN — ücretsiz, key gerektirmez)
"""
import httpx
import asyncio
import os
import logging
from typing import Dict, Any

from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

logger = logging.getLogger(__name__)

# ── API Key'ler (.env üzerinden okunur) ───────────────────────────
VT_API_KEY         = os.getenv("VT_API_KEY", "")
OTX_API_KEY        = os.getenv("OTX_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
SHODAN_API_KEY     = os.getenv("SHODAN_API_KEY", "")
GREYNOISE_API_KEY  = os.getenv("GREYNOISE_API_KEY", "")
IPINFO_API_KEY     = os.getenv("IPINFO_API_KEY", "")

_TIMEOUT = 12.0


# ──────────────────────────────────────────────────────────────────
# VirusTotal — IP
# ──────────────────────────────────────────────────────────────────
async def query_virustotal_ip(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {"source": "VirusTotal", "success": False, "error": "VT_API_KEY ayarlanmamış"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = await client.get(url, headers=headers, timeout=_TIMEOUT, follow_redirects=True)
        if resp.status_code == 401:
            return {"source": "VirusTotal", "success": False, "error": "API Anahtarı Geçersiz (401)"}
        if resp.status_code == 404:
            return {"source": "VirusTotal", "success": True, "data": {"message": "Not found"}}
        return {
            "source": "VirusTotal",
            "success": resp.status_code == 200,
            "data": resp.json() if resp.status_code == 200 else resp.text,
        }
    except Exception as e:
        logger.warning("VirusTotal IP sorgusu başarısız: %s", e)
        return {"source": "VirusTotal", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# AlienVault OTX — IP
# ──────────────────────────────────────────────────────────────────
async def query_otx_ip(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
    try:
        resp = await client.get(url, headers=headers, timeout=_TIMEOUT, follow_redirects=True)
        if resp.status_code == 404:
            return {"source": "AlienVault OTX", "success": True, "data": {"message": "Not found"}}
        return {
            "source": "AlienVault OTX",
            "success": resp.status_code == 200,
            "data": resp.json() if resp.status_code == 200 else resp.text,
        }
    except Exception as e:
        logger.warning("OTX IP sorgusu başarısız: %s", e)
        return {"source": "AlienVault OTX", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# AbuseIPDB
# ──────────────────────────────────────────────────────────────────
async def query_abuseipdb(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    if not ABUSEIPDB_API_KEY:
        return {"source": "AbuseIPDB", "success": False, "error": "ABUSEIPDB_API_KEY ayarlanmamış"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
    try:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=_TIMEOUT,
            follow_redirects=True,
        )
        if resp.status_code == 401:
            return {"source": "AbuseIPDB", "success": False, "error": "API Anahtarı Geçersiz (401)"}
        return {
            "source": "AbuseIPDB",
            "success": resp.status_code == 200,
            "data": resp.json() if resp.status_code == 200 else resp.text,
        }
    except Exception as e:
        logger.warning("AbuseIPDB sorgusu başarısız: %s", e)
        return {"source": "AbuseIPDB", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Shodan
# ──────────────────────────────────────────────────────────────────
async def query_shodan(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    if not SHODAN_API_KEY:
        return {"source": "Shodan", "success": False, "error": "SHODAN_API_KEY ayarlanmamış"}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    try:
        resp = await client.get(url, timeout=_TIMEOUT)
        if resp.status_code == 401:
            return {"source": "Shodan", "success": False, "error": "API Anahtarı Geçersiz (401)"}
        if resp.status_code == 404:
            return {"source": "Shodan", "success": True, "data": {"message": "No information available"}}
        if resp.status_code == 200:
            data = resp.json()
            # Önemli alanları öne çıkar
            return {
                "source": "Shodan",
                "success": True,
                "data": {
                    "ip": data.get("ip_str"),
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "country": data.get("country_name"),
                    "city": data.get("city"),
                    "open_ports": data.get("ports", []),
                    "vulns": list(data.get("vulns", {}).keys())[:10],
                    "os": data.get("os"),
                    "hostnames": data.get("hostnames", [])[:5],
                    "tags": data.get("tags", []),
                },
            }
        return {"source": "Shodan", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("Shodan sorgusu başarısız: %s", e)
        return {"source": "Shodan", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# GreyNoise — Noise & Context API
# ──────────────────────────────────────────────────────────────────
async def query_greynoise(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    # Community API (ücretsiz), Enterprise key varsa v2 context kullanılır
    if GREYNOISE_API_KEY:
        url = f"https://api.greynoise.io/v2/noise/context/{ip}"
        headers = {"key": GREYNOISE_API_KEY, "Accept": "application/json"}
    else:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"Accept": "application/json"}
    try:
        resp = await client.get(url, headers=headers, timeout=_TIMEOUT)
        if resp.status_code == 404:
            return {"source": "GreyNoise", "success": True, "data": {"message": "IP not observed by GreyNoise", "noise": False}}
        if resp.status_code in (401, 403):
            return {"source": "GreyNoise", "success": False, "error": f"Yetkilendirme Hatası ({resp.status_code})"}
        if resp.status_code == 200:
            return {"source": "GreyNoise", "success": True, "data": resp.json()}
        return {"source": "GreyNoise", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("GreyNoise sorgusu başarısız: %s", e)
        return {"source": "GreyNoise", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# IPInfo.io — Geo + ASN
# ──────────────────────────────────────────────────────────────────
async def query_ipinfo(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    url = f"https://ipinfo.io/{ip}/json"
    params = {}
    if IPINFO_API_KEY:
        params["token"] = IPINFO_API_KEY
    try:
        resp = await client.get(url, params=params, timeout=_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "source": "IPInfo.io",
                "success": True,
                "data": {
                    "ip": data.get("ip"),
                    "hostname": data.get("hostname"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "org": data.get("org"),
                    "asn": data.get("asn", {}).get("asn") if isinstance(data.get("asn"), dict) else None,
                    "loc": data.get("loc"),
                    "timezone": data.get("timezone"),
                },
            }
        return {"source": "IPInfo.io", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("IPInfo sorgusu başarısız: %s", e)
        return {"source": "IPInfo.io", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# ipapi.co — Geo / ASN (ücretsiz, key gerektirmez)
# ──────────────────────────────────────────────────────────────────
async def query_ipapi(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    url = f"https://ipapi.co/{ip}/json/"
    headers = {"User-Agent": "TracePoint-SOC/2.5"}
    try:
        resp = await client.get(url, headers=headers, timeout=_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("error"):
                return {"source": "ipapi.co", "success": False, "error": data.get("reason", "Bilinmeyen hata")}
            return {
                "source": "ipapi.co",
                "success": True,
                "data": {
                    "ip": data.get("ip"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country_name": data.get("country_name"),
                    "org": data.get("org"),
                    "asn": data.get("asn"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "timezone": data.get("timezone"),
                },
            }
        return {"source": "ipapi.co", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("ipapi.co sorgusu başarısız: %s", e)
        return {"source": "ipapi.co", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Ana Analiz Fonksiyonu
# ──────────────────────────────────────────────────────────────────
async def analyze_ip(ip_address: str) -> Dict[str, Any]:
    """
    Tüm IP istihbarat servislerine eşzamanlı istek atar.
    Herhangi birinin başarısız olması diğerlerini etkilemez.
    """
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            query_virustotal_ip(client, ip_address),
            query_otx_ip(client, ip_address),
            query_abuseipdb(client, ip_address),
            query_shodan(client, ip_address),
            query_greynoise(client, ip_address),
            query_ipinfo(client, ip_address),
            query_ipapi(client, ip_address),
            return_exceptions=True,
        )

    safe_results = []
    for r in results:
        if isinstance(r, Exception):
            safe_results.append({"source": "Bilinmeyen Kaynak", "success": False, "error": str(r)})
        else:
            safe_results.append(r)

    return {"ip": ip_address, "results": safe_results}
