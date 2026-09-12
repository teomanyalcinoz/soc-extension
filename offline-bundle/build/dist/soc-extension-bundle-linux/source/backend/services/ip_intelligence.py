import httpx
import asyncio
import os
from typing import Dict, Any

# Gelecekte eklenebilecek API anahtarları için opsiyonel çevresel değişkenler
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "bba747d1fdb03538935c609f3de2a5a2a3d2fd988f80446b6626e70b97ab34fa")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "41f396e23d4714280812f88398efb63e84bf82bc7c33da04f765518b45c2c9bd9a3ad9a2a146a994")

async def query_otx_ip(client: httpx.AsyncClient, ip_address: str) -> Dict[str, Any]:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
    try:
        response = await client.get(url, headers=headers, timeout=10.0, follow_redirects=True)
        if response.status_code == 404:
            return {"source": "AlienVault OTX", "success": True, "data": {"message": "Not found"}}
        return {"source": "AlienVault OTX", "success": response.status_code == 200, "data": response.json() if response.status_code == 200 else response.text}
    except Exception as e:
        return {"source": "AlienVault OTX", "success": False, "error": str(e)}

async def query_virustotal_ip(client: httpx.AsyncClient, ip_address: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}
    try:
        response = await client.get(url, headers=headers, timeout=10.0, follow_redirects=True)
        if response.status_code == 401:
            return {"source": "VirusTotal", "success": False, "error": "API Anahtarı Gerekli (Unauthorized)"}
        elif response.status_code == 404:
            return {"source": "VirusTotal", "success": True, "data": {"message": "Not found"}}
        return {"source": "VirusTotal", "success": response.status_code == 200, "data": response.json() if response.status_code == 200 else response.text}
    except Exception as e:
        return {"source": "VirusTotal", "success": False, "error": str(e)}

async def query_abuseipdb(client: httpx.AsyncClient, ip_address: str) -> Dict[str, Any]:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"} if ABUSEIPDB_API_KEY else {}
    params = {"ipAddress": ip_address, "maxAgeInDays": "90", "verbose": ""}
    try:
        response = await client.get(url, headers=headers, params=params, timeout=10.0, follow_redirects=True)
        if response.status_code == 401:
            return {"source": "AbuseIPDB", "success": False, "error": "API Anahtarı Gerekli (Unauthorized)"}
        return {"source": "AbuseIPDB", "success": response.status_code == 200, "data": response.json() if response.status_code == 200 else response.text}
    except Exception as e:
        return {"source": "AbuseIPDB", "success": False, "error": str(e)}

async def analyze_ip(ip_address: str) -> Dict[str, Any]:
    """
    Tüm IP istihbarat servislerine asenkron (eşzamanlı) istek atar.
    Böylece analist bekleme süresi tek bir servisin cevap süresine düşer.
    """
    async with httpx.AsyncClient() as client:
        # Aynı anda tüm kaynaklara istek at
        results = await asyncio.gather(
            query_otx_ip(client, ip_address),
            query_virustotal_ip(client, ip_address),
            query_abuseipdb(client, ip_address),
            return_exceptions=True
        )
        
    # Hata döndüren (Exception Raise eden) gathering durumlarını string'e çevir.
    safe_results = []
    for r in results:
        if isinstance(r, Exception):
            safe_results.append({"source": "Bilinmeyen Kaynak", "success": False, "error": str(r)})
        else:
            safe_results.append(r)

    return {
        "ip": ip_address,
        "results": safe_results
    }
