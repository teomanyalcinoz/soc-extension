import httpx
import asyncio
import os
from typing import Dict, Any

# Gelecekte eklenebilecek API anahtarları için opsiyonel çevresel değişkenler
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "5dad265712ca5a5b3677dca49c1bf4a64351f2b9ea334324")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "orb8m9gqfafeb869qxvcr6gv51ad82efw4zaudio3e768a3daqv1zt2i8ca37516")
VT_API_KEY = os.getenv("VT_API_KEY", "bba747d1fdb03538935c609f3de2a5a2a3d2fd988f80446b6626e70b97ab34fa")

async def query_malwarebazaar(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": file_hash}
    headers = {"Auth-Key": MALWAREBAZAAR_API_KEY} if MALWAREBAZAAR_API_KEY else {}
    try:
        response = await client.post(url, data=data, headers=headers, timeout=10.0, follow_redirects=True)
        if response.status_code == 401:
            return {"source": "MalwareBazaar", "success": False, "error": "API Anahtarı Gerekli (Unauthorized)"}
        return {"source": "MalwareBazaar", "success": response.status_code == 200, "data": response.json() if response.status_code == 200 else response.text}
    except Exception as e:
        return {"source": "MalwareBazaar", "success": False, "error": str(e)}

async def query_otx(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
    try:
        response = await client.get(url, headers=headers, timeout=10.0)
        return {"source": "AlienVault OTX", "success": response.status_code == 200, "data": response.json() if response.status_code == 200 else response.text}
    except Exception as e:
        return {"source": "AlienVault OTX", "success": False, "error": str(e)}

async def query_circl(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    # CIRCL API URL'i hash uzunluğuna göre karar vermek daha sağlıklıdır.
    hash_type = "sha256"
    if len(file_hash) == 32:
        hash_type = "md5"
    elif len(file_hash) == 40:
        hash_type = "sha1"
    
    url = f"https://hashlookup.circl.lu/lookup/{hash_type}/{file_hash}"
    try:
        response = await client.get(url, timeout=10.0, follow_redirects=True)
        # 404 CIRCL için "Kayıt bulunamadı", hata değildir
        if response.status_code == 404:
            return {"source": "CIRCL Hashlookup", "success": True, "data": {"message": "Not found"}}
        return {"source": "CIRCL Hashlookup", "success": response.status_code == 200, "data": response.json() if response.status_code == 200 else response.text}
    except Exception as e:
        return {"source": "CIRCL Hashlookup", "success": False, "error": str(e)}

async def query_hybrid_analysis(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    data = {"hash": file_hash}
    headers = {
        "accept": "application/json",
        "user-agent": "SOC Assistant",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    if HYBRID_ANALYSIS_API_KEY:
        headers["api-key"] = HYBRID_ANALYSIS_API_KEY
        
    try:
        response = await client.post(url, data=data, headers=headers, timeout=10.0, follow_redirects=True)
        if response.status_code in (401, 403):
            return {"source": "Hybrid Analysis", "success": False, "error": f"API Anahtarı Eksik veya Hatalı ({response.status_code})"}
        return {"source": "Hybrid Analysis", "success": response.status_code == 200, "data": response.json() if response.status_code == 200 else response.text}
    except Exception as e:
        return {"source": "Hybrid Analysis", "success": False, "error": str(e)}

async def query_virustotal(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}
    try:
        response = await client.get(url, headers=headers, timeout=10.0, follow_redirects=True)
        if response.status_code == 401:
            return {"source": "VirusTotal", "success": False, "error": "API Anahtarı Gerekli (Unauthorized)"}
        elif response.status_code == 404:
            return {"source": "VirusTotal", "success": True, "data": {"message": "Not found"}}
        return {"source": "VirusTotal", "success": response.status_code == 200, "data": response.json() if response.status_code == 200 else response.text}
    except Exception as e:
        return {"source": "Hybrid Analysis", "success": False, "error": str(e)}

async def analyze_hash(file_hash: str) -> Dict[str, Any]:
    """
    Tüm istihbarat servislerine asenkron (eşzamanlı) istek atar.
    Böylece analist bekleme süresi tek bir servisin cevap süresine düşer.
    """
    async with httpx.AsyncClient() as client:
        # Aynı anda tüm kaynaklara istek at
        results = await asyncio.gather(
            query_malwarebazaar(client, file_hash),
            query_otx(client, file_hash),
            query_circl(client, file_hash),
            query_hybrid_analysis(client, file_hash),
            query_virustotal(client, file_hash),
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
        "hash": file_hash,
        "results": safe_results
    }
