"""
TracePoint v2.0 — Hash / Dosya İstihbaratı
Desteklenen servisler:
  • VirusTotal
  • AlienVault OTX
  • CIRCL Hashlookup
  • MalwareBazaar (abuse.ch)
  • Hybrid Analysis
  • Triage (Hatching)
  • Polyswarm
  • Pulsedive
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
VT_API_KEY             = os.getenv("VT_API_KEY", "")
OTX_API_KEY            = os.getenv("OTX_API_KEY", "")
MALWAREBAZAAR_API_KEY  = os.getenv("MALWAREBAZAAR_API_KEY", "")
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "")
TRIAGE_API_KEY         = os.getenv("TRIAGE_API_KEY", "")
POLYSWARM_API_KEY      = os.getenv("POLYSWARM_API_KEY", "")
PULSEDIVE_API_KEY      = os.getenv("PULSEDIVE_API_KEY", "")

_TIMEOUT = 12.0


# ──────────────────────────────────────────────────────────────────
# Yardımcı: hash tipini belirle
# ──────────────────────────────────────────────────────────────────
def _hash_type(h: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h), "unknown")


# ──────────────────────────────────────────────────────────────────
# VirusTotal
# ──────────────────────────────────────────────────────────────────
async def query_virustotal(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {"source": "VirusTotal", "success": False, "error": "VT_API_KEY ayarlanmamış"}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
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
        logger.warning("VirusTotal hash sorgusu başarısız: %s", e)
        return {"source": "VirusTotal", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# AlienVault OTX
# ──────────────────────────────────────────────────────────────────
async def query_otx(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY} if OTX_API_KEY else {}
    try:
        resp = await client.get(url, headers=headers, timeout=_TIMEOUT)
        return {
            "source": "AlienVault OTX",
            "success": resp.status_code == 200,
            "data": resp.json() if resp.status_code == 200 else resp.text,
        }
    except Exception as e:
        logger.warning("OTX hash sorgusu başarısız: %s", e)
        return {"source": "AlienVault OTX", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# CIRCL Hashlookup
# ──────────────────────────────────────────────────────────────────
async def query_circl(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    ht = _hash_type(file_hash)
    if ht == "unknown":
        return {"source": "CIRCL Hashlookup", "success": False, "error": "Desteklenmeyen hash uzunluğu"}
    url = f"https://hashlookup.circl.lu/lookup/{ht}/{file_hash}"
    try:
        resp = await client.get(url, timeout=_TIMEOUT, follow_redirects=True)
        if resp.status_code == 404:
            return {"source": "CIRCL Hashlookup", "success": True, "data": {"message": "Not found"}}
        return {
            "source": "CIRCL Hashlookup",
            "success": resp.status_code == 200,
            "data": resp.json() if resp.status_code == 200 else resp.text,
        }
    except Exception as e:
        logger.warning("CIRCL Hashlookup sorgusu başarısız: %s", e)
        return {"source": "CIRCL Hashlookup", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# MalwareBazaar (abuse.ch)
# ──────────────────────────────────────────────────────────────────
async def query_malwarebazaar(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": file_hash}
    headers = {"Auth-Key": MALWAREBAZAAR_API_KEY} if MALWAREBAZAAR_API_KEY else {}
    try:
        resp = await client.post(url, data=data, headers=headers, timeout=_TIMEOUT, follow_redirects=True)
        if resp.status_code == 401:
            return {"source": "MalwareBazaar", "success": False, "error": "API Anahtarı Gerekli (401)"}
        return {
            "source": "MalwareBazaar",
            "success": resp.status_code == 200,
            "data": resp.json() if resp.status_code == 200 else resp.text,
        }
    except Exception as e:
        logger.warning("MalwareBazaar sorgusu başarısız: %s", e)
        return {"source": "MalwareBazaar", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Hybrid Analysis
# ──────────────────────────────────────────────────────────────────
async def query_hybrid_analysis(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    if not HYBRID_ANALYSIS_API_KEY:
        return {"source": "Hybrid Analysis", "success": False, "error": "HYBRID_ANALYSIS_API_KEY ayarlanmamış"}
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "accept": "application/json",
        "user-agent": "TracePoint-SOC/2.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "api-key": HYBRID_ANALYSIS_API_KEY,
    }
    try:
        resp = await client.post(url, data={"hash": file_hash}, headers=headers, timeout=_TIMEOUT, follow_redirects=True)
        if resp.status_code in (401, 403):
            return {"source": "Hybrid Analysis", "success": False, "error": f"Yetkilendirme Hatası ({resp.status_code})"}
        return {
            "source": "Hybrid Analysis",
            "success": resp.status_code == 200,
            "data": resp.json() if resp.status_code == 200 else resp.text,
        }
    except Exception as e:
        logger.warning("Hybrid Analysis sorgusu başarısız: %s", e)
        return {"source": "Hybrid Analysis", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Triage (Hatching) — Sandbox
# ──────────────────────────────────────────────────────────────────
async def query_triage(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    if not TRIAGE_API_KEY:
        return {"source": "Triage", "success": False, "error": "TRIAGE_API_KEY ayarlanmamış"}

    ht = _hash_type(file_hash)
    url = f"https://api.tria.ge/v0/search?query={ht}:{file_hash}&limit=5"
    headers = {"Authorization": f"Bearer {TRIAGE_API_KEY}"}
    try:
        resp = await client.get(url, headers=headers, timeout=_TIMEOUT)
        if resp.status_code == 401:
            return {"source": "Triage", "success": False, "error": "API Anahtarı Geçersiz (401)"}
        if resp.status_code == 200:
            data = resp.json()
            # Triage search döner: {"data": [...samples...]}
            samples = data.get("data", [])
            return {
                "source": "Triage",
                "success": True,
                "data": {
                    "sample_count": len(samples),
                    "samples": samples[:3],  # İlk 3 örnek
                },
            }
        return {"source": "Triage", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("Triage sorgusu başarısız: %s", e)
        return {"source": "Triage", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Polyswarm
# ──────────────────────────────────────────────────────────────────
async def query_polyswarm(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    if not POLYSWARM_API_KEY:
        return {"source": "Polyswarm", "success": False, "error": "POLYSWARM_API_KEY ayarlanmamış"}

    ht = _hash_type(file_hash)
    if ht not in ("sha256", "sha1", "md5"):
        return {"source": "Polyswarm", "success": False, "error": "Desteklenmeyen hash tipi"}

    url = f"https://api.polyswarm.network/v3/search/hash/{ht}?hash={file_hash}"
    headers = {"Authorization": POLYSWARM_API_KEY}
    try:
        resp = await client.get(url, headers=headers, timeout=_TIMEOUT)
        if resp.status_code in (401, 403):
            return {"source": "Polyswarm", "success": False, "error": f"Yetkilendirme Hatası ({resp.status_code})"}
        if resp.status_code == 200:
            return {"source": "Polyswarm", "success": True, "data": resp.json()}
        return {"source": "Polyswarm", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("Polyswarm sorgusu başarısız: %s", e)
        return {"source": "Polyswarm", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Pulsedive
# ──────────────────────────────────────────────────────────────────
async def query_pulsedive_hash(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    params = {"indicator": file_hash, "pretty": "1"}
    if PULSEDIVE_API_KEY:
        params["key"] = PULSEDIVE_API_KEY
    try:
        resp = await client.get("https://pulsedive.com/api/info.php", params=params, timeout=_TIMEOUT)
        if resp.status_code == 200:
            return {"source": "Pulsedive", "success": True, "data": resp.json()}
        return {"source": "Pulsedive", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("Pulsedive hash sorgusu başarısız: %s", e)
        return {"source": "Pulsedive", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Ana Analiz Fonksiyonu
# ──────────────────────────────────────────────────────────────────
async def analyze_hash(file_hash: str) -> Dict[str, Any]:
    """
    Tüm hash istihbarat servislerine eşzamanlı istek atar.
    Herhangi birinin başarısız olması diğerlerini etkilemez.
    """
    async with httpx.AsyncClient(follow_redirects=True) as client:
        results = await asyncio.gather(
            query_virustotal(client, file_hash),
            query_otx(client, file_hash),
            query_circl(client, file_hash),
            query_malwarebazaar(client, file_hash),
            query_hybrid_analysis(client, file_hash),
            query_triage(client, file_hash),
            query_polyswarm(client, file_hash),
            query_pulsedive_hash(client, file_hash),
            return_exceptions=True,
        )

    safe_results = []
    for r in results:
        if isinstance(r, Exception):
            safe_results.append({"source": "Bilinmeyen Kaynak", "success": False, "error": str(r)})
        else:
            safe_results.append(r)

    return {"hash": file_hash, "results": safe_results}
