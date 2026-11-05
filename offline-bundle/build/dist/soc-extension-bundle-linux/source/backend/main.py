"""
TracePoint v2.5 — Ana API Sunucusu (FastAPI)
"""
import re
import time
import asyncio
import hashlib
import logging
import urllib.parse
from typing import List, Any

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Servis Import'ları ─────────────────────────────────────────────
from services.intelligence import analyze_hash
from services.ip_intelligence import analyze_ip
from services.url_intelligence import analyze_url
from services.email_intelligence import analyze_email_all
from services.ai_summary import generate_summary
from services.powershell_intelligence import analyze_powershell_with_ai
from services.spl_intelligence import generate_spl_queries
from services.splunk_executor import execute_spl_query
from services.report_scanner import analyze_report_text
from services.xdr_executor import execute_xdr_query
from services.domain_intelligence import analyze_domain

# ══════════════════════════════════════════════════════════════════
# Logging Yapılandırması
# ══════════════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("tracepoint")

# ══════════════════════════════════════════════════════════════════
# FastAPI Uygulaması
# ══════════════════════════════════════════════════════════════════
app = FastAPI(
    title="TracePoint SOC Assistant API v2.5",
    description="Siber Güvenlik Tehdit İstihbaratı, IOC Analizi, Splunk & XDR Entegrasyonu",
    version="2.5.0",
)

# ── CORS ───────────────────────────────────────────────────────────
# İç ağ ortamı: Chrome Extension origin'lerine izin ver.
# allow_credentials=False olmalı (chrome-extension:// ile credential gerektirmiyor).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # İç ağ; production'da "chrome-extension://<ID>" ile kısıtlayın
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ══════════════════════════════════════════════════════════════════
# Asyncio-Safe In-Memory Cache (TTL: 5 dakika)
# ══════════════════════════════════════════════════════════════════
_CACHE: dict = {}
_CACHE_TTL: int = 300  # saniye
_cache_lock = asyncio.Lock()


async def get_from_cache(key: str):
    async with _cache_lock:
        entry = _CACHE.get(key)
        if entry and (time.time() - entry["timestamp"]) < _CACHE_TTL:
            logger.debug("Cache HIT: %s", key)
            return entry["data"]
        if entry:
            del _CACHE[key]
    return None


async def set_to_cache(key: str, data: dict):
    async with _cache_lock:
        _CACHE[key] = {"data": data, "timestamp": time.time()}
        logger.debug("Cache SET: %s", key)


# ══════════════════════════════════════════════════════════════════
# HASH ANALİZİ
# ══════════════════════════════════════════════════════════════════
@app.get("/api/analyze/hash/{file_hash}")
async def analyze_hash_endpoint(file_hash: str):
    """
    MD5 (32), SHA1 (40) veya SHA256 (64) hash'i çoklu OSINT + sandbox servislerinde sorgular.
    Servisler: VirusTotal, OTX, CIRCL, MalwareBazaar, Hybrid Analysis, Triage, Polyswarm, Pulsedive
    """
    if not file_hash or len(file_hash) not in (32, 40, 64):
        raise HTTPException(status_code=400, detail="Geçersiz hash formatı. MD5 (32), SHA1 (40) veya SHA256 (64) bekleniyor.")

    cache_key = f"hash_{file_hash}"
    cached = await get_from_cache(cache_key)
    if cached:
        return cached

    logger.info("Hash analizi başladı: %s", file_hash)
    results = await analyze_hash(file_hash)
    results["ai_summary"] = await generate_summary(file_hash, "Hash Dosyası", results.get("results", []))

    await set_to_cache(cache_key, results)
    return results


# ══════════════════════════════════════════════════════════════════
# IP ANALİZİ
# ══════════════════════════════════════════════════════════════════
@app.get("/api/analyze/ip/{ip_address}")
async def analyze_ip_endpoint(ip_address: str):
    """
    IPv4 adresini çoklu OSINT + network istihbarat servislerinde sorgular.
    Servisler: VirusTotal, OTX, AbuseIPDB, Shodan, GreyNoise, IPInfo.io, ipapi.co
    """
    ip_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if not ip_address or not re.match(ip_regex, ip_address):
        raise HTTPException(status_code=400, detail="Geçersiz IPv4 formatı.")

    cache_key = f"ip_{ip_address}"
    cached = await get_from_cache(cache_key)
    if cached:
        return cached

    logger.info("IP analizi başladı: %s", ip_address)
    results = await analyze_ip(ip_address)
    results["ai_summary"] = await generate_summary(ip_address, "IPv4 Adresi", results.get("results", []))

    await set_to_cache(cache_key, results)
    return results


# ══════════════════════════════════════════════════════════════════
# URL / DOMAIN ANALİZİ
# ══════════════════════════════════════════════════════════════════
@app.get("/api/analyze/url/{url:path}")
async def analyze_url_endpoint(url: str):
    """
    URL/Domain'i güvenlik servislerinde taratır.
    Servisler: VirusTotal, URLhaus, Sucuri, URLScan.io, USOM, PhishTank, Pulsedive
    """
    url = urllib.parse.unquote(url)
    if not url or len(url) < 4:
        raise HTTPException(status_code=400, detail="Geçersiz URL formatı.")

    cache_key = f"url_{url}"
    cached = await get_from_cache(cache_key)
    if cached:
        return cached

    logger.info("URL analizi başladı: %s", url[:80])
    results = await analyze_url(url)
    results["ai_summary"] = await generate_summary(url, "URL / Web Adresi", results.get("results", []))

    await set_to_cache(cache_key, results)
    return results


# ══════════════════════════════════════════════════════════════════
# DOMAIN ALTYAPI ANALİZİ (YENİ - v2.0)
# ══════════════════════════════════════════════════════════════════
@app.get("/api/analyze/domain/{domain:path}")
async def analyze_domain_endpoint(domain: str):
    """
    Domain altyapısını derinlemesine analiz eder.
    Servisler: SecurityTrails (DNS geçmişi/subdomain), crt.sh (SSL sertifikaları),
               RDAP (WHOIS), IntelX (dark/clearweb arama)
    """
    domain = urllib.parse.unquote(domain).strip().lower()
    # Şema varsa temizle
    domain = re.sub(r"^https?://", "", domain).split("/")[0]

    if not domain or len(domain) < 3 or "." not in domain:
        raise HTTPException(status_code=400, detail="Geçersiz domain formatı. Örnek: example.com")

    cache_key = f"domain_{domain}"
    cached = await get_from_cache(cache_key)
    if cached:
        return cached

    logger.info("Domain altyapı analizi başladı: %s", domain)
    results = await analyze_domain(domain)
    results["ai_summary"] = await generate_summary(domain, "Domain / Altyapı", results.get("results", []))

    await set_to_cache(cache_key, results)
    return results


# ══════════════════════════════════════════════════════════════════
# E-POSTA ANALİZİ
# ══════════════════════════════════════════════════════════════════
@app.get("/api/analyze/email/{email:path}")
async def analyze_email_endpoint(email: str):
    """
    E-Posta adresini güvenlik ve ihlal servislerinde taratır.
    Servisler: AbstractAPI, Spamhaus DBL, MX/DNS, VirusTotal, emailrep.io, HIBP, BreachDirectory
    """
    email_regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    if not email or not re.match(email_regex, email):
        raise HTTPException(status_code=400, detail="Geçersiz E-Posta formatı.")

    cache_key = f"email_{email}"
    cached = await get_from_cache(cache_key)
    if cached:
        return cached

    logger.info("E-Posta analizi başladı: %s", email)
    results_list = await analyze_email_all(email)
    results = {"results": results_list}
    results["ai_summary"] = await generate_summary(email, "E-Posta Adresi", results_list)

    await set_to_cache(cache_key, results)
    return results


# ══════════════════════════════════════════════════════════════════
# POWERSHELL ANALİZİ
# ══════════════════════════════════════════════════════════════════
class PowerShellRequest(BaseModel):
    script_content: str


@app.post("/api/analyze/powershell/")
async def analyze_powershell_endpoint(request: PowerShellRequest):
    """
    PowerShell betiğini deobfuscate eder ve LLM ile zararlı yazılım analizi yapar.
    """
    content = request.script_content.strip()
    if not content or len(content) < 5:
        raise HTTPException(status_code=400, detail="Geçersiz veya çok kısa PowerShell betiği.")

    script_hash = hashlib.md5(content.encode("utf-8")).hexdigest()
    cache_key = f"ps_{script_hash}"
    cached = await get_from_cache(cache_key)
    if cached:
        return cached

    logger.info("PowerShell analizi başladı (hash=%s)", script_hash[:8])
    results = await analyze_powershell_with_ai(content)
    await set_to_cache(cache_key, results)
    return results


# ══════════════════════════════════════════════════════════════════
# RAPOR TARAMASI
# ══════════════════════════════════════════════════════════════════
class ReportRequest(BaseModel):
    text: str
    url: str = ""


@app.post("/api/analyze/report")
async def analyze_report_endpoint(request: ReportRequest):
    """
    Web sayfası/rapor metnindeki IOC'leri LLM ile tespit eder,
    repütasyon taraması ve SPL sorgusu üretimi yapar.
    """
    content = request.text.strip()
    if not content or len(content) < 50:
        raise HTTPException(status_code=400, detail="Geçersiz veya çok kısa rapor metni.")

    logger.info("Rapor taraması başladı: %d karakter", len(content))
    return await analyze_report_text(content, request.url)


class ReportSplRequest(BaseModel):
    ioc_type: str
    values: List[str]


@app.post("/api/analyze/report/spl")
async def report_spl_endpoint(request: ReportSplRequest):
    """
    Rapor taramasında bulunan IOC grupları için lazy loading ile SPL sorgusu üretir.
    """
    from services.spl_intelligence import generate_bulk_spl_queries

    if not request.values:
        raise HTTPException(status_code=400, detail="Değer listesi boş olamaz.")

    val_str = ",".join(sorted(request.values))
    cache_key = f"spl_bulk_{hashlib.md5((request.ioc_type + val_str).encode()).hexdigest()}"
    cached = await get_from_cache(cache_key)
    if cached:
        return cached

    queries = await generate_bulk_spl_queries(request.ioc_type, request.values)
    result = {"ioc_type": request.ioc_type, "query_count": len(queries), "queries": queries}
    await set_to_cache(cache_key, result)
    return result


# ══════════════════════════════════════════════════════════════════
# SPLUNK SIEM ENTEGRASYONU
# ══════════════════════════════════════════════════════════════════
class SplunkRequest(BaseModel):
    ioc_value: str
    ioc_type: str  # hash | ipv4 | url | email | powershell | domain
    osint_results: List[Any] = []


@app.post("/api/splunk/generate-spl")
async def generate_spl_endpoint(request: SplunkRequest):
    """
    IOC değerine ve tipine göre kurum Splunk ortamına özgü SPL sorguları üretir.
    """
    ioc_value = request.ioc_value.strip()
    ioc_type  = request.ioc_type.strip().lower()

    if not ioc_value:
        raise HTTPException(status_code=400, detail="ioc_value boş olamaz.")

    valid_types = ["hash", "ipv4", "url", "email", "powershell", "domain"]
    if ioc_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Geçersiz ioc_type. Desteklenen tipler: {', '.join(valid_types)}")

    cache_key = f"spl_{hashlib.md5((ioc_type + ioc_value).encode()).hexdigest()}"
    cached = await get_from_cache(cache_key)
    if cached:
        return cached

    queries = await generate_spl_queries(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        osint_results=request.osint_results,
    )

    result = {"ioc_value": ioc_value, "ioc_type": ioc_type, "query_count": len(queries), "queries": queries}
    await set_to_cache(cache_key, result)
    return result


class SplunkExecuteRequest(BaseModel):
    query: str


@app.post("/api/splunk/execute")
async def execute_spl_endpoint(request: SplunkExecuteRequest):
    """
    SPL sorgusunu Splunk REST API üzerinden çalıştırır.
    Yapılandırma eksikse 'not_configured' yanıtı döner (exception fırlatmaz).
    """
    query = request.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="SPL sorgusu boş olamaz.")

    return await execute_spl_query(query)


# ══════════════════════════════════════════════════════════════════
# CVE ZAFİYET ANALİZİ
# ══════════════════════════════════════════════════════════════════
@app.get("/api/analyze/cve/{cve_id}")
async def analyze_cve_endpoint(cve_id: str):
    """
    CVE numarasını NIST NVD + FIRST EPSS ile sorgular.
    EPSS: zafiyetin gerçek dünyada istismar edilme olasılığı (0-1 arası skor).
    """
    from services.cve_intelligence import fetch_cve_details

    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise HTTPException(status_code=400, detail="Geçersiz CVE formatı. Örnek: CVE-2024-1234")

    cache_key = f"cve_{cve_id}"
    cached = await get_from_cache(cache_key)
    if cached:
        return cached

    logger.info("CVE analizi başladı: %s", cve_id)
    result = await fetch_cve_details(cve_id)

    if result.get("status") == "success":
        await set_to_cache(cache_key, result)

    return result


# ══════════════════════════════════════════════════════════════════
# XDR SORGU ÇALIŞTIRMA
# ══════════════════════════════════════════════════════════════════
class XDRExecuteRequest(BaseModel):
    query: str


@app.post("/api/xdr/execute")
async def execute_xdr_endpoint(req: XDRExecuteRequest):
    """
    Cortex XDR üzerinde XQL sorgusu çalıştırır.
    Yapılandırma eksikse 'not_configured' yanıtı döner (exception fırlatmaz).
    """
    if not req.query:
        raise HTTPException(status_code=400, detail="XQL sorgusu boş olamaz.")

    return await execute_xdr_query(req.query)


# ══════════════════════════════════════════════════════════════════
# SAĞLIK KONTROLÜ
# ══════════════════════════════════════════════════════════════════
@app.get("/health")
@app.get("/api/health")
async def health_check():
    """Servis sağlık durumunu döner. Splunk ve XDR yapılandırma durumu dahil."""
    from services.splunk_executor import is_configured as splunk_configured
    from services.xdr_executor import _is_configured as xdr_configured
    from services.llm_config import LLM_URL, LLM_API_KEY

    return {
        "status": "ok",
        "version": "2.5.0",
        "services": {
            "llm": bool(LLM_URL and LLM_API_KEY),
            "splunk": splunk_configured(),
            "xdr": xdr_configured(),
        },
        "cache_entries": len(_CACHE),
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
