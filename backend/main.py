from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Any
from services.intelligence import analyze_hash
from services.ip_intelligence import analyze_ip
from services.url_intelligence import analyze_url
from services.email_intelligence import analyze_email_all
from services.ai_summary import generate_summary
from services.powershell_intelligence import analyze_powershell_with_ai
from services.spl_intelligence import generate_spl_queries
from services.splunk_executor import execute_spl_query
from services.report_scanner import analyze_report_text
import re
import urllib.parse
import time
import uvicorn
import hashlib

app = FastAPI(title="SOC Asistani API", description="Siber Guvenlik Tehdit Istihbarati ve Hash Analizi")

# Basit In-Memory Önbellek Sistemi (5 Dakika = 300 Saniye)
CACHE = {}
CACHE_TTL = 300

def get_from_cache(key: str):
    if key in CACHE:
        if time.time() - CACHE[key]["timestamp"] < CACHE_TTL:
            return CACHE[key]["data"]
        else:
            del CACHE[key]
    return None

def set_to_cache(key: str, data: dict):
    CACHE[key] = {
        "data": data,
        "timestamp": time.time()
    }

# CORS (Cross-Origin Resource Sharing) Ayarları - Frontend'in haberleşebilmesi için
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Geliştirme ortamında her yerden erişime izin veriyoruz
    allow_credentials=False, # Eklentilerin CORS 'Failed to Fetch' hatalarını önlemek için False olmalı
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/analyze/hash/{file_hash}")
async def analyze_hash_endpoint(file_hash: str):
    """
    Verilen hash (MD5, SHA1 veya SHA256) değerini çeşitli OSINT ve Tehdit İstihbaratı kaynaklarında sorgular.
    """
    if not file_hash or len(file_hash) not in (32, 40, 64):
        raise HTTPException(status_code=400, detail="Geçersiz hash formatı. MD5 (32), SHA1 (40) veya SHA256 (64) bekleniyor.")
    
    # Cache Kontrolü
    cached_result = get_from_cache(f"hash_{file_hash}")
    if cached_result:
        return cached_result
        
    results = await analyze_hash(file_hash)
    
    # Başarılı olan sonuçların json halleriyle yapay zekaya özetleme isteği at
    ai_text = await generate_summary(file_hash, "Hash Dosyası", results.get("results", []))
    results["ai_summary"] = ai_text
    
    set_to_cache(f"hash_{file_hash}", results)
    return results

@app.get("/api/analyze/ip/{ip_address}")
async def analyze_ip_endpoint(ip_address: str):
    """
    Verilen IPv4 adresini çeşitli OSINT ve Tehdit İstihbaratı kaynaklarında sorgular.
    """
    ip_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if not ip_address or not re.match(ip_regex, ip_address):
        raise HTTPException(status_code=400, detail="Geçersiz IPv4 formatı.")
        
    # Cache Kontrolü
    cached_result = get_from_cache(f"ip_{ip_address}")
    if cached_result:
        return cached_result
    
    results = await analyze_ip(ip_address)
    
    ai_text = await generate_summary(ip_address, "IPv4 Adresi", results.get("results", []))
    results["ai_summary"] = ai_text
    
    set_to_cache(f"ip_{ip_address}", results)
    return results

@app.get("/api/analyze/url/{url:path}")
async def analyze_url_endpoint(url: str):
    """
    Verilen URL/Domain adresini güvenlik servislerinde taratır.
    """
    url = urllib.parse.unquote(url)
    if not url or len(url) < 4:
        raise HTTPException(status_code=400, detail="Geçersiz URL formatı.")
        
    # URL'lerde http/https temizliği (sadece arama motoru optimizasyonu içindir, vt vs domain destekler)
    
    cached_result = get_from_cache(f"url_{url}")
    if cached_result:
        return cached_result
    
    results = await analyze_url(url)
    
    ai_text = await generate_summary(url, "URL / Web Adresi", results.get("results", []))
    results["ai_summary"] = ai_text
    
    set_to_cache(f"url_{url}", results)
    return results

@app.get("/api/analyze/email/{email:path}")
async def analyze_email_endpoint(email: str):
    """
    Verilen E-Posta adresini HIBP, emailrep.io ve AbstractAPI servislerinde taratır.
    """
    email_regex = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    if not email or not re.match(email_regex, email):
        raise HTTPException(status_code=400, detail="Geçersiz E-Posta formatı.")
        
    cached_result = get_from_cache(f"email_{email}")
    if cached_result:
        return cached_result
    
    results_list = await analyze_email_all(email)
    results = {"results": results_list}
    
    ai_text = await generate_summary(email, "E-Posta Adresi", results_list)
    results["ai_summary"] = ai_text
    
    set_to_cache(f"email_{email}", results)
    return results

class PowerShellRequest(BaseModel):
    script_content: str

@app.post("/api/analyze/powershell/")
async def analyze_powershell_endpoint(request: PowerShellRequest):
    """
    Gönderilen PowerShell betiğini deobfuscate (çözümler) eder ve Llama-3 Modeli üzerinden zararlı yazılım analizine tabi tutar.
    """
    content = request.script_content.strip()
    if not content or len(content) < 5:
        raise HTTPException(status_code=400, detail="Geçersiz veya çok kısa PowerShell betiği.")
        
    script_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
    cached_result = get_from_cache(f"ps_{script_hash}")
    if cached_result:
        return cached_result
    
    results = await analyze_powershell_with_ai(content)
    
    set_to_cache(f"ps_{script_hash}", results)
    return results

class ReportRequest(BaseModel):
    text: str
    url: str = ""

@app.post("/api/analyze/report")
async def analyze_report_endpoint(request: ReportRequest):
    """
    Gönderilen metin (web sayfası içeriği vb.) içindeki IOC'leri LLM aracılığıyla bulur,
    özet çıkartır ve bulunan IOC'ler için repütasyon ile SPL sorgularını otomatik oluşturur.
    """
    content = request.text.strip()
    if not content or len(content) < 50:
        raise HTTPException(status_code=400, detail="Geçersiz veya çok kısa rapor metni.")
        
    results = await analyze_report_text(content, request.url)
    return results

class ReportSplRequest(BaseModel):
    ioc_type: str
    values: List[str]

@app.post("/api/analyze/report/spl")
async def report_spl_endpoint(request: ReportSplRequest):
    """
    Rapor taraması sonucunda bulunan IOC grupları için lazy loading ile
    asenkron SPL sorgusu üretir.
    """
    from services.spl_intelligence import generate_bulk_spl_queries
    
    if not request.values:
        raise HTTPException(status_code=400, detail="Değer listesi boş olamaz.")
        
    # Cache key
    val_str = ",".join(sorted(request.values))
    cache_key = f"spl_bulk_{hashlib.md5((request.ioc_type + val_str).encode('utf-8')).hexdigest()}"
    cached = get_from_cache(cache_key)
    if cached:
        return cached

    queries = await generate_bulk_spl_queries(request.ioc_type, request.values)
    
    result = {
        "ioc_type": request.ioc_type,
        "query_count": len(queries),
        "queries": queries
    }
    
    set_to_cache(cache_key, result)
    return result

# ──────────────────────────────────────────────────────────────────
# SPLUNK SIEM ENTEGRASYONU
# ──────────────────────────────────────────────────────────────────

class SplunkRequest(BaseModel):
    ioc_value: str
    ioc_type: str          # hash | ipv4 | url | email | powershell
    osint_results: List[Any] = []

@app.post("/api/splunk/generate-spl")
async def generate_spl_endpoint(request: SplunkRequest):
    """
    Verilen IOC değeri ve tipine göre kurum Splunk ortamına özgü SPL sorguları üretir.
    Kullanılan indexler: panos (Firewall), bluecoat (Proxy), wineventlog (Windows/Sysmon),
    fortimail (Mail), f5 (WAF).
    Yapay zeka (Gemma-4) SPL kurallarını ve OSINT bağlamını dikkate alarak sorgular oluşturur.
    """
    ioc_value = request.ioc_value.strip()
    ioc_type  = request.ioc_type.strip().lower()

    if not ioc_value:
        raise HTTPException(status_code=400, detail="ioc_value boş olamaz.")

    valid_types = ["hash", "ipv4", "url", "email", "powershell"]
    if ioc_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Geçersiz ioc_type. Desteklenen tipler: {', '.join(valid_types)}"
        )

    # Cache anahtarı: ioc_type + ioc_value kombinasyonu
    cache_key = f"spl_{hashlib.md5((ioc_type + ioc_value).encode('utf-8')).hexdigest()}"
    cached = get_from_cache(cache_key)
    if cached:
        return cached

    queries = await generate_spl_queries(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        osint_results=request.osint_results
    )

    result = {
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "query_count": len(queries),
        "queries": queries
    }

    set_to_cache(cache_key, result)
    return result


# ──────────────────────────────────────────────────────────────────
# SPLUNK REST API SORGU ÇALIŞTIRMA
# ──────────────────────────────────────────────────────────────────

class SplunkExecuteRequest(BaseModel):
    query: str

@app.post("/api/splunk/execute")
async def execute_spl_endpoint(request: SplunkExecuteRequest):
    """
    Üretilen SPL sorgusunu Splunk REST API üzerinden çalıştırır.
    Yapılandırma (.env) eksikse pasif modda uyarı mesajı döner.
    """
    query = request.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="SPL sorgusu boş olamaz.")

    result = await execute_spl_query(query)
    return result


# ──────────────────────────────────────────────────────────────────
# CVE DETAY ANALİZİ (NIST NVD)
# ──────────────────────────────────────────────────────────────────

@app.get("/api/analyze/cve/{cve_id}")
async def analyze_cve_endpoint(cve_id: str):
    """
    Verilen CVE numarasını (örn: CVE-2024-1234) NIST NVD API üzerinden sorgular.
    CVSS skoru, zafiyet açıklaması ve etkilenen varlıkları döner.
    """
    from services.cve_intelligence import fetch_cve_details

    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise HTTPException(status_code=400, detail="Geçersiz CVE formatı. Örnek: CVE-2024-1234")

    cached = get_from_cache(f"cve_{cve_id}")
    if cached:
        return cached

    result = await fetch_cve_details(cve_id)

    if result.get("status") == "success":
        set_to_cache(f"cve_{cve_id}", result)

    return result


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
