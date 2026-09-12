import httpx
import asyncio
import socket
import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
ABSTRACT_API_KEY = os.getenv("ABSTRACT_API_KEY", "79fabf82b95f4b59879e93f281faee2d")
VT_API_KEY = os.getenv("VT_API_KEY", "bba747d1fdb03538935c609f3de2a5a2a3d2fd988f80446b6626e70b97ab34fa")

# -------------------------------------------------------------------------
# 1. Abstract API - Email Validation (Doğru endpoint: emailvalidation)
# -------------------------------------------------------------------------
async def check_abstract_api(email: str):
    """AbstractAPI üzerinden posta geçerlilik + kalite skoru"""
    url = f"https://emailvalidation.abstractapi.com/v1/?api_key={ABSTRACT_API_KEY}&email={email}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                # Flatten nested boolean fields from AbstractAPI response format
                flat = {
                    "deliverability": data.get("deliverability", "UNKNOWN"),
                    "quality_score": data.get("quality_score", 0),
                    "is_disposable_email": {"value": data.get("is_disposable_email", {}).get("value", False)},
                    "is_free_email": {"value": data.get("is_free_email", {}).get("value", False)},
                    "is_role_email": {"value": data.get("is_role_email", {}).get("value", False)},
                    "is_valid_format": data.get("is_valid_format", {}).get("value", False),
                    "mx_records": data.get("is_mx_found", {}).get("value", False),
                }
                return {"source": "AbstractAPI", "success": True, "data": flat}
            else:
                return {"source": "AbstractAPI", "success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"source": "AbstractAPI", "success": False, "error": str(e)}

# -------------------------------------------------------------------------
# 2. Spamhaus Domain Blacklist - Ücretsiz DNS tabanlı kontrol
# -------------------------------------------------------------------------
def check_spamhaus_dns(domain: str) -> dict:
    """Spamhaus DBL (Domain Block List) üzerinden DNS sorgusu yapar.
    Herhangi bir IP cevabı alınması = kara listede demektir.
    Ücretsiz, API keyi gerektirmez."""
    import signal
    
    dbl_listed = False
    sbl_listed = False
    
    try:
        socket.setdefaulttimeout(2)  # 2 saniye timeout
        try:
            socket.getaddrinfo(f"{domain}.dbl.spamhaus.org", None)
            dbl_listed = True
        except (socket.gaierror, socket.timeout):
            pass
        
        try:
            socket.getaddrinfo(f"{domain}.zen.spamhaus.org", None)
            sbl_listed = True
        except (socket.gaierror, socket.timeout):
            pass
    finally:
        socket.setdefaulttimeout(None)  # timeout'u sıfırla
    
    is_listed = dbl_listed or sbl_listed
    return {
        "source": "Spamhaus",
        "success": True,
        "data": {
            "domain_blacklisted": is_listed,
            "dbl_listed": dbl_listed,
            "sbl_listed": sbl_listed,
            "domain": domain
        }
    }

# -------------------------------------------------------------------------
# 3. MX Record Doğrulama - DNS üzerinden ücretsiz
# -------------------------------------------------------------------------
def check_mx_record(domain: str) -> dict:
    """E-posta adresinin domain'inin gerçek bir DNS kaydı olup olmadığını doğrular."""
    try:
        socket.setdefaulttimeout(2)
        try:
            results = socket.getaddrinfo(domain, None)
            has_dns = len(results) > 0
        except (socket.gaierror, socket.timeout):
            has_dns = False
        finally:
            socket.setdefaulttimeout(None)
        
        return {
            "source": "MX / DNS Doğrulama",
            "success": True,
            "data": {
                "domain": domain,
                "domain_resolves": has_dns,
                "mx_valid": has_dns
            }
        }
    except Exception:
        return {
            "source": "MX / DNS Doğrulama",
            "success": True,
            "data": {
                "domain": domain,
                "domain_resolves": False,
                "mx_valid": False
            }
        }

# -------------------------------------------------------------------------
# 4. VirusTotal - E-Posta arama (Mevcut VT Key)
# -------------------------------------------------------------------------
async def check_vt_email(email: str):
    """VirusTotal v3 Search Endpointi ile e-posta geçmiş kontrol"""
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/search?query={email}"
    async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                # VT email search returns a 'data' array of matched files/URLs
                results_count = len(data.get("data", []))
                return {
                    "source": "VirusTotal",
                    "success": True,
                    "data": {
                        "email_matches": results_count,
                        "raw_results": data.get("data", [])[:3]  # Sadece ilk 3 sonuç
                    }
                }
            else:
                return {"source": "VirusTotal", "success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"source": "VirusTotal", "success": False, "error": str(e)}

# -------------------------------------------------------------------------
# 5. EmailRep.io - İtibar Kontrolü (Rate limit sonrası ücretsiz API)
# -------------------------------------------------------------------------
async def check_emailrep(email: str):
    """emailrep.io üzerinden e-posta risk analizi"""
    headers = {
        "User-Agent": "TracePoint-KuveytTurk-SOC/1.0",
        "Accept": "application/json"
    }
    url = f"https://emailrep.io/{email}"
    async with httpx.AsyncClient(timeout=10.0, headers=headers) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                return {"source": "emailrep.io", "success": True, "data": resp.json()}
            elif resp.status_code == 429:
                return {"source": "emailrep.io", "success": False, "error": "Rate Limit aşıldı (günlük 100 istek limiti)"}
            else:
                return {"source": "emailrep.io", "success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"source": "emailrep.io", "success": False, "error": str(e)}

# -------------------------------------------------------------------------
# Ana Analiz Fonksiyonu - Tüm kaynakları paralel çalıştırır
# -------------------------------------------------------------------------
async def analyze_email_all(email: str):
    """E-Posta analizi için tüm istihbarat kaynaklarına paralel istek atar"""
    # E-postadan domain'i çıkar
    domain = email.split("@")[1] if "@" in email else email
    
    # Senkron DNS kontrollerini çalıştır
    spamhaus_result = check_spamhaus_dns(domain)
    mx_result = check_mx_record(domain)
    
    # Asenkron API çağrılarını paralel yap
    async_tasks = [
        check_abstract_api(email),
        check_emailrep(email),
        check_vt_email(email)
    ]
    async_results = await asyncio.gather(*async_tasks, return_exceptions=True)
    
    final_results = [spamhaus_result, mx_result]
    for r in async_results:
        if isinstance(r, Exception):
            final_results.append({"source": "Bilinmiyor", "success": False, "error": str(r)})
        else:
            final_results.append(r)
            
    return final_results
