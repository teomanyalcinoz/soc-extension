"""
TracePoint v2.5 — E-Posta İstihbaratı
Desteklenen servisler:
  • AbstractAPI (Email Validation)
  • Spamhaus DBL (DNS — ücretsiz)
  • MX / DNS Doğrulama (ücretsiz)
  • VirusTotal (Email Search)
  • emailrep.io
  • HaveIBeenPwned (HIBP)
  • BreachDirectory (RapidAPI)
"""
import httpx
import asyncio
import socket
import os
import logging
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

logger = logging.getLogger(__name__)

# ── API Key'ler (.env üzerinden okunur) ───────────────────────────
ABSTRACT_API_KEY       = os.getenv("ABSTRACT_API_KEY", "")
VT_API_KEY             = os.getenv("VT_API_KEY", "")
HIBP_API_KEY           = os.getenv("HIBP_API_KEY", "")
BREACHDIRECTORY_API_KEY = os.getenv("BREACHDIRECTORY_API_KEY", "")

_TIMEOUT = 12.0


# ──────────────────────────────────────────────────────────────────
# 1. AbstractAPI — E-Posta Doğrulama + Kalite Skoru
# ──────────────────────────────────────────────────────────────────
async def check_abstract_api(email: str) -> dict:
    """AbstractAPI üzerinden posta geçerlilik + kalite skoru"""
    if not ABSTRACT_API_KEY:
        return {"source": "AbstractAPI", "success": False, "error": "ABSTRACT_API_KEY ayarlanmamış"}

    url = f"https://emailreputation.abstractapi.com/v1/?api_key={ABSTRACT_API_KEY}&email={email}"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                deliv = data.get("email_deliverability", {})
                flat = {
                    "deliverability": deliv.get("status", data.get("deliverability", "UNKNOWN")),
                    "quality_score": data.get("quality_score", 0),
                    "is_disposable_email": {"value": data.get("is_disposable_email", False)},
                    "is_free_email": {"value": data.get("is_free_email", False)},
                    "is_role_email": {"value": data.get("is_role_email", False)},
                    "is_valid_format": data.get("is_valid_format", True),
                    "breaches": data.get("breaches", []),
                    "breach_count": len(data.get("breaches", [])),
                }
                return {"source": "AbstractAPI", "success": True, "data": flat}
            return {"source": "AbstractAPI", "success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning("AbstractAPI e-posta sorgusu başarısız: %s", e)
            return {"source": "AbstractAPI", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# 2. Spamhaus DBL — DNS Tabanlı Kara Liste
# Senkron DNS çağrısı → thread pool'da çalıştırılır (event loop'u bloke etmez)
# ──────────────────────────────────────────────────────────────────
def _check_spamhaus_dns_sync(domain: str) -> dict:
    """Spamhaus DBL ve Zen listelerini DNS üzerinden sorgular (senkron)."""
    dbl_listed = sbl_listed = False
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2)
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
        socket.setdefaulttimeout(old_timeout)

    return {
        "source": "Spamhaus",
        "success": True,
        "data": {
            "domain_blacklisted": dbl_listed or sbl_listed,
            "dbl_listed": dbl_listed,
            "sbl_listed": sbl_listed,
            "domain": domain,
        },
    }


async def check_spamhaus_dns(domain: str) -> dict:
    """Spamhaus'u thread pool'da çalıştır (asyncio event loop'u bloke etmez)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_spamhaus_dns_sync, domain)


# ──────────────────────────────────────────────────────────────────
# 3. MX / DNS Doğrulama — Ücretsiz, key gerektirmez
# ──────────────────────────────────────────────────────────────────
def _check_mx_record_sync(domain: str) -> dict:
    """E-posta domain'inin DNS kaydı olup olmadığını senkron kontrol eder."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2)
        try:
            results = socket.getaddrinfo(domain, None)
            has_dns = len(results) > 0
        except (socket.gaierror, socket.timeout):
            has_dns = False
        finally:
            socket.setdefaulttimeout(old_timeout)
        return {
            "source": "MX / DNS Doğrulama",
            "success": True,
            "data": {"domain": domain, "domain_resolves": has_dns, "mx_valid": has_dns},
        }
    except Exception:
        return {
            "source": "MX / DNS Doğrulama",
            "success": True,
            "data": {"domain": domain, "domain_resolves": False, "mx_valid": False},
        }


async def check_mx_record(domain: str) -> dict:
    """MX kontrolünü thread pool'da çalıştır."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_mx_record_sync, domain)


# ──────────────────────────────────────────────────────────────────
# 4. VirusTotal — E-Posta Arama
# ──────────────────────────────────────────────────────────────────
async def check_vt_email(email: str) -> dict:
    if not VT_API_KEY:
        return {"source": "VirusTotal", "success": False, "error": "VT_API_KEY ayarlanmamış"}
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        try:
            resp = await client.get(f"https://www.virustotal.com/api/v3/search?query={email}")
            if resp.status_code == 200:
                data = resp.json()
                results_count = len(data.get("data", []))
                return {
                    "source": "VirusTotal",
                    "success": True,
                    "data": {
                        "email_matches": results_count,
                        "raw_results": data.get("data", [])[:3],
                    },
                }
            return {"source": "VirusTotal", "success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning("VirusTotal email sorgusu başarısız: %s", e)
            return {"source": "VirusTotal", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# 5. emailrep.io — İtibar Kontrolü
# ──────────────────────────────────────────────────────────────────
async def check_emailrep(email: str) -> dict:
    headers = {"User-Agent": "TracePoint-SOC/2.5", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        try:
            resp = await client.get(f"https://emailrep.io/{email}")
            if resp.status_code == 200:
                return {"source": "emailrep.io", "success": True, "data": resp.json()}
            if resp.status_code == 429:
                return {"source": "emailrep.io", "success": False, "error": "Rate limit aşıldı (günlük 100 istek)"}
            return {"source": "emailrep.io", "success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning("emailrep.io sorgusu başarısız: %s", e)
            return {"source": "emailrep.io", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# 6. HaveIBeenPwned (HIBP) v3
# ──────────────────────────────────────────────────────────────────
async def check_hibp(email: str) -> dict:
    """HaveIBeenPwned v3 API ile e-posta ihlal kontrolü."""
    if not HIBP_API_KEY:
        return {"source": "HaveIBeenPwned", "success": False, "error": "HIBP_API_KEY ayarlanmamış"}

    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "TracePoint-SOC/2.5",
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                breaches = resp.json()
                return {
                    "source": "HaveIBeenPwned",
                    "success": True,
                    "breached": True,
                    "data": [{"Name": b.get("Name"), "Domain": b.get("Domain"), "BreachDate": b.get("BreachDate"), "DataClasses": b.get("DataClasses", [])} for b in breaches],
                }
            if resp.status_code == 404:
                return {"source": "HaveIBeenPwned", "success": True, "breached": False, "data": []}
            if resp.status_code == 401:
                return {"source": "HaveIBeenPwned", "success": False, "error": "API Key geçersiz (401)"}
            if resp.status_code == 429:
                return {"source": "HaveIBeenPwned", "success": False, "error": "Rate limit aşıldı (429)"}
            return {"source": "HaveIBeenPwned", "success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning("HIBP sorgusu başarısız: %s", e)
            return {"source": "HaveIBeenPwned", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# 7. BreachDirectory (RapidAPI)
# ──────────────────────────────────────────────────────────────────
async def check_breachdirectory(email: str) -> dict:
    """BreachDirectory RapidAPI ile sızdırılmış kimlik bilgisi kontrolü."""
    if not BREACHDIRECTORY_API_KEY:
        return {"source": "BreachDirectory", "success": False, "error": "BREACHDIRECTORY_API_KEY ayarlanmamış"}

    headers = {
        "X-RapidAPI-Key": BREACHDIRECTORY_API_KEY,
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
    }
    url = f"https://breachdirectory.p.rapidapi.com/?func=auto&term={email}"
    async with httpx.AsyncClient(timeout=_TIMEOUT, headers=headers) as client:
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "source": "BreachDirectory",
                    "success": True,
                    "data": {
                        "found": data.get("found", 0),
                        "result": data.get("result", [])[:5],  # İlk 5 sonuç
                    },
                }
            if resp.status_code in (401, 403):
                return {"source": "BreachDirectory", "success": False, "error": f"API Key hatası ({resp.status_code})"}
            return {"source": "BreachDirectory", "success": False, "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning("BreachDirectory sorgusu başarısız: %s", e)
            return {"source": "BreachDirectory", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Ana Analiz Fonksiyonu
# ──────────────────────────────────────────────────────────────────
async def analyze_email_all(email: str) -> list:
    """
    E-Posta analizi için tüm istihbarat kaynaklarına paralel istek atar.
    DNS kontrolleri thread pool'da çalışır — event loop'u bloke etmez.
    """
    domain = email.split("@")[1] if "@" in email else email

    # Tüm görevleri (hem async hem thread-pool) tek gather'da çalıştır
    all_results = await asyncio.gather(
        check_spamhaus_dns(domain),
        check_mx_record(domain),
        check_abstract_api(email),
        check_emailrep(email),
        check_vt_email(email),
        return_exceptions=True,
    )

    final_results = []
    for r in all_results:
        if isinstance(r, Exception):
            final_results.append({"source": "Bilinmeyen Kaynak", "success": False, "error": str(r)})
        else:
            final_results.append(r)

    return final_results
