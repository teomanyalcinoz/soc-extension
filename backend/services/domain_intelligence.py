"""
TracePoint v2.5 — Domain / Altyapı İstihbaratı
Desteklenen servisler:
  • SecurityTrails (DNS geçmişi, subdomain'ler, WHOIS)
  • crt.sh (Sertifika Şeffaflık Günlüğü)
  • RDAP (Domain WHOIS verileri — ücretsiz)
  • IntelX (2.intelx.io — dark/clearweb arama)
"""
import httpx
import asyncio
import os
import logging
from typing import Dict, Any

from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

logger = logging.getLogger(__name__)

SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
INTELX_API_KEY         = os.getenv("INTELX_API_KEY", "")

_TIMEOUT = 15.0


# ──────────────────────────────────────────────────────────────────
# SecurityTrails — DNS Geçmişi & Subdomain Keşfi
# ──────────────────────────────────────────────────────────────────
async def query_securitytrails(client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
    """SecurityTrails ile domain DNS geçmişi, subdomain ve WHOIS bilgisi."""
    if not SECURITYTRAILS_API_KEY:
        return {"source": "SecurityTrails", "success": False, "error": "SECURITYTRAILS_API_KEY ayarlanmamış"}

    headers = {"APIKEY": SECURITYTRAILS_API_KEY, "Accept": "application/json"}

    try:
        # Paralel: domain detayı + subdomain sayısı
        domain_resp, sub_resp = await asyncio.gather(
            client.get(f"https://api.securitytrails.com/v1/domain/{domain}", headers=headers, timeout=_TIMEOUT),
            client.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=true&include_inactive=false",
                headers=headers,
                timeout=_TIMEOUT,
            ),
            return_exceptions=True,
        )

        result: dict = {}

        if not isinstance(domain_resp, Exception) and domain_resp.status_code == 200:
            d = domain_resp.json()
            result["current_dns"] = d.get("current_dns", {})
            result["alexa_rank"] = d.get("alexa_rank")
            result["whois"] = {
                "registrar": d.get("whois", {}).get("registrar"),
                "created": d.get("whois", {}).get("createdDate"),
                "expires": d.get("whois", {}).get("expiresDate"),
                "status": d.get("whois", {}).get("status"),
            }

        if not isinstance(sub_resp, Exception) and sub_resp.status_code == 200:
            sd = sub_resp.json()
            result["subdomain_count"] = sd.get("subdomain_count", 0)
            result["subdomains"] = sd.get("subdomains", [])[:20]

        if not result:
            status_code = domain_resp.status_code if not isinstance(domain_resp, Exception) else "N/A"
            return {"source": "SecurityTrails", "success": False, "error": f"HTTP {status_code}"}

        return {"source": "SecurityTrails", "success": True, "data": result}

    except Exception as e:
        logger.warning("SecurityTrails sorgusu başarısız: %s", e)
        return {"source": "SecurityTrails", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# crt.sh — Sertifika Şeffaflık Günlüğü
# ──────────────────────────────────────────────────────────────────
async def query_crtsh(client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
    """
    crt.sh (Certificate Transparency Log) üzerinden yayınlanmış SSL sertifikalarını sorgular.
    Domain ile eşleşen sertifika kayıtları döner — subdomain keşfi için de kullanışlıdır.
    """
    try:
        resp = await client.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            certs = resp.json()
            # Benzersiz common name / SAN listesi çıkar
            seen: set[str] = set()
            entries = []
            for cert in certs[:100]:  # Max 100 kayıt
                cn = cert.get("common_name", "")
                if cn and cn not in seen:
                    seen.add(cn)
                    entries.append({
                        "common_name": cn,
                        "issuer": cert.get("issuer_name", ""),
                        "not_before": cert.get("not_before", "")[:10] if cert.get("not_before") else None,
                        "not_after": cert.get("not_after", "")[:10] if cert.get("not_after") else None,
                    })
            return {
                "source": "crt.sh",
                "success": True,
                "data": {
                    "certificate_count": len(certs),
                    "unique_names": len(entries),
                    "certificates": entries[:30],  # İlk 30 benzersiz
                },
            }
        return {"source": "crt.sh", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("crt.sh sorgusu başarısız: %s", e)
        return {"source": "crt.sh", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# RDAP — Domain WHOIS (Ücretsiz, key gerektirmez)
# ──────────────────────────────────────────────────────────────────
async def query_rdap(client: httpx.AsyncClient, domain: str) -> Dict[str, Any]:
    """
    RDAP (Registration Data Access Protocol) üzerinden domain WHOIS bilgisi alır.
    ARIN, RIPE, APNIC gibi RDAP uyumlu sunuculara yönlendirilir.
    """
    try:
        resp = await client.get(
            f"https://rdap.org/domain/{domain}",
            timeout=_TIMEOUT,
            follow_redirects=True,
        )
        if resp.status_code == 200:
            data = resp.json()

            # Temel RDAP alanlarını parse et
            registrar = None
            entities = data.get("entities", [])
            for entity in entities:
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for field in vcard[1]:
                            if isinstance(field, list) and field[0] == "fn":
                                registrar = field[3]
                                break

            # Olaylar (kayıt tarihi, güncelleme tarihi, sona erme tarihi)
            events_parsed = {}
            for event in data.get("events", []):
                action = event.get("eventAction", "")
                date = event.get("eventDate", "")[:10] if event.get("eventDate") else None
                if action and date:
                    events_parsed[action] = date

            return {
                "source": "RDAP",
                "success": True,
                "data": {
                    "domain": data.get("ldhName"),
                    "status": data.get("status", []),
                    "registrar": registrar,
                    "registration": events_parsed.get("registration"),
                    "expiration": events_parsed.get("expiration"),
                    "last_changed": events_parsed.get("last changed"),
                    "name_servers": [ns.get("ldhName") for ns in data.get("nameservers", [])],
                },
            }
        if resp.status_code == 404:
            return {"source": "RDAP", "success": True, "data": {"message": "Domain RDAP veritabanında bulunamadı"}}
        return {"source": "RDAP", "success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        logger.warning("RDAP sorgusu başarısız: %s", e)
        return {"source": "RDAP", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# IntelX — Intelligence X Arama
# ──────────────────────────────────────────────────────────────────
async def query_intelx(client: httpx.AsyncClient, query: str) -> Dict[str, Any]:
    """
    Intelligence X (2.intelx.io) üzerinden dark/clearweb arama.
    İki aşamalı API: önce arama başlat, sonra sonuçları al.
    """
    if not INTELX_API_KEY:
        return {"source": "IntelX", "success": False, "error": "INTELX_API_KEY ayarlanmamış"}

    headers = {"x-key": INTELX_API_KEY, "Content-Type": "application/json"}

    try:
        # Arama başlat
        search_payload = {
            "term": query,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": 10,
            "timeout": 5,
            "datefrom": "",
            "dateto": "",
            "sort": 4,  # En yeniden en eskiye
            "media": 0,
            "terminate": [],
        }
        start_resp = await client.post(
            "https://2.intelx.io/intelligent/search",
            headers=headers,
            json=search_payload,
            timeout=10.0,
        )
        if start_resp.status_code != 200:
            return {"source": "IntelX", "success": False, "error": f"Arama başlatılamadı: HTTP {start_resp.status_code}"}

        search_id = start_resp.json().get("id")
        if not search_id:
            return {"source": "IntelX", "success": False, "error": "Search ID alınamadı"}

        # Kısa bekleme
        await asyncio.sleep(1.5)

        # Sonuçları al
        result_resp = await client.get(
            f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=10",
            headers=headers,
            timeout=10.0,
        )
        if result_resp.status_code == 200:
            result_data = result_resp.json()
            records = result_data.get("records", [])
            return {
                "source": "IntelX",
                "success": True,
                "data": {
                    "total_found": len(records),
                    "records": [
                        {
                            "name": r.get("name"),
                            "date": r.get("date", "")[:10] if r.get("date") else None,
                            "bucket": r.get("bucket"),
                            "type": r.get("type"),
                        }
                        for r in records[:10]
                    ],
                },
            }
        return {"source": "IntelX", "success": False, "error": f"Sonuçlar alınamadı: HTTP {result_resp.status_code}"}

    except Exception as e:
        logger.warning("IntelX sorgusu başarısız: %s", e)
        return {"source": "IntelX", "success": False, "error": str(e)}


# ──────────────────────────────────────────────────────────────────
# Ana Analiz Fonksiyonu
# ──────────────────────────────────────────────────────────────────
async def analyze_domain(domain: str) -> Dict[str, Any]:
    """
    Domain altyapısını SecurityTrails, crt.sh, RDAP ve IntelX ile analiz eder.
    Tüm sorgular eşzamanlı çalışır.
    """
    async with httpx.AsyncClient(follow_redirects=True) as client:
        results = await asyncio.gather(
            query_securitytrails(client, domain),
            query_crtsh(client, domain),
            query_rdap(client, domain),
            query_intelx(client, domain),
            return_exceptions=True,
        )

    safe_results = []
    for r in results:
        if isinstance(r, Exception):
            safe_results.append({"source": "Bilinmeyen Kaynak", "success": False, "error": str(r)})
        else:
            safe_results.append(r)

    return {"domain": domain, "results": safe_results}
