from __future__ import annotations
"""
TracePoint v2.5 — CVE Zafiyet İstihbaratı
Desteklenen servisler:
  • NIST NVD 2.0 API
  • FIRST EPSS (Exploit Prediction Scoring System)
  • CIRCL CVE API (NIST erişilemediğinde yedek fallback)
"""
import httpx
import re
import os
import logging
from typing import Optional, Dict, Any, List

from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CIRCL_API_URL = "https://cve.circl.lu/api/cve"

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
# Kurumsal ağlarda SSL inspection (MITM proxy) olduğu için varsayılan verify=False
CVE_VERIFY_SSL = os.getenv("CVE_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_TIMEOUT = 20.0

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 TracePoint/2.5",
    "Accept": "application/json, text/plain, */*",
}


# ──────────────────────────────────────────────────────────────────
# Yardımcı: CPE 2.3 parse
# ──────────────────────────────────────────────────────────────────
def _parse_cpe_label(criteria: str) -> Optional[Dict[str, str]]:
    """
    CPE 2.3 formatını parse eder.
    Örn: cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*
         → {"vendor": "Microsoft", "product": "Exchange Server"}
    """
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    vendor = parts[3].replace("_", " ").title()
    product = parts[4].replace("_", " ").title()
    if not vendor or vendor == "*" or not product or product == "*":
        return None
    return {"vendor": vendor, "product": product}


# ──────────────────────────────────────────────────────────────────
# NIST NVD — CVE Detay
# ──────────────────────────────────────────────────────────────────
async def _fetch_nvd(cve_id: str, client: httpx.AsyncClient) -> dict:
    headers = dict(DEFAULT_HEADERS)
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    resp = await client.get(NVD_API_URL, params={"cveId": cve_id}, headers=headers, timeout=_TIMEOUT)

    if resp.status_code == 403:
        raise ValueError("NIST NVD rate limit veya erişim engeli (403).")
    if resp.status_code != 200:
        raise ValueError(f"NIST NVD HTTP {resp.status_code}")

    data = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        raise ValueError("Bu CVE NIST veritabanında bulunamadı.")

    cve_data = vulnerabilities[0].get("cve", {})

    # Açıklama (İngilizce öncelikli)
    description = ""
    try:
        for desc in cve_data.get("descriptions", []) or []:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description:
            descs = cve_data.get("descriptions", []) or []
            description = descs[0].get("value", "Açıklama bulunamadı.") if descs else "Açıklama bulunamadı."
    except (AttributeError, IndexError, TypeError):
        description = "Açıklama bulunamadı."

    # CVSS Skoru (v3.1 → v3.0 → v2.0 sırasıyla)
    cvss_score = None
    cvss_severity = None
    cvss_vector = None
    try:
        metrics = cve_data.get("metrics") or {}
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(key) or []
            if metric_list:
                cvss_data = metric_list[0].get("cvssData") or {}
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity") or metric_list[0].get("baseSeverity")
                cvss_vector = cvss_data.get("vectorString")
                break
    except (AttributeError, IndexError, TypeError) as e:
        logger.warning("CVSS parse hatası (%s): %s", cve_id, e)

    # Etkilenen Varlıklar (CPE Parse)
    affected_assets = []
    seen: set[str] = set()
    try:
        for config in cve_data.get("configurations") or []:
            for node in (config.get("nodes") or []):
                for cpe_match in (node.get("cpeMatch") or []):
                    parsed = _parse_cpe_label(cpe_match.get("criteria", ""))
                    if parsed:
                        key = f"{parsed['vendor']}|{parsed['product']}"
                        if key not in seen:
                            seen.add(key)
                            affected_assets.append(parsed)
    except (AttributeError, TypeError) as e:
        logger.warning("CPE parse hatası (%s): %s", cve_id, e)

    # Referanslar (İlk 5)
    try:
        references = [ref.get("url") for ref in (cve_data.get("references") or [])[:5] if ref.get("url")]
    except (AttributeError, TypeError):
        references = []

    # Yayınlanma tarihi
    published = cve_data.get("published", None)
    if published:
        published = published[:10]

    return {
        "source": "NIST NVD",
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "affected_assets": affected_assets,
        "references": references,
        "published": published,
    }


# ──────────────────────────────────────────────────────────────────
# CIRCL CVE — Yedek Fallback Servisi
# ──────────────────────────────────────────────────────────────────
async def _fetch_circl(cve_id: str, client: httpx.AsyncClient) -> dict:
    """NIST erişilemediğinde CIRCL açık CVE kaynağından zafiyet bilgilerini çeker."""
    url = f"{CIRCL_API_URL}/{cve_id}"
    resp = await client.get(url, headers=DEFAULT_HEADERS, timeout=12.0)
    if resp.status_code != 200:
        raise ValueError(f"CIRCL CVE HTTP {resp.status_code}")

    data = resp.json()
    if not data:
        raise ValueError("CIRCL CVE boş yanıt döndü.")

    # Açıklama
    description = data.get("summary", "")
    if not description and "containers" in data:
        try:
            cna = data["containers"].get("cna", {})
            descs = cna.get("descriptions", [])
            if descs:
                description = descs[0].get("value", "")
        except Exception:
            pass

    # CVSS
    cvss_score = data.get("cvss")
    cvss_severity = None
    cvss_vector = data.get("cvss-vector")

    if cvss_score is not None:
        try:
            score = float(cvss_score)
            if score >= 9.0:
                cvss_severity = "CRITICAL"
            elif score >= 7.0:
                cvss_severity = "HIGH"
            elif score >= 4.0:
                cvss_severity = "MEDIUM"
            else:
                cvss_severity = "LOW"
        except (ValueError, TypeError):
            pass

    # Referanslar
    references = data.get("references", [])
    if isinstance(references, list):
        references = [r if isinstance(r, str) else r.get("url", "") for r in references[:5]]
    else:
        references = []

    published = data.get("Published", data.get("published", None))
    if published:
        published = str(published)[:10]

    return {
        "source": "CIRCL CVE (Fallback)",
        "description": description or "Açıklama bulunamadı.",
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "affected_assets": [],
        "references": references,
        "published": published,
    }


# ──────────────────────────────────────────────────────────────────
# FIRST EPSS — Exploit Prediction Scoring System
# ──────────────────────────────────────────────────────────────────
async def _fetch_epss(cve_id: str, client: httpx.AsyncClient) -> dict:
    """
    FIRST EPSS API'den istismar olasılığı ve yüzdelik dilim alır.
    EPSS skoru 0-1 arasında; 1'e yaklaştıkça istismar olasılığı artar.
    """
    try:
        resp = await client.get(EPSS_API_URL, params={"cve": cve_id}, headers=DEFAULT_HEADERS, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            if data:
                return {
                    "epss_score": round(float(data[0].get("epss", 0)), 4),
                    "epss_percentile": round(float(data[0].get("percentile", 0)) * 100, 1),
                }
    except Exception as e:
        logger.warning("FIRST EPSS sorgusu başarısız: %s", e)
    return {"epss_score": None, "epss_percentile": None}


# ──────────────────────────────────────────────────────────────────
# Ana Fonksiyon
# ──────────────────────────────────────────────────────────────────
async def fetch_cve_details(cve_id: str) -> dict:
    """
    NIST NVD (+ gerekirse CIRCL fallback) + FIRST EPSS verilerini birleştirerek CVE detayı döner.
    """
    if not _CVE_PATTERN.match(cve_id):
        return {"status": "error", "cve_id": cve_id, "error": "Geçersiz CVE formatı. Örnek: CVE-2024-1234"}

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, verify=CVE_VERIFY_SSL) as client:
            import asyncio
            # 1. Öncelikli olarak NIST NVD ve EPSS dene
            nvd_task = _fetch_nvd(cve_id, client)
            epss_task = _fetch_epss(cve_id, client)
            nvd_result, epss_result = await asyncio.gather(nvd_task, epss_task, return_exceptions=True)

            # NIST başarısız olursa (rate limit, cloudflare, SSL hatası vb.) CIRCL fallback dene
            if isinstance(nvd_result, Exception):
                logger.warning("NIST NVD başarısız (%s: %s). CIRCL fallback deneniyor...", cve_id, nvd_result)
                try:
                    nvd_result = await _fetch_circl(cve_id, client)
                except Exception as circl_err:
                    logger.error("CIRCL fallback de başarısız (%s): %s", cve_id, circl_err)
                    return {
                        "status": "error",
                        "cve_id": cve_id,
                        "error": f"NIST ve CIRCL sorguları başarısız oldu: {str(nvd_result)}"
                    }

            # EPSS başarısızsa boş devam et
            if isinstance(epss_result, Exception):
                logger.warning("EPSS alınamadı (%s): %s", cve_id, epss_result)
                epss_result = {"epss_score": None, "epss_percentile": None}

            return {
                "status": "success",
                "cve_id": cve_id,
                **nvd_result,
                **epss_result,
            }

    except httpx.TimeoutException:
        return {"status": "error", "cve_id": cve_id, "error": "CVE API isteği zaman aşımına uğradı."}
    except Exception as e:
        logger.error("CVE analizi beklenmeyen hata (%s): %s", cve_id, e)
        return {"status": "error", "cve_id": cve_id, "error": f"CVE sorgulama hatası: {str(e)}"}
