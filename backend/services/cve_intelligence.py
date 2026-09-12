"""
TracePoint v2.0 — CVE Zafiyet İstihbaratı
Desteklenen servisler:
  • NIST NVD 2.0 API
  • FIRST EPSS (Exploit Prediction Scoring System)
"""
import httpx
import re
import os
import logging

from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

NVD_API_KEY = os.getenv("NVD_API_KEY", "")

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_TIMEOUT = 20.0


# ──────────────────────────────────────────────────────────────────
# Yardımcı: CPE 2.3 parse
# ──────────────────────────────────────────────────────────────────
def _parse_cpe_label(criteria: str) -> dict | None:
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
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    resp = await client.get(NVD_API_URL, params={"cveId": cve_id}, headers=headers, timeout=_TIMEOUT)

    if resp.status_code == 403:
        raise ValueError("NIST NVD rate limit — lütfen birkaç saniye bekleyin.")
    if resp.status_code != 200:
        raise ValueError(f"NIST NVD HTTP {resp.status_code}")

    data = resp.json()
    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        raise ValueError("Bu CVE NIST veritabanında bulunamadı.")

    cve_data = vulnerabilities[0].get("cve", {})

    # Açıklama (İngilizce öncelikli)
    description = ""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description:
        descs = cve_data.get("descriptions", [])
        description = descs[0].get("value", "Açıklama bulunamadı.") if descs else "Açıklama bulunamadı."

    # CVSS Skoru (v3.1 → v3.0 → v2.0 sırasıyla)
    cvss_score = cvss_severity = cvss_vector = None
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = cve_data.get("metrics", {}).get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity") or metric_list[0].get("baseSeverity")
            cvss_vector = cvss_data.get("vectorString")
            break

    # Etkilenen Varlıklar (CPE Parse)
    affected_assets = []
    seen: set[str] = set()
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                parsed = _parse_cpe_label(cpe_match.get("criteria", ""))
                if parsed:
                    key = f"{parsed['vendor']}|{parsed['product']}"
                    if key not in seen:
                        seen.add(key)
                        affected_assets.append(parsed)

    # Referanslar (İlk 5)
    references = [ref.get("url") for ref in cve_data.get("references", [])[:5] if ref.get("url")]

    # Yayınlanma tarihi
    published = cve_data.get("published", None)
    if published:
        published = published[:10]

    return {
        "description": description,
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "cvss_vector": cvss_vector,
        "affected_assets": affected_assets,
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
        resp = await client.get(EPSS_API_URL, params={"cve": cve_id}, timeout=10.0)
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
    NIST NVD + FIRST EPSS verilerini birleştirerek kapsamlı CVE detayı döner.

    Returns:
        {
            "status": "success" | "error",
            "cve_id": str,
            "description": str,
            "cvss_score": float | None,
            "cvss_severity": str | None,
            "cvss_vector": str | None,
            "epss_score": float | None,
            "epss_percentile": float | None,
            "affected_assets": list,
            "references": list,
            "published": str | None,
        }
    """
    if not _CVE_PATTERN.match(cve_id):
        return {"status": "error", "cve_id": cve_id, "error": "Geçersiz CVE formatı. Örnek: CVE-2024-1234"}

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            import asyncio
            nvd_task = _fetch_nvd(cve_id, client)
            epss_task = _fetch_epss(cve_id, client)
            nvd_result, epss_result = await asyncio.gather(nvd_task, epss_task, return_exceptions=True)

        if isinstance(nvd_result, Exception):
            return {"status": "error", "cve_id": cve_id, "error": str(nvd_result)}

        # EPSS başarısızsa sıfır değerle devam et
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
        return {"status": "error", "cve_id": cve_id, "error": "NIST API isteği zaman aşımına uğradı."}
    except Exception as e:
        logger.error("CVE analizi beklenmeyen hata (%s): %s", cve_id, e)
        return {"status": "error", "cve_id": cve_id, "error": f"Beklenmeyen hata: {str(e)}"}
