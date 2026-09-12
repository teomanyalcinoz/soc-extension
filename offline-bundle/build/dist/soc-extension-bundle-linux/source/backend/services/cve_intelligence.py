import httpx
import re

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = "9da1147a-c81d-47a5-bb4b-1ae5e77830c6"


def _parse_cpe_label(criteria: str) -> dict | None:
    """
    CPE 2.3 formatını parse ederek Vendor ve Product bilgilerini çıkarır.
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


async def fetch_cve_details(cve_id: str) -> dict:
    """
    NIST NVD 2.0 API'sine istek atarak CVE detaylarını çeker ve parse eder.
    Dönen yapı:
    {
        "status": "success" | "error",
        "cve_id": str,
        "description": str,
        "cvss_score": float | None,
        "cvss_severity": str | None,
        "affected_assets": [{"vendor": str, "product": str}, ...],
        "references": [str, ...],
        "published": str | None,
        "error": str | None
    }
    """
    cve_pattern = r"^CVE-\d{4}-\d{4,}$"
    if not re.match(cve_pattern, cve_id, re.IGNORECASE):
        return {
            "status": "error",
            "cve_id": cve_id,
            "error": "Geçersiz CVE formatı."
        }

    headers = {"apiKey": NVD_API_KEY}

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                headers=headers
            )

            if resp.status_code == 403:
                return {
                    "status": "error",
                    "cve_id": cve_id,
                    "error": "NIST API rate limit'e takıldı. Lütfen birkaç saniye bekleyip tekrar deneyin."
                }

            if resp.status_code != 200:
                return {
                    "status": "error",
                    "cve_id": cve_id,
                    "error": f"NIST API Hatası: HTTP {resp.status_code}"
                }

            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if not vulnerabilities:
                return {
                    "status": "error",
                    "cve_id": cve_id,
                    "error": "Bu CVE numarası NIST veritabanında bulunamadı."
                }

            cve_data = vulnerabilities[0].get("cve", {})

            # ── Açıklama (İngilizce) ──────────────────────────
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description:
                descriptions = cve_data.get("descriptions", [])
                if descriptions:
                    description = descriptions[0].get("value", "Açıklama bulunamadı.")

            # ── CVSS Skoru ────────────────────────────────────
            cvss_score = None
            cvss_severity = None
            metrics = cve_data.get("metrics", {})

            # CVSS v3.1 → v3.0 → v2.0 sırasıyla dene
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity")
                    if not cvss_severity:
                        # v2 formatında severity farklı yerde olabilir
                        cvss_severity = metric_list[0].get("baseSeverity")
                    break

            # ── Etkilenen Varlıklar (CPE Parse) ───────────────
            affected_assets = []
            seen = set()
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        criteria = cpe_match.get("criteria", "")
                        parsed = _parse_cpe_label(criteria)
                        if parsed:
                            key = f"{parsed['vendor']}|{parsed['product']}"
                            if key not in seen:
                                seen.add(key)
                                affected_assets.append(parsed)

            # ── Referanslar (İlk 5 kaynak) ────────────────────
            references = []
            for ref in cve_data.get("references", [])[:5]:
                url = ref.get("url", "")
                if url:
                    references.append(url)

            # ── Yayınlanma Tarihi ─────────────────────────────
            published = cve_data.get("published", None)
            if published:
                published = published[:10]  # Sadece tarih kısmı (YYYY-MM-DD)

            return {
                "status": "success",
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "affected_assets": affected_assets,
                "references": references,
                "published": published
            }

    except httpx.TimeoutException:
        return {
            "status": "error",
            "cve_id": cve_id,
            "error": "NIST API isteği zaman aşımına uğradı. Sunucular meşgul olabilir."
        }
    except Exception as e:
        return {
            "status": "error",
            "cve_id": cve_id,
            "error": f"Beklenmeyen hata: {str(e)}"
        }
