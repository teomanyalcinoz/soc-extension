import os
import httpx
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────────────────
# Splunk REST API Yapılandırması (.env dosyasından okunur)
# ─────────────────────────────────────────────────────────────────
SPLUNK_URL = os.getenv("SPLUNK_URL", "").strip()
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "").strip()
SPLUNK_VERIFY_SSL = os.getenv("SPLUNK_VERIFY_SSL", "False").strip().lower() in ("true", "1", "yes")


def is_configured() -> bool:
    """Splunk REST API yapılandırmasının tamamlanıp tamamlanmadığını kontrol eder."""
    return bool(SPLUNK_URL) and bool(SPLUNK_TOKEN)


async def execute_spl_query(query: str) -> dict:
    """
    Verilen SPL sorgusunu Splunk REST API üzerinden çalıştırır.

    Splunk'un /services/search/jobs/export endpoint'ini kullanır (exec_mode=oneshot).
    Bu mod, sorguyu anında çalıştırıp sonuçları tek bir yanıtta döndürür.

    Returns:
        {
            "status": "success" | "not_configured" | "error",
            "message": str (opsiyonel, uyarı/hata mesajı),
            "results": list[dict] (sonuç satırları),
            "result_count": int
        }
    """

    # ── 1. Yapılandırma Kontrolü ──────────────────────────────────
    if not is_configured():
        return {
            "status": "not_configured",
            "message": (
                "Splunk REST API yapılandırması eksik. "
                "backend/.env dosyasında SPLUNK_URL ve SPLUNK_TOKEN değerlerini tanımlayın."
            ),
            "results": [],
            "result_count": 0
        }

    # ── 2. Splunk REST API İsteği ─────────────────────────────────
    # Oneshot export: sorguyu anında çalıştırır, sonuçları JSON döner.
    # Daha uzun sorgular için /services/search/jobs ile async job
    # oluşturulabilir ancak oneshot çoğu SIEM sorgusu için yeterlidir.
    export_url = f"{SPLUNK_URL.rstrip('/')}/services/search/jobs/export"

    params = {
        "search": query if query.strip().startswith("|") else f"search {query}",
        "output_mode": "json",
        "count": 100,          # Maksimum döndürülecek sonuç sayısı
        "earliest_time": "-30d@d",
        "latest_time": "now"
    }

    headers = {
        "Authorization": f"Bearer {SPLUNK_TOKEN}",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        async with httpx.AsyncClient(
            timeout=60.0,
            verify=SPLUNK_VERIFY_SSL
        ) as client:
            response = await client.post(
                export_url,
                data=params,
                headers=headers
            )

            # HTTP hata kontrolü
            if response.status_code == 401:
                return {
                    "status": "error",
                    "message": "Splunk kimlik doğrulaması başarısız. Token geçersiz veya süresi dolmuş olabilir.",
                    "results": [],
                    "result_count": 0
                }

            if response.status_code == 403:
                return {
                    "status": "error",
                    "message": "Splunk erişim yetkisi yok. Token'ın bu işlem için yetkilendirildiğinden emin olun.",
                    "results": [],
                    "result_count": 0
                }

            if response.status_code >= 400:
                return {
                    "status": "error",
                    "message": f"Splunk API hatası (HTTP {response.status_code}): {response.text[:300]}",
                    "results": [],
                    "result_count": 0
                }

            # ── 3. Yanıt İşleme ──────────────────────────────────
            # Splunk export endpoint'i her satırı ayrı JSON nesnesi olarak döner
            # (NDJSON formatı). Her satır {"result": {...}} yapısındadır.
            raw_text = response.text.strip()
            if not raw_text:
                return {
                    "status": "success",
                    "message": "Sorgu başarıyla çalıştırıldı ancak sonuç bulunamadı.",
                    "results": [],
                    "result_count": 0
                }

            import json

            results = []
            for line in raw_text.split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if "result" in obj:
                        results.append(obj["result"])
                except json.JSONDecodeError:
                    continue

            return {
                "status": "success",
                "message": f"{len(results)} sonuç bulundu.",
                "results": results,
                "result_count": len(results)
            }

    except httpx.ConnectError:
        return {
            "status": "error",
            "message": f"Splunk sunucusuna bağlanılamadı ({SPLUNK_URL}). URL doğruluğunu ve ağ erişimini kontrol edin.",
            "results": [],
            "result_count": 0
        }
    except httpx.TimeoutException:
        return {
            "status": "error",
            "message": "Splunk sorgusu zaman aşımına uğradı (60s). Sorguyu daraltmayı veya zaman aralığını kısaltmayı deneyin.",
            "results": [],
            "result_count": 0
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Beklenmeyen hata: {str(e)}",
            "results": [],
            "result_count": 0
        }
