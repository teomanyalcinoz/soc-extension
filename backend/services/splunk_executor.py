import os
import httpx
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────────────────
# Splunk REST API Yapılandırması (.env dosyasından dinamik okunur)
# ─────────────────────────────────────────────────────────────────
def get_splunk_config():
    load_dotenv(override=True)
    url = os.getenv("SPLUNK_URL", "").strip()
    token = os.getenv("SPLUNK_TOKEN", "").strip()
    verify_ssl = os.getenv("SPLUNK_VERIFY_SSL", "False").strip().lower() in ("true", "1", "yes")
    web_url = os.getenv("SPLUNK_WEB_URL", "https://splunk.kuveytturk.com.tr").strip().rstrip('/')
    if url and not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"
    if web_url and not web_url.startswith("http://") and not web_url.startswith("https://"):
        web_url = f"https://{web_url}"
    return url, token, verify_ssl, web_url


def is_configured() -> bool:
    """Splunk REST API yapılandırmasının tamamlanıp tamamlanmadığını kontrol eder."""
    url, token, _, _ = get_splunk_config()
    return bool(url) and bool(token)


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
    url, token, verify_ssl, web_url = get_splunk_config()
    if not (url and token):
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
    export_url = f"{url.rstrip('/')}/services/search/jobs/export"

    q = query.strip()
    if not q.startswith("|") and not q.lower().startswith("search "):
        q = f"search {q}"

    params = {
        "search": q,
        "output_mode": "json",
        "count": 100,          # Maksimum döndürülecek sonuç sayısı
        "adhoc_search_level": "fast",  # Fast Mode: Alan keşfini atlar, 10x-50x hızlandırır
    }

    auth_header = token if (token.startswith("Bearer ") or token.startswith("Splunk ")) else f"Bearer {token}"
    headers = {
        "Authorization": auth_header,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        timeout_config = httpx.Timeout(connect=8.0, read=90.0, write=10.0, pool=5.0)
        async with httpx.AsyncClient(
            timeout=timeout_config,
            verify=verify_ssl
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

            import urllib.parse
            encoded_q = urllib.parse.quote(q)
            splunk_web_link = f"{web_url}/en-US/app/search/search?q={encoded_q}"
            return {
                "status": "success",
                "message": f"{len(results)} sonuç bulundu.",
                "results": results,
                "result_count": len(results),
                "splunk_web_url": splunk_web_link,
                "query": q
            }

    except (httpx.ConnectError, httpx.ConnectTimeout):
        return {
            "status": "error",
            "message": f"Splunk sunucusuna bağlanılamadı ({url}). Kurumsal iç ağa veya VPN'e bağlı olduğunuzdan emin olun.",
            "results": [],
            "result_count": 0
        }
    except (httpx.ReadTimeout, httpx.TimeoutException):
        return {
            "status": "error",
            "message": "Splunk sorgusu zaman aşımına uğradı. Büyük log indekslerinde zaman aralığını (örn: earliest=-24h veya -7d) daraltmayı deneyin.",
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
