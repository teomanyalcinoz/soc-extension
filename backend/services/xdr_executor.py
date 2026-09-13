"""
TracePoint v2.5 — Cortex XDR Sorgu Çalıştırıcı
İki aşamalı XQL API: sorgu başlat → polling ile sonuç al.
Kimlik bilgileri .env'den okunur; eksikse graceful "not_configured" döner.
"""
import os
import httpx
import asyncio
import json
import logging

from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

logger = logging.getLogger(__name__)

XDR_BASE_URL    = os.getenv("XDR_BASE_URL", "").strip()
XDR_API_KEY_ID  = os.getenv("XDR_API_KEY_ID", "").strip()
XDR_API_KEY     = os.getenv("XDR_API_KEY", "").strip()
_XDR_VERIFY_SSL = os.getenv("XDR_VERIFY_SSL", "true").lower() in ("true", "1", "yes")


def _is_configured() -> bool:
    return bool(XDR_BASE_URL and XDR_API_KEY_ID and XDR_API_KEY)


async def execute_xdr_query(query: str) -> dict:
    """
    Cortex XDR üzerinde XQL sorgusu çalıştırır.
    XDR parametreleri .env'de tanımlı değilse, HTTP exception fırlatmak yerine
    graceful bir 'not_configured' yanıtı döner.

    Returns:
        {
            "status": "success" | "not_configured" | "error",
            "affected_hosts": int,
            "raw_data": list,
            "message": str (opsiyonel)
        }
    """
    if not _is_configured():
        logger.info("XDR yapılandırması eksik — not_configured döndürülüyor.")
        return {
            "status": "not_configured",
            "message": (
                "Cortex XDR yapılandırması eksik. "
                "backend/.env dosyasında XDR_BASE_URL, XDR_API_KEY_ID ve XDR_API_KEY değerlerini tanımlayın."
            ),
            "affected_hosts": 0,
            "raw_data": [],
        }

    headers = {
        "Authorization": XDR_API_KEY,
        "x-xdr-auth-id": XDR_API_KEY_ID,
        "Content-Type": "application/json",
    }

    start_url   = f"{XDR_BASE_URL.rstrip('/')}/public_api/v1/xql/start_xql_query/"
    results_url = f"{XDR_BASE_URL.rstrip('/')}/public_api/v1/xql/get_query_results/"

    try:
        async with httpx.AsyncClient(verify=_XDR_VERIFY_SSL, timeout=60.0) as client:
            # ── Adım 1: Sorguyu başlat ────────────────────────────
            start_payload = {"request_data": {"query": query}}
            start_res = await client.post(start_url, headers=headers, json=start_payload, timeout=10.0)

            if start_res.status_code in (401, 403):
                return {
                    "status": "error",
                    "message": f"XDR kimlik doğrulaması başarısız (HTTP {start_res.status_code}).",
                    "affected_hosts": 0,
                    "raw_data": [],
                }

            start_res.raise_for_status()
            start_data = start_res.json()

            reply = start_data.get("reply")
            job_id = reply if isinstance(reply, str) else (reply or {}).get("job_id")

            if not job_id:
                return {
                    "status": "error",
                    "message": "XDR API'den job_id alınamadı.",
                    "affected_hosts": 0,
                    "raw_data": [],
                }

            logger.debug("XDR sorgusu başlatıldı: job_id=%s", job_id)

            # ── Adım 2: Polling (max 30 saniye) ──────────────────
            results_payload = {"request_data": {"query_id": job_id}}
            for attempt in range(15):
                await asyncio.sleep(2)
                poll_res = await client.post(results_url, headers=headers, json=results_payload, timeout=10.0)
                poll_res.raise_for_status()
                poll_data = poll_res.json()

                reply_data = poll_data.get("reply", {})
                status = reply_data.get("status", "")

                if status == "SUCCESS":
                    results_array = reply_data.get("results", {}).get("data", [])

                    # affected_hosts_count field varsa topla, yoksa satır sayısını kullan
                    count = 0
                    has_field = False
                    for row in results_array:
                        if isinstance(row, dict) and "affected_hosts_count" in row:
                            has_field = True
                            try:
                                count += int(row["affected_hosts_count"])
                            except (ValueError, TypeError):
                                pass
                    if not has_field:
                        count = len(results_array)

                    logger.info("XDR sorgusu tamamlandı: %d satır, %d etkilenen host", len(results_array), count)
                    return {
                        "status": "success",
                        "affected_hosts": count,
                        "raw_data": results_array,
                        "message": f"{len(results_array)} sonuç bulundu.",
                    }

                elif status in ("PENDING", "RUNNING"):
                    logger.debug("XDR polling (%d/15): status=%s", attempt + 1, status)
                    continue
                else:
                    return {
                        "status": "error",
                        "message": f"XDR sorgusu başarısız. Durum: {status}",
                        "affected_hosts": 0,
                        "raw_data": [],
                    }

            return {
                "status": "error",
                "message": "XDR sorgusu zaman aşımına uğradı (30 saniye).",
                "affected_hosts": 0,
                "raw_data": [],
            }

    except httpx.ConnectError as e:
        logger.error("XDR bağlantı hatası: %s", e)
        return {"status": "error", "message": f"XDR sunucusuna bağlanılamadı: {e}", "affected_hosts": 0, "raw_data": []}
    except httpx.TimeoutException:
        logger.error("XDR zaman aşımı")
        return {"status": "error", "message": "XDR isteği zaman aşımına uğradı.", "affected_hosts": 0, "raw_data": []}
    except Exception as e:
        logger.error("XDR beklenmeyen hata: %s", e)
        return {"status": "error", "message": f"Beklenmeyen hata: {str(e)}", "affected_hosts": 0, "raw_data": []}
