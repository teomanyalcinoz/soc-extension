import os
import httpx
import asyncio
import json
from fastapi import HTTPException
from dotenv import load_dotenv

# .env dosyasını yükle
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
load_dotenv(dotenv_path=env_path)

XDR_BASE_URL = os.getenv("XDR_BASE_URL", "")
XDR_API_KEY_ID = os.getenv("XDR_API_KEY_ID", "")
XDR_API_KEY = os.getenv("XDR_API_KEY", "")

async def execute_xdr_query(query: str) -> dict:
    if not XDR_BASE_URL or not XDR_API_KEY_ID or not XDR_API_KEY:
        raise HTTPException(status_code=500, detail="Cortex XDR yapılandırması (.env) eksik.")

    headers = {
        "Authorization": XDR_API_KEY,
        "x-xdr-auth-id": XDR_API_KEY_ID,
        "Content-Type": "application/json"
    }

    start_url = f"{XDR_BASE_URL.rstrip('/')}/public_api/v1/xql/start_xql_query/"
    results_url = f"{XDR_BASE_URL.rstrip('/')}/public_api/v1/xql/get_query_results/"

    async with httpx.AsyncClient(verify=False) as client:
        # Adım 1: Sorguyu Başlat
        try:
            start_payload = {"request_data": {"query": query}}
            start_res = await client.post(start_url, headers=headers, json=start_payload, timeout=10.0)
            start_res.raise_for_status()
            start_data = start_res.json()
            
            job_id = start_data.get("reply")
            if not isinstance(job_id, str):
                job_id = start_data.get("reply", {}).get("job_id")
                
            if not job_id:
                raise Exception("XDR API'den job_id alınamadı.")
                
        except Exception as e:
            print(f"XDR Start Query Hatası: {e}")
            raise HTTPException(status_code=500, detail=f"XDR Sorgusu başlatılamadı: {str(e)}")

        # Adım 2: Sonuçları Bekle (Polling)
        max_retries = 15  # 15 * 2 = 30 saniye
        results_payload = {"request_data": {"query_id": job_id}}

        for attempt in range(max_retries):
            try:
                poll_res = await client.post(results_url, headers=headers, json=results_payload, timeout=10.0)
                poll_res.raise_for_status()
                poll_data = poll_res.json()
                
                status = poll_data.get("reply", {}).get("status", "")
                
                if status == "SUCCESS":
                    # results.data genelde dizi olarak döner
                    results_array = poll_data.get("reply", {}).get("results", {}).get("data", [])
                    
                    count = 0
                    has_count_field = False
                    for row in results_array:
                        if isinstance(row, dict) and "affected_hosts_count" in row:
                            has_count_field = True
                            try:
                                count += int(row["affected_hosts_count"])
                            except:
                                pass
                                
                    # Eğer affected_hosts_count field'ı yoksa fallback olarak array uzunluğunu kullan
                    if not has_count_field:
                        count = len(results_array)
                    return {
                        "status": "success",
                        "affected_hosts": count,
                        "raw_data": results_array
                    }
                elif status in ["PENDING", "RUNNING"]:
                    await asyncio.sleep(2)
                else:
                    # FAILED veya başka bir hata
                    raise Exception(f"Sorgu başarısız oldu. Durum: {status}")

            except Exception as e:
                print(f"XDR Polling Hatası: {e}")
                raise HTTPException(status_code=500, detail=f"XDR Sonuçları alınırken hata: {str(e)}")

        raise HTTPException(status_code=408, detail="XDR Sorgusu zaman aşımına uğradı (30 saniye).")
