import json
import httpx

from services.llm_config import LLM_API_KEY, LLM_URL, LLM_VERIFY_SSL, get_llm_headers, build_llm_payload

async def generate_summary(target: str, target_type: str, intelligence_results: list) -> str:
    """
    Tehdit istihbaratından dönen sonuçları json string olarak LLM'e verir,
    sadece 2-3 cümlelik maksimum net bir özet döndürmesini ister.
    """
    
    if not LLM_API_KEY:
        return "Yapay Zeka analizi için LLM_API_KEY ayarlanmamış."
        
    # Tüm veriyi LLM'e göndermek response'u yavaşlatıp hata verdirebilir,
    # Sadece en önemli metrikleri süzerek LLM'e küçük bir payload (vektör) gönderelim.
    filtered_results = []
    for r in intelligence_results:
        if isinstance(r, dict) and r.get("success"):
            src = r.get("source")
            raw_data = r.get("data")
            data = raw_data if isinstance(raw_data, dict) else {}
            
            summary_dict = {"source": src}
            # Kaynağa özel verileri topla
            if "AlienVault" in src:
                summary_dict["pulses"] = data.get("pulse_info", {}).get("count", 0)
                summary_dict["tags"] = data.get("pulse_info", {}).get("pulses", [{}])[0].get("tags", [])[:3] if data.get("pulse_info", {}).get("pulses") else []
            elif "VirusTotal" in src:
                vt_data = data.get("data")
                stats = {}
                if isinstance(vt_data, list) and len(vt_data) > 0:
                    stats = vt_data[0].get("attributes", {}).get("last_analysis_stats", {})
                elif isinstance(vt_data, dict):
                    stats = vt_data.get("attributes", {}).get("last_analysis_stats", {})
                    
                summary_dict["malicious_hits"] = stats.get("malicious", 0)
                summary_dict["suspicious_hits"] = stats.get("suspicious", 0)
            elif "MalwareBazaar" in src:
                summary_dict["status"] = data.get("query_status", "unknown")
            elif "AbuseIPDB" in src:
                summary_dict["abuse_confidence_score"] = data.get("data", {}).get("abuseConfidenceScore", 0)
                summary_dict["total_reports"] = data.get("data", {}).get("totalReports", 0)
            elif "URLhaus" in src:
                summary_dict["url_status"] = data.get("url_status", "unknown")
                summary_dict["threat"] = data.get("threat", "unknown")
            elif "Sucuri" in src:
                blacklists = data.get("blacklists", [])
                summary_dict["blacklisted"] = any(b.get("is_blacklisted") for b in blacklists) if isinstance(blacklists, list) else False
                warnings = data.get("warnings", [])
                summary_dict["warning_count"] = len(warnings) if isinstance(warnings, list) else 0
            elif "urlscan.io" in src:
                summary_dict["historical_scans_found"] = data.get("total", 0)
            elif "USOM" in src:
                summary_dict["usom_blacklist_hits"] = data.get("totalCount", 0)
            elif "AbstractAPI" in src:
                summary_dict["deliverability"] = data.get("deliverability", "UNKNOWN")
                summary_dict["quality_score"] = round(float(data.get("quality_score") or 0), 2)
                summary_dict["is_disposable"] = data.get("is_disposable_email", {}).get("value", False) if isinstance(data.get("is_disposable_email"), dict) else bool(data.get("is_disposable_email", False))
                summary_dict["mx_records"] = data.get("mx_records", False)
            elif "emailrep.io" in src:
                summary_dict["reputation"] = data.get("reputation", "unknown")
                summary_dict["suspicious"] = data.get("suspicious", False)
            elif "HaveIBeenPwned" in src:
                summary_dict["breached"] = r.get("breached", False)
                data_list = r.get("data", [])
                summary_dict["breach_count"] = len(data_list) if isinstance(data_list, list) else 0
            elif "Spamhaus" in src:
                summary_dict["domain_blacklisted"] = data.get("domain_blacklisted", False)
                summary_dict["dbl_listed"] = data.get("dbl_listed", False)
            elif "MX" in src or "DNS" in src:
                summary_dict["domain_resolves"] = data.get("domain_resolves", False)
                summary_dict["mx_valid"] = data.get("mx_valid", False)
                
            filtered_results.append(summary_dict)

    llm_context = json.dumps(filtered_results)
    
    prompt = f"""Bir L3 SOC Analisti olarak şu teknik verileri analiz et: {llm_context}. Hedef: {target} ({target_type}).
SADECE HTML formatında, kısa ve öz bir analiz raporu sun.

<div style='margin-bottom:8px;'><strong>Risk Skoru:</strong> <span style='color:[skor_renk];'>[Skor]/10</span></div>
<div style='margin-bottom:12px;'>[Vurucu analiz özeti - max 2 cümle]</div>
<strong>Acil Aksiyonlar:</strong>
<ul style='margin-top:4px; padding-left:20px;'>
    <li>[Aksiyon 1]</li>
    <li>[Aksiyon 2]</li>
</ul>
<div style='margin-top:12px; border-left:3px solid #6366f1; padding:8px; background:rgba(99,102,241,0.1);'>
    <strong>🧠 AI Tahmini</strong>
    <p style='font-size:12px;'>[Olası sonraki adım ve izlenecek Event ID/Log]</p>
</div>"""
    
    try:
        headers = get_llm_headers()
        messages = [
            {"role": "system", "content": "You are a senior SOC analyst. Provide very concise, technical HTML summaries. No talk, just code."},
            {"role": "user", "content": prompt}
        ]
        payload = build_llm_payload(messages=messages, temperature=0.3, max_tokens=300)
        
        async with httpx.AsyncClient(timeout=45.0, verify=LLM_VERIFY_SSL) as client:
            response = await client.post(LLM_URL, headers=headers, json=payload)
            response.raise_for_status()
            response_data = response.json()
            return response_data["choices"][0]["message"]["content"].strip()
            
    except Exception as e:
        return f"Model bağlantısında hata: LLM entegrasyonu başarısız oldu ({str(e)})."
