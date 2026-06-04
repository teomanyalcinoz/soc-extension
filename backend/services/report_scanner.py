import json
import httpx
import re
import asyncio
from typing import Dict, Any

from services.intelligence import analyze_hash
from services.ip_intelligence import analyze_ip
from services.url_intelligence import analyze_url
from services.email_intelligence import analyze_email_all
from services.spl_intelligence import generate_spl_queries, generate_bulk_spl_queries

from services.llm_config import LLM_API_KEY, LLM_URL, get_llm_headers, build_llm_payload

def extract_iocs_regex(text: str) -> list:
    iocs = []
    
    # IPv4
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    for match in re.finditer(ip_pattern, text):
        iocs.append({"value": match.group(0), "type": "ipv4"})
        
    # MD5, SHA1, SHA256
    hash_pattern = r'\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b'
    for match in re.finditer(hash_pattern, text):
        iocs.append({"value": match.group(0), "type": "hash"})
        
    # Email
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    for match in re.finditer(email_pattern, text):
        iocs.append({"value": match.group(0), "type": "email"})
        
    # URL (Strict)
    url_pattern = r'\bhttps?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<"\']*)?'
    for match in re.finditer(url_pattern, text):
        iocs.append({"value": match.group(0), "type": "url"})
        
    return iocs

async def check_ioc_reputation(value: str, ioc_type: str) -> Dict[str, Any]:
    try:
        if ioc_type == "ipv4":
            res = await analyze_ip(value)
        elif ioc_type == "hash":
            res = await analyze_hash(value)
        elif ioc_type == "url":
            res = await analyze_url(value)
        elif ioc_type == "email":
            res_list = await analyze_email_all(value)
            res = {"results": res_list}
        else:
            res = {"results": []}
        return res
    except Exception as e:
        return {"error": str(e), "results": []}

async def enrich_ioc(ioc: dict) -> dict:
    val = ioc.get("value", "").strip()
    itype = ioc.get("type", "").strip().lower()
    
    if not val or not itype:
        return ioc
        
    rep_task = check_ioc_reputation(val, itype)
    rep_res = await rep_task
    osint_list = rep_res.get("results", [])
    
    spl_res = await generate_spl_queries(ioc_value=val, ioc_type=itype, osint_results=osint_list)
    
    malicious_count = 0
    suspicious_count = 0
    
    for r in osint_list:
        src = r.get("source", "")
        data = r.get("data", {})
        if not isinstance(data, dict):
            continue
            
        if "VirusTotal" in src:
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count += stats.get("malicious", 0)
            suspicious_count += stats.get("suspicious", 0)
        elif "AbuseIPDB" in src:
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            if score > 50:
                malicious_count += 1
            elif score > 10:
                suspicious_count += 1
        elif "AlienVault" in src:
            pulses = data.get("pulse_info", {}).get("count", 0)
            if pulses > 0:
                suspicious_count += 1
        elif "Sucuri" in src:
            blacklists = data.get("blacklists", [])
            if isinstance(blacklists, list) and any(b.get("is_blacklisted") for b in blacklists):
                malicious_count += 1
                
    if malicious_count > 0:
        status = "Malicious"
        risk_score = min(10, 5 + malicious_count)
    elif suspicious_count > 0:
        status = "Suspicious"
        risk_score = min(7, 3 + suspicious_count)
    else:
        status = "Clean"
        risk_score = 0
        
    return {
        "value": val,
        "type": itype,
        "status": status,
        "risk_score": risk_score,
        "reputation": rep_res,
        "spl_queries": spl_res
    }

async def analyze_report_text(text: str, url: str) -> Dict[str, Any]:
    if not LLM_API_KEY:
        return {"status": "error", "message": "LLM_API_KEY ayarlanmamış."}
        
    # Sınırlandırma: Token limitini aşmamak için ilk 15000 karakter
    text_sample = text[:15000]
    
    prompt = f"""Bir L3 SOC Analisti olarak aşağıdaki tehdit istihbaratı raporunu (veya web sayfasını) incele. Raporun alındığı URL: {url}

Lütfen analiz sonucunu SADECE aşağıdaki formattaki gibi geçerli bir JSON objesi olarak dön (markdown kullanmadan, doğrudan JSON):

{{
  "summary": "Raporun Türkçe olarak kısa ve vurucu özeti (3-4 cümle). Hedeflenen zafiyet veya zararlı yazılım ailesi, saldırı vektörü belirtilmelidir.",
  "iocs": [
    {{ "value": "1.1.1.1", "type": "ipv4" }},
    {{ "value": "evil.com", "type": "url" }},
    {{ "value": "8508e67a989ef32a8de5b1a038d1d86d", "type": "hash" }},
    {{ "value": "hacker@example.com", "type": "email" }}
  ]
}}

Desteklenen IOC tipleri SADECE şunlardır: "ipv4", "url", "hash", "email". Başka tip uydurma.
IOC bulamazsan "iocs" dizisini boş bırak.

Rapor Metni:
{text_sample}
"""

    try:
        headers = get_llm_headers()
        messages = [
            {"role": "system", "content": "You are a senior SOC analyst. You only output valid JSON matching the exact schema requested, with no extra text."},
            {"role": "user", "content": prompt}
        ]
        payload = build_llm_payload(messages=messages, temperature=0.1, max_tokens=1500)
        
        async with httpx.AsyncClient(timeout=90.0) as client:
            response = await client.post(LLM_URL, headers=headers, json=payload)
            response.raise_for_status()
            response_data = response.json()
            content = response_data["choices"][0]["message"]["content"].strip()
            
            # Markdown block temizliği
            match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", content)
            if match:
                content = match.group(1).strip()
                
            try:
                parsed_json = json.loads(content)
            except json.JSONDecodeError:
                return {"status": "error", "message": "LLM çıktısı geçerli bir JSON değil.", "raw_output": content}
                
            summary = parsed_json.get("summary", "Özet çıkarılamadı.")
            raw_iocs = parsed_json.get("iocs", [])
            
            # Tüm metin üzerinde Regex taraması yaparak LLM'in kaçırdıklarını ekle
            regex_iocs = extract_iocs_regex(text)
            raw_iocs.extend(regex_iocs)
            
            # IOC listesini temizle ve benzersiz hale getir
            unique_iocs = {}
            for ioc in raw_iocs:
                val = ioc.get("value", "").strip()
                itype = ioc.get("type", "").strip().lower()
                if val and itype in ["ipv4", "url", "hash", "email"]:
                    unique_iocs[val] = {"value": val, "type": itype}
                    
            ioc_list = list(unique_iocs.values())
            
            # 1. Repütasyon aşaması IPTAL. IOC'leri tiplerine göre grupla
            grouped_dict = {}
            for ioc in ioc_list:
                itype = ioc["type"]
                if itype not in grouped_dict:
                    grouped_dict[itype] = []
                grouped_dict[itype].append(ioc["value"])
                
            grouped_iocs = []
            
            # 2. Sadece gruplanmış değerleri dön (SPL sorguları frontend tarafından on-demand istenecek)
            for ioc_type, values in grouped_dict.items():
                grouped_iocs.append({
                    "type": ioc_type,
                    "count": len(values),
                    "values": values
                })
                
            return {
                "status": "success",
                "summary": summary,
                "total_iocs_found": len(ioc_list),
                "grouped_iocs": grouped_iocs
            }
            
    except Exception as e:
        return {"status": "error", "message": f"LLM bağlantısında veya analiz sırasında hata: {str(e)}"}
