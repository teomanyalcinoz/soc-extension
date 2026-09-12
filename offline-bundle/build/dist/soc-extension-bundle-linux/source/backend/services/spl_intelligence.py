import json
import httpx
import hashlib
import re

from services.llm_config import LLM_API_KEY, LLM_URL, get_llm_headers, build_llm_payload

# ─────────────────────────────────────────────────────────────────
# Kurum Ortamı: Splunk Index Tanımları
# ─────────────────────────────────────────────────────────────────
INDEXES = {
    "panos": {
        "label": "Firewall (Palo Alto)",
        "color": "#f97316",
        "fields": {
            "src_ip": "Kaynak IP adresi",
            "dst_ip": "Hedef IP adresi",
            "src_port": "Kaynak port",
            "dst_port": "Hedef port",
            "app": "Uygulama adı (Palo Alto tarafından tespit edilen)",
            "action": "Firewall aksiyonu (allow/deny/drop)",
            "bytes_out": "Giden veri miktarı (byte)",
            "bytes_in": "Gelen veri miktarı (byte)",
            "rule_name": "Uygulanan firewall kuralı",
            "src_zone": "Kaynak güvenlik bölgesi",
            "dst_zone": "Hedef güvenlik bölgesi",
        }
    },
    "bluecoat": {
        "label": "Proxy (Blue Coat)",
        "color": "#3b82f6",
        "fields": {
            "c-ip": "İstemci IP adresi",
            "cs-host": "İstenen host / domain",
            "cs-uri-stem": "İstenen URI yolu",
            "cs-uri-query": "URI sorgu parametreleri",
            "sc-status": "HTTP durum kodu",
            "cs-username": "Kullanıcı adı",
            "cs-method": "HTTP metodu (GET/POST vb.)",
            "cs-bytes": "İstek boyutu (byte)",
            "sc-bytes": "Yanıt boyutu (byte)",
            "s-ip": "Proxy sunucu IP'si",
            "cs-user-agent": "Kullanıcı tarayıcı/istemci bilgisi",
            "cs-categories": "URL kategorisi (Proxy sınıflandırması)",
        }
    },
    "wineventlog": {
        "label": "Windows / Sysmon / PowerShell",
        "color": "#8b5cf6",
        "fields": {
            "EventID": "Windows Event ID (4688=Süreç, 4103/4104=PowerShell, 1=Sysmon Süreç, 3=Ağ, 7=DLL)",
            "ComputerName": "Kaynak makine adı",
            "User": "İşlemi başlatan kullanıcı",
            "Image": "Çalıştırılan process yolu",
            "CommandLine": "Komut satırı argümanları",
            "ParentImage": "Üst süreç yolu",
            "ParentCommandLine": "Üst süreç komut satırı",
            "Hashes": "Süreç dosyası hash değerleri (MD5, SHA256)",
            "DestinationIp": "Bağlanılan hedef IP (Sysmon EventID 3)",
            "DestinationPort": "Hedef port",
            "TargetFilename": "Oluşturulan/değiştirilen dosya yolu (EventID 11)",
            "ScriptBlockText": "PowerShell betik içeriği (EventID 4104)",
        }
    },
    "fortimail": {
        "label": "Mail Güvenlik (FortiMail)",
        "color": "#10b981",
        "fields": {
            "sender": "Gönderen e-posta adresi",
            "recipient": "Alıcı e-posta adresi",
            "subject": "E-posta konusu",
            "attachment": "Ek dosya adı",
            "action": "FortiMail aksiyonu (accept/reject/quarantine)",
            "virus": "Tespit edilen virüs adı",
            "src_ip": "Gönderen sunucu IP adresi",
            "spam_score": "Spam skoru",
            "policy": "Uygulanan mail politikası",
        }
    },
    "f5": {
        "label": "WAF (F5 BIG-IP)",
        "color": "#ef4444",
        "fields": {
            "src_ip": "Saldırı kaynak IP",
            "uri": "İstenen URI",
            "request": "Ham HTTP isteği",
            "response_code": "HTTP yanıt kodu",
            "attack_type": "Saldırı türü (SQLi, XSS, CSRF vb.)",
            "severity": "Tehdit seviyesi (Critical/High/Medium/Low)",
            "policy_name": "Uygulanan WAF politikası",
            "method": "HTTP metodu",
            "x_forwarded_for": "Gerçek istemci IP (proxy arkasında)",
        }
    }
}

# IOC tipine göre ilgili indexleri döner
IOC_INDEX_MAP = {
    "ipv4":       ["panos", "bluecoat", "wineventlog", "f5"],
    "hash":       ["wineventlog"],
    "url":        ["panos", "bluecoat", "f5", "fortimail"],
    "email":      ["fortimail", "wineventlog"],
    "powershell": ["wineventlog"],
}

# ─────────────────────────────────────────────────────────────────
# SPL Kuralları Sistem Promptu (Splunk Cheat Sheet'ten)
# ─────────────────────────────────────────────────────────────────
SPL_RULES_SYSTEM_PROMPT = """
Sen Kuveyt Türk SOME'de çalışan bir L3 SOC Analisti ve Splunk SPL uzmanısın.
Görevin, verilen IOC değeri ve OSINT bağlamı için Splunk SPL sorguları üretmek.

## SPL YAZIM KURALLARI (Bunlara KESINLIKLE uy):

1. **Index her zaman ilk filtre**: Performans için `index=<indexname>` her zaman en başta yaz
2. **Zaman aralığı**: `earliest=-30d@d latest=now` kullan (varsayılan 30 gün)
3. **Kesin eşleme**: IP, hash, domain gibi değerler tırnak içinde yazılır: `src_ip="1.2.3.4"`
4. **Joker dikkatli**: Wildcard (`*`) kullanımını minimize et, sadece gerektiğinde
5. **IN operatörü**: Birden fazla değer için `field IN ("val1", "val2")` kullan (Splunk 7.2+)
6. **stats count**: Gruplama için `| stats count by field1, field2`
7. **table**: Sadece gerekli alanları göster: `| table _time, field1, field2`
8. **sort**: `| sort -_time` ile en yeni önce
9. **dedup**: Tekrar eden kayıtları temizle: `| dedup src_ip, dst_ip`
10. **where threshold**: Anlamlı filtreleme için `| where count > 1`
11. **Büyük/küçük harf**: SPL komutları (index, stats, table, sort) küçük harf
12. **Pipeline zinciri**: Her komut yeni satırda `|` ile başlar (okunabilirlik)
13. **Hash araması**: Sysmon'da `Hashes` alanı `MD5=<hash>,SHA256=<hash>` formatındadır, wildcard kullan: `Hashes="*<HASHVALUE>*"`
14. **EventID bazlı**: Windows loglarında her zaman EventID ile başla

## ÇIKTI FORMATI:
Sadece JSON array döndür, başka hiçbir açıklama, markdown veya kod bloğu ekleme.
Format:
[
  {
    "index": "panos",
    "label": "Firewall (Palo Alto)",
    "color": "#f97316",
    "description": "Bu sorgunun Türkçe açıklaması (1 cümle)",
    "query": "Tam SPL sorgusu buraya"
  }
]
"""

# ─────────────────────────────────────────────────────────────────
# OSINT Bağlamını özetle (LLM'e küçük payload gönder)
# ─────────────────────────────────────────────────────────────────
def _summarize_osint(osint_results: list) -> str:
    """OSINT sonuçlarından kısa bir bağlam özeti oluşturur."""
    if not osint_results:
        return "OSINT verisi mevcut değil."
    
    summary_parts = []
    for r in osint_results:
        if not isinstance(r, dict):
            continue
        src = r.get("source", "Bilinmiyor")
        success = r.get("success", False)
        if not success:
            continue
        data = r.get("data", {})
        if not isinstance(data, dict):
            continue
        
        # Her kaynaktan en kritik veriyi çıkar
        if "AbuseIPDB" in src:
            score = data.get("data", {}).get("abuseConfidenceScore", 0)
            reports = data.get("data", {}).get("totalReports", 0)
            summary_parts.append(f"AbuseIPDB: {score}% kötüye kullanım skoru, {reports} rapor")
        elif "VirusTotal" in src:
            vt_data = data.get("data", {})
            if isinstance(vt_data, dict):
                stats = vt_data.get("attributes", {}).get("last_analysis_stats", {})
                mal = stats.get("malicious", 0)
                summary_parts.append(f"VirusTotal: {mal} motor tarafından zararlı işaretlendi")
        elif "AlienVault" in src:
            pulses = data.get("pulse_info", {}).get("count", 0)
            summary_parts.append(f"AlienVault OTX: {pulses} tehdit pulse'u")
        elif "MalwareBazaar" in src:
            status = data.get("query_status", "")
            if status == "ok":
                summary_parts.append("MalwareBazaar: Zararlı yazılım veritabanında bulundu")
        elif "URLhaus" in src:
            url_status = data.get("url_status", "")
            threat = data.get("threat", "")
            if url_status:
                summary_parts.append(f"URLhaus: Durum={url_status}, Tehdit={threat}")
        elif "USOM" in src:
            total = data.get("totalCount", 0)
            if total > 0:
                summary_parts.append(f"USOM: Türkiye ulusal kara listesinde {total} kayıt")
    
    return "; ".join(summary_parts) if summary_parts else "Önemli OSINT bulgusu tespit edilmedi."


# ─────────────────────────────────────────────────────────────────
# Ana SPL Üretim Fonksiyonu
# ─────────────────────────────────────────────────────────────────
async def generate_spl_queries(
    ioc_value: str,
    ioc_type: str,
    osint_results: list
) -> list:
    """
    IOC tipi ve OSINT bağlamına göre kurum ortamına özgü SPL sorguları üretir.
    Returns: [{"index": str, "label": str, "color": str, "description": str, "query": str}, ...]
    """
    
    # Bu IOC tipi için alakalı indexleri belirle
    relevant_index_keys = IOC_INDEX_MAP.get(ioc_type, [])
    if not relevant_index_keys:
        return []
    
    # Ilgili index bilgilerini derle
    index_context_parts = []
    for key in relevant_index_keys:
        info = INDEXES.get(key, {})
        fields_str = ", ".join([f"`{f}` ({desc})" for f, desc in info.get("fields", {}).items()])
        index_context_parts.append(
            f"**{key}** ({info.get('label', key)}):\n  Alanlar: {fields_str}"
        )
    index_context = "\n\n".join(index_context_parts)
    
    # OSINT özetini oluştur
    osint_context = _summarize_osint(osint_results)
    
    # IOC tipine göre Türkçe açıklama
    ioc_type_labels = {
        "ipv4": "IPv4 Adresi",
        "hash": "Dosya Hash (MD5/SHA1/SHA256)",
        "url": "URL / Domain",
        "email": "E-Posta Adresi",
        "powershell": "PowerShell Betiği"
    }
    ioc_label = ioc_type_labels.get(ioc_type, ioc_type.upper())
    
    # User prompt oluştur
    user_prompt = f"""IOC Değeri: {ioc_value}
IOC Tipi: {ioc_label}

OSINT Bağlamı: {osint_context}

Aşağıdaki Splunk indexleri için SPL sorguları üret. Her index için 1 adet, amaca yönelik ve çalıştırılabilir sorgu yaz.

Kullanılacak Indexler ve Alan Bilgileri:
{index_context}

Önemli: 
- Her sorgu doğrudan Splunk'a kopyalanıp çalıştırılabilir olmalı
- IOC değerini ({ioc_value}) sorgulara doğru biçimde ekle
- OSINT bulgularındaki risk seviyesine göre sorguyu şekillendir (yüksek riskli ise daha geniş araştır)
- Sonuçları JSON array olarak döndür, başka hiçbir şey yazma"""

    try:
        headers = get_llm_headers()
        messages = [
            {"role": "system", "content": SPL_RULES_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ]
        payload = build_llm_payload(messages=messages, temperature=0.1, max_tokens=2000)
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(LLM_URL, headers=headers, json=payload)
            response.raise_for_status()
            response_data = response.json()
            raw_content = response_data["choices"][0]["message"]["content"].strip()
        
        # Markdown kod bloğu temizleme
        raw_content = raw_content.replace("```json", "").replace("```", "").strip()
        
        # JSON parse
        queries = json.loads(raw_content)
        
        # Her sorguya index renk/label bilgisini ekle (LLM eksik bırakabilir)
        for q in queries:
            idx_key = q.get("index", "")
            if idx_key in INDEXES:
                q.setdefault("label", INDEXES[idx_key]["label"])
                q.setdefault("color", INDEXES[idx_key]["color"])
        
        return queries
        
    except json.JSONDecodeError:
        # LLM beklenen JSON formatında dönmediyse fallback sorgular üret
        return _generate_fallback_spl(ioc_value, ioc_type, relevant_index_keys)
    except Exception as e:
        return _generate_fallback_spl(ioc_value, ioc_type, relevant_index_keys, error=str(e))


# ─────────────────────────────────────────────────────────────────
# LLM Erişilemediğinde Statik Fallback SPL Üretici
# ─────────────────────────────────────────────────────────────────
def _generate_fallback_spl(
    ioc_value: str,
    ioc_type: str,
    index_keys: list,
    error: str = None
) -> list:
    """
    LLM kullanılamadığında önceden tanımlanmış şablonlardan SPL üretir.
    """
    val = ioc_value.replace('"', '\\"')  # Güvenli escape
    queries = []

    for idx in index_keys:
        info = INDEXES.get(idx, {})
        label = info.get("label", idx)
        color = info.get("color", "#64748b")
        query = ""
        description = ""

        if ioc_type == "ipv4":
            if idx == "panos":
                description = "Palo Alto Firewall'da kaynak ve hedef IP bazlı trafik analizi"
                query = (
                    f'index=panos earliest=-30d@d latest=now (src_ip="{val}" OR dst_ip="{val}")\n'
                    f'| stats count by src_ip, dst_ip, app, action, rule_name\n'
                    f'| sort -count'
                )
            elif idx == "bluecoat":
                description = "Blue Coat Proxy üzerinden bu IP'ye yapılan web istekleri"
                query = (
                    f'index=bluecoat earliest=-30d@d latest=now c-ip="{val}"\n'
                    f'| stats count by cs-host, sc-status, cs-username\n'
                    f'| sort -count\n'
                    f'| table cs-username, cs-host, sc-status, count'
                )
            elif idx == "wineventlog":
                description = "Sysmon ağ bağlantısı loglarında bu IP ile iletişim (EventID 3)"
                query = (
                    f'index=wineventlog earliest=-30d@d latest=now EventID=3 DestinationIp="{val}"\n'
                    f'| stats count by ComputerName, User, Image, DestinationPort\n'
                    f'| sort -count'
                )
            elif idx == "f5":
                description = "F5 WAF'ta bu IP'den gelen saldırı girişimleri"
                query = (
                    f'index=f5 earliest=-30d@d latest=now src_ip="{val}"\n'
                    f'| stats count by attack_type, uri, response_code, severity\n'
                    f'| sort -count'
                )

        elif ioc_type == "hash":
            if idx == "wineventlog":
                description = "Sysmon Process Create loglarında bu hash değerine sahip süreç tespiti"
                query = (
                    f'index=wineventlog earliest=-30d@d latest=now EventID=1 Hashes="*{val}*"\n'
                    f'| table _time, ComputerName, User, Image, CommandLine, ParentCommandLine, ParentImage\n'
                    f'| sort -_time'
                )

        elif ioc_type == "url":
            # URL'den domain ayıkla
            domain = val
            for prefix in ["https://", "http://", "www."]:
                if domain.startswith(prefix):
                    domain = domain[len(prefix):]
            domain = domain.split("/")[0].split(":")[0]

            if idx == "panos":
                description = f"Palo Alto Firewall'da {domain} adresine yapılan bağlantılar"
                query = (
                    f'index=panos earliest=-30d@d latest=now cs-host="*{domain}*"\n'
                    f'| stats count by src_ip, dst_ip, app, action\n'
                    f'| sort -count'
                )
            elif idx == "bluecoat":
                description = f"Blue Coat Proxy üzerinden {domain} adresine yapılan web istekleri"
                query = (
                    f'index=bluecoat earliest=-30d@d latest=now cs-host="*{domain}*"\n'
                    f'| stats count by c-ip, cs-uri-stem, sc-status, cs-username\n'
                    f'| sort -count\n'
                    f'| table c-ip, cs-username, cs-host, cs-uri-stem, sc-status, count'
                )
            elif idx == "f5":
                description = f"F5 WAF'ta {domain} domain'ini hedef alan istekler"
                query = (
                    f'index=f5 earliest=-30d@d latest=now uri="*{domain}*"\n'
                    f'| stats count by src_ip, attack_type, response_code\n'
                    f'| sort -count'
                )
            elif idx == "fortimail":
                description = f"FortiMail'de {domain} alan adından gelen/giden mailler"
                query = (
                    f'index=fortimail earliest=-30d@d latest=now (sender="*@{domain}" OR recipient="*@{domain}")\n'
                    f'| table _time, sender, recipient, subject, action, virus\n'
                    f'| sort -_time'
                )

        elif ioc_type == "email":
            if idx == "fortimail":
                description = f"FortiMail'de {val} e-posta adresiyle ilgili tüm posta olayları"
                query = (
                    f'index=fortimail earliest=-30d@d latest=now (sender="{val}" OR recipient="{val}")\n'
                    f'| table _time, sender, recipient, subject, action, virus, attachment\n'
                    f'| sort -_time'
                )
            elif idx == "wineventlog":
                description = f"Windows Event loglarında {val} e-posta adresi geçen olaylar"
                query = (
                    f'index=wineventlog earliest=-30d@d latest=now "{val}"\n'
                    f'| table _time, ComputerName, User, EventID, Message\n'
                    f'| sort -_time'
                )

        elif ioc_type == "powershell":
            if idx == "wineventlog":
                description = "PowerShell Script Block Logging ve Module Logging kayıtları (EventID 4103/4104)"
                query = (
                    f'index=wineventlog earliest=-30d@d latest=now EventID IN (4103, 4104, 400)\n'
                    f'| search ScriptBlockText="*{val[:50]}*"\n'
                    f'| table _time, ComputerName, User, EventID, ScriptBlockText\n'
                    f'| sort -_time'
                )

        if query:
            entry = {
                "index": idx,
                "label": label,
                "color": color,
                "description": description,
                "query": query
            }
            if error:
                entry["note"] = f"LLM bağlanamadı ({error}). Şablon sorgu kullanıldı."
            queries.append(entry)

    return queries

async def generate_bulk_spl_queries(ioc_type: str, ioc_values: list) -> list:
    """Belirli bir tipteki birden fazla IOC için gruplanmış (IN operatörlü) SPL sorguları üretir."""
    if not ioc_values:
        return []
        
    indexes_to_search = IOC_INDEX_MAP.get(ioc_type, [])
    if not indexes_to_search:
        return []
        
    context_indexes = {k: INDEXES[k] for k in indexes_to_search if k in INDEXES}
    
    formatted_values = '", "'.join(ioc_values)
    values_str = f'("{formatted_values}")'
    
    if ioc_type == "hash":
        formatted_hash_values = '*", "*'.join(ioc_values)
        values_str = f'("*{formatted_hash_values}*")'
    
    prompt = f"""
Kullanıcı, CTİ raporundan '{ioc_type}' tipinde çok sayıda tehdit aktörü varlığı (IOC) tespit etti.

Bu IOC'lerin Splunk üzerinde taranması gerekiyor. BİRDEN FAZLA değer olduğu için filtreleme aşamasında KESİNLİKLE 'IN' operatörünü kullanmalısın. 

ÇOK ÖNEMLİ KURAL: Gerçek IOC değerlerini sana göndermiyorum. Sen SPL sorgusunun içine değerlerin geleceği yere tam olarak şu metni yerleştirmelisin: __BULK_VALUES__
Ben bu metni daha sonra kod tarafında gerçek değerlerle değiştireceğim. Lütfen sorguyu bu formata göre oluştur.

Örnek: `src_ip IN __BULK_VALUES__` veya `Hashes IN __BULK_VALUES__`

Aşağıdaki Splunk index yapılarına uygun, tehdit avcılığı için en etkili 1-2 adet toplu SPL sorgusunu üret.
"""
    prompt += "\n" + json.dumps(context_indexes, ensure_ascii=False, indent=2)
    
    try:
        payload = build_llm_payload(
            messages=[
                {"role": "system", "content": SPL_RULES_SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=1500
        )
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(LLM_URL, headers=get_llm_headers(), json=payload)
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"].strip()
            
            raw_content = content # Hata ayıklamak için saklıyoruz
            
            match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", content)
            if match:
                content = match.group(1).strip()
                
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError as je:
                # LLM'in ne döndürdüğünü görebilmek için raw_content'i hata mesajına ekliyoruz
                return [
                    {
                        "index": "error",
                        "label": "JSON Parse Hatası",
                        "color": "#ef4444",
                        "description": "LLM çıktısı geçerli bir JSON değil.",
                        "query": f"Hata detayı: {str(je)}\n\nLLM'in verdiği ham çıktı:\n{raw_content}"
                    }
                ]

            if isinstance(parsed, list):
                for p in parsed:
                    if "query" in p:
                        p["query"] = p["query"].replace("__BULK_VALUES__", values_str)
                return parsed
            else:
                if "query" in parsed:
                    parsed["query"] = parsed["query"].replace("__BULK_VALUES__", values_str)
                return [parsed]
                
    except Exception as e:
        return [
            {
                "index": "error",
                "label": "LLM Hatası",
                "color": "#ef4444",
                "description": "Toplu sorgu üretilirken hata oluştu.",
                "query": f"Hata detayı: {str(e)}"
            }
        ]
