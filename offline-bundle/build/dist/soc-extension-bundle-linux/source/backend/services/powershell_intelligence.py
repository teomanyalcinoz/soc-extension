import re
import base64
import httpx

from services.llm_config import LLM_API_KEY, LLM_URL, get_llm_headers, build_llm_payload

def deobfuscate_powershell(script: str) -> dict:
    """
    PowerShell scripti içerisinde saklanmış veya encode edilmiş önemli blokları çözer.
    Özellikle -enc arkasındaki Base64 ve [Convert]::FromBase64String çağrılarını ayıklar.
    """
    findings = []
    decoded_blocks = []
    
    # Base64 Pattern (> 20 karakter)
    b64_pattern = r'(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    matches = re.findall(b64_pattern, script)
    
    for match in matches:
        try:
            # UTF-16LE -enc decode denemesi
            decoded_bytes = base64.b64decode(match)
            decoded_utf16 = decoded_bytes.decode('utf-16le')
            if len(decoded_utf16) > 5 and re.search(r'[a-zA-Z]', decoded_utf16):
                decoded_blocks.append(f"[UTF-16 Decode]: {decoded_utf16}")
                continue
        except Exception:
            pass
            
        try:
            # Normal UTF-8 decode
            decoded_utf8 = decoded_bytes.decode('utf-8')
            if len(decoded_utf8) > 5 and re.search(r'[a-zA-Z]', decoded_utf8):
                decoded_blocks.append(f"[UTF-8 Decode]: {decoded_utf8}")
        except Exception:
            pass

    return {
        "original_script": script,
        "decoded_blocks": decoded_blocks,
        "obfuscation_detected": len(decoded_blocks) > 0
    }

async def analyze_powershell_with_ai(script_content: str) -> dict:
    """
    Gelen scripti önce deobfuscate eder, sonra Senior SOC Analyst rolündeki modele analiz ettirir.
    """
    prep_data = deobfuscate_powershell(script_content)
    
    # LLM Modeline gidecek metin harmanlaması
    # Script çok uzunsa keselim (Token limitine takılmamak için)
    safe_script = prep_data["original_script"][:2500]
    
    context_str = f"Orijinal Script:\n{safe_script}\n"
    if prep_data["decoded_blocks"]:
        context_str += "\nÖn İşleme (Otomatik Çözülmüş Base64 Blokları):\n"
        context_str += "\n".join(prep_data["decoded_blocks"])
        
    prompt = f"""Sen TracePoint-SOME kıdemli Malware Analistisin. Sıfır Güven (Zero Trust) prensibiyle aşağıdaki PowerShell kodunu analiz et. Tüm teknik detayları ve olası tehditleri raporla.

Analiz Edilecek Veri:
{context_str}

Lütfen raporunu aşağıdaki HTML bazlı basit formatta sun. Sadece div, p, ul ve h4 etiketlerini kullan, fazladan markdown (```html) ETİKETİ EKLEME.

<div style="font-family: sans-serif;">
    <h4 style="color:#c5a963;">1. Özet (Amaç)</h4>
    <p>[Scriptin genel amacı ve zararlı olup olmadığı]</p>

    <h4 style="color:#c5a963;">2. Kritik Bulgular</h4>
    <p>[IEX, -enc gibi şüpheli parametre analizleri]</p>

    <h4 style="color:#c5a963;">3. IOC Listesi</h4>
    <ul><li>[Bulunan IP/Domain listesi veya "IoC Bulunamadı"]</li></ul>

    <h4 style="color:#c5a963;">4. MITRE ATT&CK</h4>
    <p>[T1059.001 - PowerShell gibi teknikler]</p>

    <div style="margin-top:10px; padding:10px; background:rgba(239, 68, 68, 0.1); border-left:4px solid #ef4444;">
        <h4 style="color:#ef4444; margin-top:0;">Analist Aksiyon Planı (Risk: [1-10 Skor]/10)</h4>
        <ul><li>[Acil yapılması gereken SOC aksiyonları]</li></ul>
    </div>
</div>"""

    preprocessor_results = [
        {
            "source": "Pre-processor (De-Obfuscator)",
            "success": True,
            "data": {
                "decoded_blocks": len(prep_data["decoded_blocks"]),
                "is_obfuscated": prep_data["obfuscation_detected"]
            }
        }
    ]

    if not LLM_API_KEY:
        return {
            "status": "success",
            "ai_summary": "LLM API anahtarı boş. Model kullanılamıyor.",
            "results": preprocessor_results
        }

    try:
        headers = get_llm_headers()
        messages = [
            {
                "role": "system",
                "content": "You are a senior SOC analyst working in a financial institution. Your responsibilities: Analyze SIEM/SOAR alerts and determine severity, root cause, and next actions. Generate concise and accurate security analysis based only on provided data. Follow bank security policies, MITRE ATT&CK, and incident response best practices. If information is missing, clearly state what is missing instead of guessing. Provide output in a structured and machine-parsable format. Never create assumptions outside the given alert context. Never invent logs, users, or events."
            },
            {
                "role": "user",
                "content": "Kıdemli TracePoint-SOME Güvenlik Analisti. Net ve doğrudan HTML dönersin.\n\n" + prompt
            }
        ]
        payload = build_llm_payload(messages=messages, temperature=0.2, max_tokens=2000)
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(LLM_URL, headers=headers, json=payload)
            response.raise_for_status()
            response_data = response.json()
            html_output = response_data["choices"][0]["message"]["content"].strip()
        
        if not html_output:
            html_output = "LLM API boş yanıt döndürdü. Lütfen modeli veya promptu kontrol edin."
        
        return {
            "status": "success",
            "ai_summary": html_output.replace('```html', '').replace('```', ''),
            "results": preprocessor_results
        }
    except Exception as e:
        return {
            "status": "success",
            "ai_summary": f"LLM Analiz Hatası: API ile haberleşirken hata oluştu ({str(e)}). Lütfen LLM_URL ve ağ bağlantısını kontrol edin.",
            "results": preprocessor_results
        }
