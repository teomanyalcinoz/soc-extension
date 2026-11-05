"""
TracePoint v2.5 — AI Özet Servisi (Azure OpenAI GPT-5.1-ptu)
IOC analiz sonuçlarını filtreleyip LLM'e gönderir,
HTML formatında kısa ve öz bir SOC analizi alır.
"""
import json
import httpx
import logging

from services.llm_config import LLM_API_KEY, LLM_URL, LLM_VERIFY_SSL, get_llm_headers, build_llm_payload

logger = logging.getLogger(__name__)


def _filter_results(intelligence_results: list) -> list:
    """
    Tüm ham OSINT verisini LLM'e göndermek yerine
    her kaynaktan en önemli metrikleri süzer.
    Token tasarrufu + daha tutarlı AI çıktısı sağlar.
    """
    filtered = []
    for r in intelligence_results:
        if not isinstance(r, dict) or not r.get("success"):
            continue

        src = r.get("source", "")
        raw_data = r.get("data")
        data = raw_data if isinstance(raw_data, dict) else {}
        summary: dict = {"source": src}

        # ── VirusTotal ────────────────────────────────────────────
        if "VirusTotal" in src:
            vt = data.get("data")
            attrs = {}
            if isinstance(vt, list) and vt:
                attrs = vt[0].get("attributes", {})
            elif isinstance(vt, dict):
                attrs = vt.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            summary["malicious_hits"] = stats.get("malicious", 0)
            summary["suspicious_hits"] = stats.get("suspicious", 0)

        # ── AlienVault OTX ────────────────────────────────────────
        elif "AlienVault" in src:
            summary["pulses"] = data.get("pulse_info", {}).get("count", 0)
            pulses = data.get("pulse_info", {}).get("pulses", [])
            summary["tags"] = pulses[0].get("tags", [])[:3] if pulses else []

        # ── MalwareBazaar ─────────────────────────────────────────
        elif "MalwareBazaar" in src:
            summary["status"] = data.get("query_status", "unknown")

        # ── AbuseIPDB ─────────────────────────────────────────────
        elif "AbuseIPDB" in src:
            d = data.get("data", {})
            summary["abuse_confidence_score"] = d.get("abuseConfidenceScore", 0)
            summary["total_reports"] = d.get("totalReports", 0)
            summary["country"] = d.get("countryCode")
            summary["isp"] = d.get("isp")

        # ── Shodan ────────────────────────────────────────────────
        elif "Shodan" in src:
            summary["open_ports"] = data.get("open_ports", [])
            summary["vulns"] = data.get("vulns", [])[:5]
            summary["org"] = data.get("org")
            summary["os"] = data.get("os")

        # ── GreyNoise ─────────────────────────────────────────────
        elif "GreyNoise" in src:
            summary["noise"] = data.get("noise", False)
            summary["riot"] = data.get("riot", False)
            summary["classification"] = data.get("classification")
            summary["name"] = data.get("name")

        # ── URLhaus ───────────────────────────────────────────────
        elif "URLhaus" in src:
            summary["url_status"] = data.get("url_status", "unknown")
            summary["threat"] = data.get("threat", "unknown")

        # ── Sucuri ────────────────────────────────────────────────
        elif "Sucuri" in src:
            bls = data.get("blacklists", [])
            summary["blacklisted"] = any(b.get("is_blacklisted") for b in bls) if isinstance(bls, list) else False
            warnings = data.get("warnings", [])
            summary["warning_count"] = len(warnings) if isinstance(warnings, list) else 0

        # ── urlscan.io ────────────────────────────────────────────
        elif "urlscan.io" in src:
            summary["historical_scans_found"] = data.get("total", 0)

        # ── USOM ──────────────────────────────────────────────────
        elif "USOM" in src:
            summary["usom_blacklist_hits"] = data.get("totalCount", 0)

        # ── PhishTank ─────────────────────────────────────────────
        elif "PhishTank" in src:
            summary["in_database"] = data.get("in_database", False)
            summary["verified"] = data.get("verified", False)

        # ── Pulsedive ─────────────────────────────────────────────
        elif "Pulsedive" in src:
            summary["risk"] = data.get("risk", "unknown")
            summary["threats"] = [t.get("name") for t in data.get("threats", [])[:3]] if data.get("threats") else []

        # ── AbstractAPI ───────────────────────────────────────────
        elif "AbstractAPI" in src:
            summary["deliverability"] = data.get("deliverability", "UNKNOWN")
            summary["quality_score"] = round(float(data.get("quality_score") or 0), 2)
            disp = data.get("is_disposable_email", {})
            summary["is_disposable"] = disp.get("value", False) if isinstance(disp, dict) else bool(disp)
            summary["breach_count"] = data.get("breach_count", 0)
            summary["breached"] = data.get("breach_count", 0) > 0

        # ── emailrep.io ───────────────────────────────────────────
        elif "emailrep.io" in src:
            summary["reputation"] = data.get("reputation", "unknown")
            summary["suspicious"] = data.get("suspicious", False)

        # ── HaveIBeenPwned ────────────────────────────────────────
        elif "HaveIBeenPwned" in src:
            summary["breached"] = r.get("breached", False)
            data_list = r.get("data", [])
            summary["breach_count"] = len(data_list) if isinstance(data_list, list) else 0

        # ── BreachDirectory ───────────────────────────────────────
        elif "BreachDirectory" in src:
            summary["found_count"] = data.get("found", 0)

        # ── Spamhaus ──────────────────────────────────────────────
        elif "Spamhaus" in src:
            summary["domain_blacklisted"] = data.get("domain_blacklisted", False)
            summary["dbl_listed"] = data.get("dbl_listed", False)

        # ── MX / DNS ──────────────────────────────────────────────
        elif "MX" in src or "DNS" in src:
            summary["domain_resolves"] = data.get("domain_resolves", False)
            summary["mx_valid"] = data.get("mx_valid", False)

        # ── Hybrid Analysis ───────────────────────────────────────
        elif "Hybrid Analysis" in src:
            items = data if isinstance(data, list) else []
            summary["sample_count"] = len(items)
            if items:
                summary["verdict"] = items[0].get("verdict", "unknown")

        # ── Triage ────────────────────────────────────────────────
        elif "Triage" in src:
            summary["sample_count"] = data.get("sample_count", 0)

        # ── Polyswarm ─────────────────────────────────────────────
        elif "Polyswarm" in src:
            summary["result_count"] = len(data.get("result", [])) if isinstance(data.get("result"), list) else 0

        # ── SecurityTrails ────────────────────────────────────────
        elif "SecurityTrails" in src:
            summary["subdomain_count"] = data.get("subdomain_count", 0)
            summary["registrar"] = data.get("whois", {}).get("registrar")

        # ── crt.sh ────────────────────────────────────────────────
        elif "crt.sh" in src:
            summary["certificate_count"] = data.get("certificate_count", 0)
            summary["unique_names"] = data.get("unique_names", 0)

        # ── RDAP ──────────────────────────────────────────────────
        elif "RDAP" in src:
            summary["registrar"] = data.get("registrar")
            summary["status"] = data.get("status", [])
            summary["expiration"] = data.get("expiration")

        filtered.append(summary)

    return filtered


async def generate_summary(target: str, target_type: str, intelligence_results: list) -> str:
    """
    Tehdit istihbaratından dönen sonuçları filtreler ve LLM'e göndererek
    HTML formatında kısa ve öz bir SOC analizi alır.
    """
    if not LLM_API_KEY or not LLM_URL:
        return "Yapay Zeka analizi için LLM_API_KEY ve LLM_URL ayarlanmamış."

    filtered_results = _filter_results(intelligence_results)
    if not filtered_results:
        return "<p>Analiz edilecek başarılı sonuç bulunamadı.</p>"

    llm_context = json.dumps(filtered_results, ensure_ascii=False)

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
            {"role": "user", "content": prompt},
        ]
        # 512 token — hem hız hem içerik dengesi
        payload = build_llm_payload(messages=messages, temperature=0.3, max_tokens=512)

        async with httpx.AsyncClient(timeout=60.0, verify=LLM_VERIFY_SSL) as client:
            response = await client.post(LLM_URL, headers=headers, json=payload)
            response.raise_for_status()
            response_data = response.json()
            content = response_data["choices"][0]["message"]["content"].strip()
            logger.debug("AI özet üretildi: %d karakter", len(content))
            return content

    except Exception as e:
        logger.error("LLM özet hatası: %s", e)
        return f"<p>Model bağlantısında hata: {str(e)}</p>"
