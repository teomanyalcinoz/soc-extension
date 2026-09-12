"""
AI summary servisini tek basiina calistiran test scripti.
Disariya (VirusTotal, AbuseIPDB vb.) istek atmaz, sadece LLM'i test eder.
"""
import asyncio
import sys
sys.path.insert(0, '.')

from services.ai_summary import generate_summary

# Gercek bir tehdit analizi gibi simulate edilmis sahte veri
fake_results = [
    {
        "source": "VirusTotal",
        "success": True,
        "data": {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 12,
                        "suspicious": 3,
                        "harmless": 45,
                        "undetected": 20
                    }
                }
            }
        }
    },
    {
        "source": "AbuseIPDB",
        "success": True,
        "data": {
            "data": {
                "abuseConfidenceScore": 87,
                "totalReports": 42
            }
        }
    },
    {
        "source": "AlienVault OTX",
        "success": True,
        "data": {
            "pulse_info": {
                "count": 5,
                "pulses": [{"tags": ["botnet", "c2", "malware"]}]
            }
        }
    }
]

async def test():
    print("AI Summary testi baslatiliyor...")
    result = await generate_summary("185.220.101.45", "IPv4 Adresi", fake_results)
    print("\n=== AI SUMMARY SONUCU ===")
    print(result)

asyncio.run(test())
