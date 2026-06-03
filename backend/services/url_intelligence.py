import httpx
import asyncio
import base64

from services.intelligence import VT_API_KEY, MALWAREBAZAAR_API_KEY
URLSCAN_API_KEY = "019cc1db-1a78-77fe-9c1f-5a051a6091a6"

async def check_virustotal_url(url: str, client: httpx.AsyncClient) -> dict:
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {
            "x-apikey": VT_API_KEY,
            "Accept": "application/json"
        }
        res = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10.0)
        
        if res.status_code == 200:
            return {"success": True, "source": "VirusTotal", "data": res.json()}
        elif res.status_code == 404:
            return {"success": True, "source": "VirusTotal", "data": {"message": "Not found"}}
        else:
            return {"success": False, "source": "VirusTotal", "error": f"API Hatası: {res.status_code}"}
    except Exception as e:
        return {"success": False, "source": "VirusTotal", "error": str(e)}

async def check_usom(url: str, client: httpx.AsyncClient) -> dict:
    try:
        from urllib.parse import urlparse
        # httpx vb üzerinden tam bir url parse edebilmek için şema eksikse ekle
        parsed_url = url if url.startswith("http") else "http://" + url
        domain = urlparse(parsed_url).netloc.split(':')[0]
        
        # USOM Domain veya URL olarak arama kabul edebiliyor.
        res = await client.get(f"https://www.usom.gov.tr/api/address/index?q={domain}", timeout=10.0)
        
        if res.status_code == 200:
            return {"success": True, "source": "USOM", "data": res.json()}
        else:
            return {"success": False, "source": "USOM", "error": f"API Hatası: {res.status_code}"}
    except Exception as e:
        return {"success": False, "source": "USOM", "error": str(e)}

async def check_urlhaus(url: str, client: httpx.AsyncClient) -> dict:
    try:
        data = {'url': url}
        headers = {'Auth-Key': MALWAREBAZAAR_API_KEY} if MALWAREBAZAAR_API_KEY else {}
        res = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data=data, headers=headers, timeout=10.0)
        if res.status_code == 200:
            return {"success": True, "source": "URLhaus", "data": res.json()}
        else:
            return {"success": False, "source": "URLhaus", "error": f"API Hatası: {res.status_code}"}
    except Exception as e:
        return {"success": False, "source": "URLhaus", "error": str(e)}

async def check_sucuri(url: str, client: httpx.AsyncClient) -> dict:
    try:
        res = await client.get(f"https://sitecheck.sucuri.net/api/v3/?scan={url}", timeout=15.0)
        if res.status_code == 200:
            return {"success": True, "source": "Sucuri SiteCheck", "data": res.json()}
        else:
            return {"success": False, "source": "Sucuri SiteCheck", "error": f"API Hatası: {res.status_code}"}
    except Exception as e:
        return {"success": False, "source": "Sucuri SiteCheck", "error": str(e)}

async def check_urlscan(url: str, client: httpx.AsyncClient) -> dict:
    # urlscan.io doğrudan tarama atmak (Scan submission) çok yavaştır (dakikalar sürer)
    # Bu nedenle biz "Search" API'sini kullanarak bu URL/Domain daha önce taranmış mı ona bakacağız.
    # search?q=domain:example.com
    try:
        from urllib.parse import urlparse
        # httpx vb üzerinden tam bir url parse edebilmek için şema eksikse ekle
        parsed_url = url if url.startswith("http") else "http://" + url
        domain = urlparse(parsed_url).netloc.split(':')[0]
        headers = {"API-Key": URLSCAN_API_KEY}
        res = await client.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", headers=headers, timeout=10.0)
        if res.status_code == 200:
            return {"success": True, "source": "urlscan.io", "data": res.json()}
        else:
            return {"success": False, "source": "urlscan.io", "error": f"API Hatası: {res.status_code}"}
    except Exception as e:
        return {"success": False, "source": "urlscan.io", "error": str(e)}

async def analyze_url(url: str) -> dict:
    async with httpx.AsyncClient(verify=False) as client:
        tasks = [
            check_virustotal_url(url, client),
            check_urlhaus(url, client),
            check_sucuri(url, client),
            check_urlscan(url, client),
            check_usom(url, client)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for r in results:
            if isinstance(r, dict):
                valid_results.append(r)
            else:
                valid_results.append({"success": False, "source": "Unknown", "error": "Bilinmeyen Exception"})
                
        return {"target": url, "type": "url", "results": valid_results}
