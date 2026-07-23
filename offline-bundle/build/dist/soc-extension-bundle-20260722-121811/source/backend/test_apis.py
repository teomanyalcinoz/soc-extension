import httpx
import asyncio

hashes = [
    "12ac32d012e818c78d6db790f6e11838ca75db88",
    "f3e891a2a39dd948cd85e1c8335a83e640d0987dbd48c16001a02f6b7c1733ae",
    "58a84e7f892cdf58116e79555debf2e2a30daff8158594ca770ddab845237576"
]

async def test_mb(client, h):
    response = await client.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": h})
    print(f"MB [{h[:8]}]: {response.status_code} - {response.text[:200]}")

async def test_circl(client, h):
    htype = "sha256" if len(h) == 64 else "sha1" if len(h) == 40 else "md5"
    response = await client.get(f"https://hashlookup.circl.lu/lookup/{htype}/{h}")
    print(f"CIRCL [{h[:8]}]: {response.status_code} - {response.text[:200]}")

async def test_hybrid(client, h):
    response = await client.post(
        "https://www.hybrid-analysis.com/api/v2/search/hash", 
        data={"hash": h}, 
        headers={"accept": "application/json", "user-agent": "SOC Assistant", "Content-Type": "application/x-www-form-urlencoded"}
    )
    print(f"Hybrid [{h[:8]}]: {response.status_code} - {response.text[:200]}")

async def main():
    async with httpx.AsyncClient() as client:
        for h in hashes:
            print(f"--- Testing {h} ---")
            await test_mb(client, h)
            await test_circl(client, h)
            await test_hybrid(client, h)
            print()

asyncio.run(main())
