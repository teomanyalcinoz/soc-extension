import asyncio
import httpx

API_KEY = "5dad265712ca5a5b3677dca49c1bf4a64351f2b9ea334324"

async def test():
    url = "www.medicalalert.com/"
    async with httpx.AsyncClient() as client:
        data = {'url': url}
        headers = {'Auth-Key': API_KEY}
        res3 = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data=data, headers=headers)
        print("URLHAUS WITH KEY:", res3.status_code, res3.text)

asyncio.run(test())
