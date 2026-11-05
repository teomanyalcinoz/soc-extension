import asyncio
import httpx
from services.llm_config import LLM_URL, get_llm_headers, build_llm_payload

async def test_llm():
    print(f"URL: {LLM_URL}")
    headers = get_llm_headers()
    print(f"Headers: {list(headers.keys())}")
    
    messages = [
        {"role": "user", "content": "Merhaba, sadece 'Çalışıyorum!' yazarak cevap ver."}
    ]
    payload = build_llm_payload(messages=messages, temperature=0.1, max_tokens=50)
    print(f"Payload keys: {list(payload.keys())}")
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(LLM_URL, headers=headers, json=payload)
            print(f"Status Code: {response.status_code}")
            if response.status_code != 200:
                print(f"Error Response: {response.text}")
            response.raise_for_status()
            data = response.json()
            print("\nLLM Response:")
            print(data["choices"][0]["message"]["content"].strip())
            print("\n[OK] LLM entegrasyonu basariyla calisiyor!")
    except Exception as e:
        print(f"\n[ERROR] LLM entegrasyonunda hata olustu: {e}")

if __name__ == "__main__":
    asyncio.run(test_llm())
