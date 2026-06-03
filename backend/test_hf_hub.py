import asyncio
import sys
from huggingface_hub import AsyncInferenceClient

async def test():
    client = AsyncInferenceClient(
        model="meta-llama/Meta-Llama-3-8B-Instruct",
        token="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"
    )
    
    messages = [{"role": "user", "content": "Selam!"}]
    try:
        response = await client.chat_completion(messages, max_tokens=50)
        print("BASSARI:", response.choices[0].message.content)
    except Exception as e:
        print("HATA:", e)

if __name__ == "__main__":
    asyncio.run(test())
