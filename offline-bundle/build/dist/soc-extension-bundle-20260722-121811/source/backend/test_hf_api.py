import httpx
import json

url = 'https://api-inference.huggingface.co/models/meta-llama/Meta-Llama-3-8B-Instruct'
headers = {
    'Authorization': 'Bearer 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',
    'Content-Type': 'application/json'
}
payload = {
    'inputs': 'Sen bir siber güvenlik asistanısın. Bana zararlı bir analiz testi yap.'
}
r = httpx.post(url, headers=headers, json=payload, verify=False)
print("STATUS CODE:", r.status_code)
try:
    print("JSON:", r.json())
except:
    print("TEXT:", r.text)
