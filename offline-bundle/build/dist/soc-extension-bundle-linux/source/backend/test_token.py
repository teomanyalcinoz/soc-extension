URL = "https://local-llm.ktappsec.com/v1/chat/completions"

headers = {
    "Authorization": f"Bearer {LM_API_TOKEN}",
    "Content-Type": "application/json"
}

payload = {
    "model": "google/gemma-4-26b-a4b", 
    "messages": [{"role": "user", "content": "Token doğrulama testi. Lütfen kısa bir 'Test Başarılı' yanıtı ver."}]
}

def check_token():
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] İstek başlatılıyor: {URL}")
    start_time = time.time()
    try:
        with httpx.Client(timeout=120.0, verify=False) as client:
            response = client.post(URL, json=payload, headers=headers)
        elapsed_time = time.time() - start_time
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] İstek tamamlandı. Süre: {elapsed_time:.2f} saniye")

        if response.status_code == 200:
            print("\nErişim Başarılı!")
            print("Yanıt:", response.json()['choices'][0]['message']['content'])
        else:
            print(f"\nHata Kodu: {response.status_code}")
            try:
                print("Hata Detayı:", response.json())
            except:
                print("Hata Detayı:", response.text)
    except Exception as e:
        elapsed_time = time.time() - start_time
        print(f"\nİstek {elapsed_time:.2f} saniye sonra bir hata ile sonlandı:")
        print("Hata Detayı:", str(e))

check_token()

try:
    response = requests.post(URL, json=payload, headers=headers, timeout=120.0, verify=False)
    elapsed_time = time.time() - start_time
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] İstek tamamlandı. Süre: {elapsed_time:.2f} saniye")

    if response.status_code == 200:
        print("\nErişim Başarılı!")
        print("Yanıt:", response.json()['choices'][0]['message']['content'])
    else:
        print(f"\nHata Kodu: {response.status_code}")
        print("Hata Detayı:", response.text)
except Exception as e:
    elapsed_time = time.time() - start_time
    print(f"\nİstek {elapsed_time:.2f} saniye sonra bir hata ile sonlandı:")
    print("Hata Detayı:", str(e))
