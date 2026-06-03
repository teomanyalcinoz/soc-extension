import os
from dotenv import load_dotenv

# .env dosyasını yükle
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
load_dotenv(dotenv_path=env_path)

LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_URL = os.getenv("LLM_URL", "")
MODEL_NAME = os.getenv("LLM_MODEL", "")
LLM_API_VERSION = os.getenv("LLM_API_VERSION", "")

def get_llm_headers():
    headers = {
        "Content-Type": "application/json"
    }
    if "azure" in LLM_URL.lower():
        headers["api-key"] = LLM_API_KEY
    else:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"
    return headers

def build_llm_payload(messages, temperature=0.3, max_tokens=300):
    payload = {
        "model": MODEL_NAME,
        "messages": messages,
        "temperature": temperature
    }
    # Azure OpenAI gpt-5.1-ptu veya benzeri modellerde max_completion_tokens kullanılır
    if "gpt-5.1" in MODEL_NAME.lower() or "azure" in LLM_URL.lower():
        payload["max_completion_tokens"] = max_tokens
    else:
        payload["max_tokens"] = max_tokens
        
    return payload
