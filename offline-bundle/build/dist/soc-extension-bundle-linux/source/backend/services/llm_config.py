"""
TracePoint v2.5 — LLM Konfigürasyonu
Azure OpenAI (gpt-5.1-ptu) bağlantı ayarları.
"""
import os
import logging
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# .env dosyasını yükle (backend/ kök dizininden)
env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
load_dotenv(dotenv_path=env_path)

LLM_API_KEY: str = os.getenv("LLM_API_KEY", "")
LLM_URL: str = os.getenv("LLM_URL", "")
MODEL_NAME: str = os.getenv("LLM_MODEL", "gpt-5.1-ptu")
LLM_API_VERSION: str = os.getenv("LLM_API_VERSION", "2023-09-15-preview")
LLM_VERIFY_SSL: bool = os.getenv("LLM_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

# LLM bağlantı durumu log'a yaz (başlangıçta bir kez)
if LLM_URL and LLM_API_KEY:
    logger.info("LLM bağlantısı yapılandırıldı: model=%s", MODEL_NAME)
else:
    logger.warning("LLM_URL veya LLM_API_KEY ayarlanmamış — AI özet devre dışı.")


def get_llm_headers() -> dict:
    """Azure OpenAI veya standart OpenAI için uygun header'ları döner."""
    headers = {"Content-Type": "application/json"}
    if "azure" in LLM_URL.lower():
        headers["api-key"] = LLM_API_KEY
    else:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"
    return headers


def build_llm_payload(
    messages: list,
    temperature: float = 0.3,
    max_tokens: int = 512,
) -> dict:
    """
    Chat Completion payload oluşturur.

    Azure OpenAI gpt-5.1-ptu modeli max_completion_tokens parametresini kullanır.
    max_tokens parametresi görmezden gelinir (API hata verir).
    Standart OpenAI uyumlu endpoint'lerde ise max_tokens kullanılır.
    """
    payload: dict = {
        "model": MODEL_NAME,
        "messages": messages,
        "temperature": temperature,
    }

    if "azure" in LLM_URL.lower() or "gpt-5" in MODEL_NAME.lower():
        # Azure OpenAI o-serisi / gpt-5.1 modelleri
        payload["max_completion_tokens"] = max_tokens
    else:
        payload["max_tokens"] = max_tokens

    return payload
