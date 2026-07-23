# ── Aşama 1: Bağımlılıkları kur ──────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Sistem bağımlılıkları
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── Aşama 2: Çalışma imajı ───────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Builder'dan kurulu paketleri kopyala
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Uygulama kaynak kodunu kopyala
# .env dosyası kopyalanmaz — docker-compose.yml env_file ile enjekte edilir
COPY main.py .
COPY services/ ./services/

# Sabit port 8000
EXPOSE 8000

# Güvenlik: root olmayan kullanıcı
RUN adduser --disabled-password --gecos "" appuser
USER appuser

# Uvicorn başlatma
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
