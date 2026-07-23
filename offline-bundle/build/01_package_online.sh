#!/usr/bin/env bash
# =============================================================================
#  ADIM 1 — ONLINE BUILD SERVER'DA ÇALIŞTIRILIR
#  Görev  : Docker image'ı, Python wheel'larını ve kaynak kodu paketleyerek
#           tek bir .tar.gz offline-bundle oluşturur.
#
#  Kullanım: chmod +x 01_package_online.sh && ./01_package_online.sh
# =============================================================================

set -euo pipefail

# ─── Konfigürasyon ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"   # SOC-EXTENSION kök dizini
BUNDLE_NAME="soc-extension-bundle"
BUNDLE_VERSION="$(date +%Y%m%d-%H%M%S)"
BUILD_DIR="$SCRIPT_DIR/dist/${BUNDLE_NAME}-${BUNDLE_VERSION}"
ARCHIVE_NAME="${BUNDLE_NAME}-${BUNDLE_VERSION}.tar.gz"

DOCKER_IMAGE_NAME="soc-backend"
DOCKER_IMAGE_TAG="offline"
PYTHON_VERSION="3.11"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║       SOC-EXTENSION  —  Offline Bundle Packager          ║"
echo "║       Version: ${BUNDLE_VERSION}                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ─── Ön Koşul Kontrolü ────────────────────────────────────────────────────────
check_prerequisite() {
    if ! command -v "$1" &>/dev/null; then
        echo "[ERROR] '$1' bulunamadı. Lütfen kurun ve tekrar deneyin."
        exit 1
    fi
    echo "[OK] $1 mevcut: $(command -v "$1")"
}

echo "▶ Ön koşullar kontrol ediliyor..."
check_prerequisite docker
check_prerequisite pip
check_prerequisite python3
check_prerequisite tar
echo ""

# ─── Dizin Yapısı Oluştur ─────────────────────────────────────────────────────
echo "▶ Bundle dizin yapısı oluşturuluyor: $BUILD_DIR"
mkdir -p "$BUILD_DIR"/{docker,wheels,source,frontend,scripts,config}

# ─── 1. Docker Image: Build & Save ────────────────────────────────────────────
echo ""
echo "▶ [1/5] Docker image build ediliyor: ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}"
docker build \
    -t "${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" \
    -f "$PROJECT_ROOT/backend/Dockerfile" \
    "$PROJECT_ROOT/backend"

echo "▶ Docker image diske kaydediliyor → docker/soc-backend.tar"
docker save "${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}" \
    | gzip -9 > "$BUILD_DIR/docker/soc-backend.tar.gz"
echo "[OK] Docker image boyutu: $(du -sh "$BUILD_DIR/docker/soc-backend.tar.gz" | cut -f1)"

# ─── 2. Python Wheel'ları İndir ───────────────────────────────────────────────
echo ""
echo "▶ [2/5] Python wheel'ları indiriliyor (platform: linux/amd64)..."
pip download \
    --dest "$BUILD_DIR/wheels" \
    --platform linux_x86_64 \
    --python-version "$PYTHON_VERSION" \
    --only-binary=:all: \
    -r "$PROJECT_ROOT/backend/requirements.txt"

# pip kendisi de offline'da lazım olabilir — pip wheel'ını da indir
pip download pip setuptools wheel \
    --dest "$BUILD_DIR/wheels" \
    --platform linux_x86_64 \
    --python-version "$PYTHON_VERSION" \
    --only-binary=:all:

WHEEL_COUNT=$(ls "$BUILD_DIR/wheels"/*.whl 2>/dev/null | wc -l)
echo "[OK] $WHEEL_COUNT adet wheel dosyası indirildi."

# ─── 3. Kaynak Kodu Kopyala ───────────────────────────────────────────────────
echo ""
echo "▶ [3/5] Backend kaynak kodu kopyalanıyor..."
rsync -a --exclude='venv' \
          --exclude='__pycache__' \
          --exclude='*.pyc' \
          --exclude='.env' \
          "$PROJECT_ROOT/backend/" "$BUILD_DIR/source/backend/"

echo "▶ [3/5] Frontend / Extension kopyalanıyor..."
rsync -a "$PROJECT_ROOT/frontend/" "$BUILD_DIR/frontend/"

echo "[OK] Kaynak kod kopyalandı."

# ─── 4. Konfigürasyon Şablonları ─────────────────────────────────────────────
echo ""
echo "▶ [4/5] Konfigürasyon şablonları hazırlanıyor..."

cat > "$BUILD_DIR/config/.env.template" <<'ENVEOF'
# ──────────────────────────────────────────────
#  SOC-EXTENSION — Ortam Değişkenleri Şablonu
#  Bu dosyayı .env olarak kopyalayın ve doldurun
# ──────────────────────────────────────────────

# Backend
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
LOG_LEVEL=info

# AI / LLM servisi (offline modda yerel LLM adresi)
LLM_BASE_URL=http://localhost:11434
LLM_MODEL=llama3

# Güvenlik
SECRET_KEY=CHANGE_ME_STRONG_RANDOM_KEY
ALLOWED_ORIGINS=http://localhost,http://127.0.0.1
ENVEOF

cat > "$BUILD_DIR/config/docker-compose.offline.yml" <<'COMPOSEEOF'
version: "3.9"

services:
  soc-backend:
    image: soc-backend:offline        # internet olmadan yüklenen image
    container_name: soc-backend
    restart: unless-stopped
    ports:
      - "8000:8000"
    env_file:
      - .env
    volumes:
      - soc_logs:/app/logs
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 20s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "5"

volumes:
  soc_logs:
COMPOSEEOF

echo "[OK] Konfigürasyon şablonları hazırlandı."

# ─── 5. Deploy Betiğini Kopyala ───────────────────────────────────────────────
echo ""
echo "▶ [5/5] Deploy betiği bundle'a dahil ediliyor..."
cp "$SCRIPT_DIR/02_deploy_offline.sh" "$BUILD_DIR/scripts/"
chmod +x "$BUILD_DIR/scripts/02_deploy_offline.sh"

# ─── Manifest Dosyası ─────────────────────────────────────────────────────────
cat > "$BUILD_DIR/MANIFEST.txt" <<MANIFESTEOF
SOC-EXTENSION Offline Bundle
============================
Sürüm       : ${BUNDLE_VERSION}
Oluşturulma : $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Build Host  : $(hostname)
Python      : ${PYTHON_VERSION}
Docker Img  : ${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_TAG}

İçerik:
  docker/soc-backend.tar.gz  — Hazır Docker image (sıkıştırılmış)
  wheels/                    — Python .whl bağımlılık dosyaları
  source/backend/            — FastAPI kaynak kodu
  frontend/                  — Chrome Extension kaynak kodu
  config/                    — .env şablonu ve docker-compose
  scripts/02_deploy_offline.sh — Offline kurulum betiği

Kurulum için: scripts/02_deploy_offline.sh dosyasını çalıştırın.
MANIFESTEOF

# ─── Arşiv Oluştur ────────────────────────────────────────────────────────────
echo ""
echo "▶ Arşiv oluşturuluyor: $ARCHIVE_NAME"
cd "$SCRIPT_DIR/dist"
tar -czf "../${ARCHIVE_NAME}" "${BUNDLE_NAME}-${BUNDLE_VERSION}/"
cd - > /dev/null

ARCHIVE_SIZE=$(du -sh "$SCRIPT_DIR/${ARCHIVE_NAME}" | cut -f1)

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  ✅  PAKETLEME TAMAMLANDI                                ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Arşiv : offline-bundle/${ARCHIVE_NAME}  ║"
echo "║  Boyut : ${ARCHIVE_SIZE}                                 ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  SONRAKI ADIM: Bu dosyayı offline sunucuya taşıyın       ║"
echo "║  ve 02_deploy_offline.sh betiğini çalıştırın.            ║"
echo "╚══════════════════════════════════════════════════════════╝"
