#!/usr/bin/env bash
# =============================================================================
#  ADIM 2 — OFFLINE SUNUCUDA ÇALIŞTIRILIR
#  Görev  : Taşınan bundle arşivini açar, Docker image'ı yükler,
#           Python wheel'larını kurar ve uygulamayı başlatır.
#
#  Kullanım:
#    1. Arşivi sunucuya kopyalayın (SCP/USB/etc.)
#    2. tar -xzf soc-extension-bundle-*.tar.gz
#    3. cd soc-extension-bundle-*/
#    4. sudo bash scripts/02_deploy_offline.sh
# =============================================================================

set -euo pipefail

# ─── Renk / Format Yardımcıları ───────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ─── Bundle Kök Dizini ────────────────────────────────────────────────────────
BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_ROOT="/opt/soc-extension"      # Kurulum hedef dizini
LOG_FILE="/var/log/soc-deploy.log"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     SOC-EXTENSION  —  Offline Deployment Script          ║${NC}"
echo -e "${BOLD}║     Bundle: ${BUNDLE_DIR}${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Tüm çıktıyı log'a da yaz
exec > >(tee -a "$LOG_FILE") 2>&1
info "Deploy log: $LOG_FILE"
info "Başlangıç: $(date -u)"

# ─── Root Kontrolü ────────────────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && error "Bu betik root (sudo) ile çalıştırılmalıdır."

# ─── Ön Koşul Kontrolü ────────────────────────────────────────────────────────
check_cmd() {
    command -v "$1" &>/dev/null || error "'$1' bulunamadı. Offline kurulum talimatlarını inceleyin."
    success "$1 mevcut."
}

info "Ön koşullar kontrol ediliyor..."
check_cmd docker
check_cmd docker-compose || check_cmd "docker compose"
check_cmd python3

# ─── ADIM 1: Dizin Yapısını Hazırla ──────────────────────────────────────────
info ""
info "▶ [1/6] Kurulum dizini hazırlanıyor: $DEPLOY_ROOT"
mkdir -p "$DEPLOY_ROOT"/{config,logs,data}

# ─── ADIM 2: Docker Daemon Çalışıyor mu? ──────────────────────────────────────
info "▶ [2/6] Docker daemon durumu kontrol ediliyor..."
if ! systemctl is-active --quiet docker 2>/dev/null; then
    warn "Docker aktif değil, başlatılıyor..."
    systemctl start docker
    sleep 3
fi
docker info > /dev/null 2>&1 || error "Docker daemon'a bağlanılamadı."
success "Docker çalışıyor."

# ─── ADIM 3: Docker Image Yükle ───────────────────────────────────────────────
info ""
info "▶ [3/6] Docker image yükleniyor (internet bağlantısı gerektirmez)..."
DOCKER_TAR="$BUNDLE_DIR/docker/soc-backend.tar.gz"

[[ -f "$DOCKER_TAR" ]] || error "Docker image bulunamadı: $DOCKER_TAR"

info "Image decompressing ve yükleniyor..."
gunzip -c "$DOCKER_TAR" | docker load

# Yüklenen image'ı doğrula
if docker image inspect "soc-backend:offline" &>/dev/null; then
    success "Docker image başarıyla yüklendi: soc-backend:offline"
    docker image ls soc-backend:offline
else
    error "Docker image yüklenemedi."
fi

# ─── ADIM 4: Python Wheel'larını Kur (Opsiyonel – Docker dışı kullanım) ───────
info ""
info "▶ [4/6] Python wheel'ları yerel depo olarak konfigüre ediliyor..."
WHEELS_DIR="$BUNDLE_DIR/wheels"

if [[ -d "$WHEELS_DIR" && "$(ls -A "$WHEELS_DIR"/*.whl 2>/dev/null | wc -l)" -gt 0 ]]; then
    WHEEL_COUNT=$(ls "$WHEELS_DIR"/*.whl | wc -l)
    success "$WHEEL_COUNT wheel dosyası bulundu → $WHEELS_DIR"

    # Basit HTTP server başlatılabilir (opsiyonel – diğer makineler için)
    # python3 -m http.server --directory "$WHEELS_DIR" 3141 &

    # Doğrudan pip kurulumu (offline, Docker dışı kullanım)
    if [[ "${INSTALL_WHEELS:-false}" == "true" ]]; then
        info "Wheel'lar pip ile kuruluyor (--no-index, --find-links)..."
        pip install \
            --no-index \
            --find-links="$WHEELS_DIR" \
            -r "$BUNDLE_DIR/source/backend/requirements.txt"
        success "Python bağımlılıkları kuruldu."
    else
        info "Wheel'lar kurulmadı (Docker mode). Doğrudan kurmak için:"
        info "INSTALL_WHEELS=true bash scripts/02_deploy_offline.sh"
    fi
else
    warn "Wheel dizini boş veya bulunamadı — Docker mode kullanılıyor."
fi

# ─── ADIM 5: Konfigürasyonu Hazırla ──────────────────────────────────────────
info ""
info "▶ [5/6] Konfigürasyon hazırlanıyor..."
ENV_FILE="$DEPLOY_ROOT/config/.env"
COMPOSE_FILE="$DEPLOY_ROOT/config/docker-compose.offline.yml"

# .env dosyası zaten varsa üzerine yazma
if [[ ! -f "$ENV_FILE" ]]; then
    cp "$BUNDLE_DIR/config/.env.template" "$ENV_FILE"
    warn "YENİ .env oluşturuldu → $ENV_FILE"
    warn "Lütfen SECRET_KEY ve diğer değerleri düzenleyin: nano $ENV_FILE"
else
    success ".env mevcut, korunuyor: $ENV_FILE"
fi

# docker-compose.offline.yml'yi her seferinde güncelle
cp "$BUNDLE_DIR/config/docker-compose.offline.yml" "$COMPOSE_FILE"
success "docker-compose.offline.yml kopyalandı."

# Source kodu deploy root'a kopyala
rsync -a --delete \
    "$BUNDLE_DIR/source/backend/" \
    "$DEPLOY_ROOT/backend/"
success "Kaynak kod güncellendi: $DEPLOY_ROOT/backend/"

# ─── ADIM 6: Uygulamayı Başlat ────────────────────────────────────────────────
info ""
info "▶ [6/6] Uygulama başlatılıyor (Docker Compose)..."
cd "$DEPLOY_ROOT/config"

# Mevcut container'ı durdur (varsa)
docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true

# .env'yi compose dosyası ile aynı dizine symlink yap
ln -sf "$ENV_FILE" "$DEPLOY_ROOT/config/.env" 2>/dev/null || true

# Başlat
docker compose \
    --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" \
    up -d

# ─── Sağlık Kontrolü ──────────────────────────────────────────────────────────
info ""
info "Sağlık kontrolü bekleniyor (30 saniye)..."
sleep 30

HEALTH_URL="http://localhost:8000/health"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL" 2>/dev/null || echo "000")

if [[ "$HTTP_STATUS" == "200" ]]; then
    success "Uygulama sağlıklı! HTTP $HTTP_STATUS → $HEALTH_URL"
else
    warn "Sağlık kontrolü başarısız (HTTP $HTTP_STATUS). Container logları:"
    docker logs soc-backend --tail=30
fi

# ─── Sonuç Raporu ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  ✅  DEPLOYMENT TAMAMLANDI                               ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Backend API   : http://localhost:8000                   ║${NC}"
echo -e "${BOLD}║  API Docs      : http://localhost:8000/docs              ║${NC}"
echo -e "${BOLD}║  Container Log : docker logs soc-backend -f              ║${NC}"
echo -e "${BOLD}║  Deploy Log    : $LOG_FILE             ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Durdurmak için: docker compose down                     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
info "Tamamlanma: $(date -u)"
