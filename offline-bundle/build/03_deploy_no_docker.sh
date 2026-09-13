#!/usr/bin/env bash
# =============================================================================
#  OPSIYONEL: Docker daemon'un olmadığı, sadece Python/venv kullanan
#             ortamlar için saf Python deploy betiği (Docker-free mode)
#
#  Kullanım: bash scripts/03_deploy_no_docker.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_ROOT="/opt/soc-extension"
VENV_PATH="$DEPLOY_ROOT/venv"
WHEELS_DIR="$BUNDLE_DIR/wheels"
PID_FILE="$DEPLOY_ROOT/soc-backend.pid"
LOG_FILE="$DEPLOY_ROOT/logs/uvicorn.log"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  SOC-EXTENSION — Docker-Free Offline Deploy           ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# Root kontrolü
[[ "$EUID" -ne 0 ]] && error "Root (sudo) ile çalıştırın."

# ─── Dizinler ─────────────────────────────────────────────────────────────────
info "▶ [1/5] Dizinler hazırlanıyor..."
mkdir -p "$DEPLOY_ROOT"/{logs,config}
success "Dizinler: $DEPLOY_ROOT"

# ─── Kaynak Kod ───────────────────────────────────────────────────────────────
info "▶ [2/5] Kaynak kod kopyalanıyor..."
mkdir -p "$DEPLOY_ROOT/backend"
if command -v rsync &>/dev/null; then
    rsync -a --delete "$BUNDLE_DIR/source/backend/" "$DEPLOY_ROOT/backend/"
else
    cp -rf "$BUNDLE_DIR/source/backend/"* "$DEPLOY_ROOT/backend/"
fi
success "Backend: $DEPLOY_ROOT/backend/"

# ─── Virtual Environment ──────────────────────────────────────────────────────
info "▶ [3/5] Python virtual environment oluşturuluyor..."
if [[ ! -d "$VENV_PATH" ]]; then
    python3 -m venv "$VENV_PATH"
    success "venv oluşturuldu: $VENV_PATH"
else
    success "Mevcut venv kullanılıyor: $VENV_PATH"
fi

# ─── Offline pip Kurulumu ─────────────────────────────────────────────────────
info "▶ [4/5] Bağımlılıklar offline olarak kuruluyor (--no-index)..."
WHEEL_COUNT=$(ls "$WHEELS_DIR"/*.whl 2>/dev/null | wc -l)
[[ "$WHEEL_COUNT" -eq 0 ]] && error "Wheel dosyası bulunamadı: $WHEELS_DIR"

"$VENV_PATH/bin/pip" install \
    --no-index \
    --find-links="$WHEELS_DIR" \
    --upgrade pip setuptools wheel

"$VENV_PATH/bin/pip" install \
    --no-index \
    --find-links="$WHEELS_DIR" \
    -r "$DEPLOY_ROOT/backend/requirements.txt"

success "$(${VENV_PATH}/bin/pip list | wc -l) paket kuruldu."

# ─── .env Konfigürasyonu ──────────────────────────────────────────────────────
ENV_FILE="$DEPLOY_ROOT/config/.env"
if [[ ! -f "$ENV_FILE" ]]; then
    if [[ -f "$BUNDLE_DIR/config/.env.template" ]]; then
        cp "$BUNDLE_DIR/config/.env.template" "$ENV_FILE"
    elif [[ -f "$BUNDLE_DIR/config/.env" ]]; then
        cp "$BUNDLE_DIR/config/.env" "$ENV_FILE"
    else
        touch "$ENV_FILE"
    fi
    warn "YENİ .env oluşturuldu. Düzenleyin: nano $ENV_FILE"
fi
ln -sf "$ENV_FILE" "$DEPLOY_ROOT/backend/.env"

# ─── Mevcut Süreci Durdur ─────────────────────────────────────────────────────
systemctl stop soc-backend 2>/dev/null || true
pkill -f uvicorn 2>/dev/null || true
fuser -k 8000/tcp 2>/dev/null || true
sleep 2
rm -f "$PID_FILE"

# ─── Uvicorn'u Başlat ─────────────────────────────────────────────────────────
info "▶ [5/5] Uvicorn başlatılıyor..."
mkdir -p "$DEPLOY_ROOT/logs"
cd "$DEPLOY_ROOT/backend"

nohup "$VENV_PATH/bin/uvicorn" main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 2 \
    --log-level info \
    >> "$LOG_FILE" 2>&1 &

NEW_PID=$!
echo "$NEW_PID" > "$PID_FILE"
sleep 3

if kill -0 "$NEW_PID" 2>/dev/null; then
    success "Uvicorn çalışıyor (PID: $NEW_PID)"
else
    echo "--- LOG ÇIKTISI ($LOG_FILE) ---"
    tail -n 25 "$LOG_FILE" 2>/dev/null || true
    echo "--------------------------------"
    error "Uvicorn başlatılamadı. Yukarıdaki log detayını inceleyin."
fi

# ─── Systemd Servis Dosyası Oluştur ─────────────────────────────────────────
info "Systemd servis dosyası yazılıyor..."
cat > /etc/systemd/system/soc-backend.service <<SERVICEEOF
[Unit]
Description=SOC Extension Backend (Uvicorn)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${DEPLOY_ROOT}/backend
ExecStart=${VENV_PATH}/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2
Restart=always
RestartSec=5
EnvironmentFile=${ENV_FILE}
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable soc-backend.service 2>/dev/null || true
pkill -f uvicorn 2>/dev/null || true
sleep 1
systemctl restart soc-backend.service 2>/dev/null || true
success "Systemd servisi etkinleştirildi ve başlatıldı: soc-backend.service"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  ✅  DOCKER-FREE DEPLOYMENT TAMAMLANDI               ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║  Backend : http://localhost:8000                     ║${NC}"
echo -e "${BOLD}║  Log     : tail -f $LOG_FILE         ║${NC}"
echo -e "${BOLD}║  Servis  : systemctl status soc-backend              ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
