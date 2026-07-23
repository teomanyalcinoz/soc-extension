# ============================================================================
#  ONLINE BUILD SERVER — SOC-EXTENSION Offline Bundle Packager (PowerShell)
#  Docker KULLANILMAZ. Sadece Python wheel + kaynak kod paketlenir.
#
#  Kullanım:
#    powershell -ExecutionPolicy Bypass .\01_package_online.ps1
# ============================================================================

# ── UYARI: param() bloğu her zaman ilk çalıştırılabilir satır olmali ────────
param(
    [string]$ProjectRoot     = (Resolve-Path "$PSScriptRoot\..\..").Path,
    [string]$OutputDir       = "$PSScriptRoot\dist",
    [string]$PythonVersion   = "3.11",          # Offline sunucudaki Python surumu
    [string]$TargetPlatform  = "win_amd64"       # Offline sunucu platformu (win_amd64 / linux_x86_64)
)

# ── UTF-8 (param()'dan SONRA gelir, burası doğru yer) ───────────────────────
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$ErrorActionPreference = "Stop"
$BundleVersion = (Get-Date -Format "yyyyMMdd-HHmmss")
$BundleName    = "soc-extension-bundle"
$BuildDir      = "$OutputDir\${BundleName}-${BundleVersion}"
$ArchiveName   = "${BundleName}-${BundleVersion}.zip"

# ── Yardımcı Fonksiyonlar ────────────────────────────────────────────────────
function Write-Step($msg) { Write-Host "`n>> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "[OK]   $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "=================================================" -ForegroundColor Magenta
Write-Host "  SOC-EXTENSION - Offline Bundle Packager"         -ForegroundColor Magenta
Write-Host "  Surum: $BundleVersion"                           -ForegroundColor Magenta
Write-Host "=================================================" -ForegroundColor Magenta
Write-Host ""

# ── On kosul kontrolu ────────────────────────────────────────────────────────
Write-Step "[1/4] On kosullar kontrol ediliyor..."

foreach ($cmd in @("pip", "python")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Err "'$cmd' bulunamadi. Python'un PATH'e ekli oldugunu kontrol edin."
    }
    Write-OK "$cmd mevcut: $((Get-Command $cmd).Source)"
}

$pythonVer = (python --version 2>&1).ToString()
Write-OK "Python: $pythonVer"

$requirementsFile = "$ProjectRoot\backend\requirements.txt"
if (-not (Test-Path $requirementsFile)) {
    Write-Err "requirements.txt bulunamadi: $requirementsFile"
}
Write-OK "requirements.txt bulundu."

# ── Dizin yapisi ─────────────────────────────────────────────────────────────
Write-Step "[2/4] Bundle dizin yapisi olusturuluyor..."

$subDirs = @("wheels", "source\backend", "frontend", "scripts", "config")
foreach ($d in $subDirs) {
    New-Item -ItemType Directory -Force -Path "$BuildDir\$d" | Out-Null
}
Write-OK "Dizinler hazir: $BuildDir"

# ── Python Wheel'larini indir ─────────────────────────────────────────────────
Write-Step "[3/4] Python wheel'lari indiriliyor..."
Write-Host "      Platform     : $TargetPlatform" -ForegroundColor Gray
Write-Host "      Python Surumu: $PythonVersion"  -ForegroundColor Gray
Write-Host "      Hedef Dizin  : $BuildDir\wheels" -ForegroundColor Gray

# ── Ana indirme: hedef platforma ozel binary wheel'lar ──────────────────────
Write-Host "   [1/2] Ana bagimliliklar indiriliyor..." -ForegroundColor Gray
pip download `
    --dest "$BuildDir\wheels" `
    --platform $TargetPlatform `
    --python-version $PythonVersion `
    --only-binary ":all:" `
    -r $requirementsFile

if ($LASTEXITCODE -ne 0) {
    # Fallback: uvicorn[standard] yerine sade uvicorn dene (httptools vs. native dep yok)
    Write-Warn "Bazi native wheel'lar bulunamadi. uvicorn[standard] yerine sade uvicorn deneniyor..."

    # requirements.txt'in gecici kopyasini olustur, uvicorn[standard] -> uvicorn yap
    $tmpReq = "$env:TEMP\requirements_fallback.txt"
    (Get-Content $requirementsFile) -replace 'uvicorn\[standard\]','uvicorn' | Set-Content $tmpReq

    pip download `
        --dest "$BuildDir\wheels" `
        --platform $TargetPlatform `
        --python-version $PythonVersion `
        --only-binary ":all:" `
        -r $tmpReq

    if ($LASTEXITCODE -ne 0) {
        # Son fallback: platformsuz indir (build makinesiyle ayni ise calisir)
        Write-Warn "Platform-specific indirme basarisiz. Platformsuz indiriliyor (build = offline ayni platform)..."
        pip download --dest "$BuildDir\wheels" -r $requirementsFile
        if ($LASTEXITCODE -ne 0) { Write-Err "pip download tamamen basarisiz oldu." }
    }

    # Fallback requirements.txt'i bundle'a kopyala (deploy'da kullanilacak)
    Copy-Item $tmpReq "$BuildDir\config\requirements_fallback.txt" -Force
    Write-Warn "'requirements_fallback.txt' olusturuldu (uvicorn[standard] -> uvicorn). Deploy scripti bunu kullanacak."
}

# ── pip / setuptools / wheel araclarini da ekle ──────────────────────────────
Write-Host "   [2/2] pip/setuptools/wheel arac wheel'lari indiriliyor..." -ForegroundColor Gray
pip download pip setuptools wheel `
    --dest "$BuildDir\wheels" `
    --platform $TargetPlatform `
    --python-version $PythonVersion `
    --only-binary ":all:"

$whlFiles = Get-ChildItem "$BuildDir\wheels\*.whl" -ErrorAction SilentlyContinue
Write-OK "$($whlFiles.Count) adet wheel dosyasi indirildi."

# ── Kaynak kodu kopyala ───────────────────────────────────────────────────────
Write-Step "[4/4] Kaynak kod kopyalaniyor..."

# Backend — .env, venv, __pycache__ haric
$backendSrc  = "$ProjectRoot\backend"
$backendDest = "$BuildDir\source\backend"
$excludeList = @("venv", "__pycache__", ".git", "node_modules", ".env")

Get-ChildItem $backendSrc -Recurse | Where-Object {
    $rel      = $_.FullName.Replace($backendSrc, "").TrimStart("\")
    $topLevel = ($rel -split "\\")[0]
    $excludeList -notcontains $topLevel
} | ForEach-Object {
    $destPath = $_.FullName.Replace($backendSrc, $backendDest)
    if ($_.PSIsContainer) {
        New-Item -ItemType Directory -Force -Path $destPath | Out-Null
    } else {
        Copy-Item $_.FullName -Destination $destPath -Force
    }
}
Write-OK "Backend kopyalandi: source\backend\"

# Frontend
$frontendSrc = "$ProjectRoot\frontend"
if (Test-Path $frontendSrc) {
    Copy-Item $frontendSrc "$BuildDir\frontend" -Recurse -Force
    Write-OK "Frontend kopyalandi: frontend\"
}

# ── .env Sablonu ─────────────────────────────────────────────────────────────
@"
# SOC-EXTENSION - Ortam Degiskenleri Sablonu
# Bu dosyayi .env olarak kopyalayip doldurun.
# ONEMLI: Bu dosyayi sunucuda gizli tutun (chmod 600 .env)

BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
LOG_LEVEL=info

# Yerel/offline LLM kullaniyorsaniz (Ollama vb.)
LLM_BASE_URL=http://localhost:11434
LLM_MODEL=llama3

# Guvenlik - mutlaka degistirin!
SECRET_KEY=CHANGE_ME_USE_A_STRONG_RANDOM_KEY
ALLOWED_ORIGINS=http://localhost,http://127.0.0.1
"@ | Set-Content "$BuildDir\config\.env.template" -Encoding UTF8

Write-OK ".env.template olusturuldu."

# Deploy betiklerini ekle
$deployScriptSrc = "$PSScriptRoot\03_deploy_no_docker.sh"
if (Test-Path $deployScriptSrc) {
    Copy-Item $deployScriptSrc "$BuildDir\scripts\" -Force
    Write-OK "Linux deploy betiği eklendi: scripts\03_deploy_no_docker.sh"
}

$windowsDeploySrc = "$PSScriptRoot\02_deploy_windows.ps1"
if (Test-Path $windowsDeploySrc) {
    Copy-Item $windowsDeploySrc "$BuildDir\scripts\" -Force
    Write-OK "Windows deploy betiği eklendi: scripts\02_deploy_windows.ps1"
}

# ── Manifest ─────────────────────────────────────────────────────────────────
@"
SOC-EXTENSION Offline Bundle
=============================
Surum       : $BundleVersion
Olusturulma : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Build Host  : $env:COMPUTERNAME
Python      : $PythonVersion
Docker      : KULLANILMIYOR (wheel/venv tabani)

Icerik:
  wheels\                  - Python .whl bagimlilik dosyalari ($($whlFiles.Count) adet)
  source\backend\          - FastAPI kaynak kodu (.env haric)
  frontend\                - Chrome Extension dosyalari
  config\.env.template     - Ortam degiskenleri sablonu
  scripts\03_deploy_no_docker.sh - Offline kurulum betigi

Kurulum icin:
  1. Bu arsivi offline sunucuya tasiyin
  2. tar -xzf *.tar.gz  (veya zip'i acin)
  3. sudo bash scripts/03_deploy_no_docker.sh
"@ | Set-Content "$BuildDir\MANIFEST.txt" -Encoding UTF8

# ── ZIP Arsivi ────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null }
$archivePath = "$OutputDir\$ArchiveName"

Compress-Archive -Path "$BuildDir\*" -DestinationPath $archivePath -Force

$sizeMB = [math]::Round((Get-Item $archivePath).Length / 1MB, 2)

Write-Host ""
Write-Host "=================================================" -ForegroundColor Green
Write-Host "  PAKETLEME TAMAMLANDI"                            -ForegroundColor Green
Write-Host "  Arsiv : $ArchiveName"                           -ForegroundColor Green
Write-Host "  Boyut : $sizeMB MB"                              -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host ""
Write-Host "SONRAKI ADIM: Arsivi offline sunucuya tasiyin"    -ForegroundColor Yellow
Write-Host "ve scripts/03_deploy_no_docker.sh calistirin."    -ForegroundColor Yellow
Write-Host ""
