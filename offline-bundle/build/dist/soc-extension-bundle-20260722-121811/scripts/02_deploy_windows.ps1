# ============================================================================
#  OFFLINE WINDOWS SUNUCU — SOC-EXTENSION Kurulum ve Deploy Scripti
#  Docker KULLANILMAZ. Python venv + pip (offline) + Windows Service
#
#  Kullanım:
#    1. ZIP'i sunucuya kopyalayın ve açın
#    2. Açılan klasörde PowerShell'i YÖNETİCİ olarak açın
#    3. powershell -ExecutionPolicy Bypass .\02_deploy_windows.ps1
#
#  Parametreler (isteğe bağlı):
#    -InstallDir   : Kurulum hedef dizini (varsayılan: C:\soc-extension)
#    -Port         : Backend port (varsayılan: 8000)
#    -ServiceName  : Windows servis adı (varsayılan: SocExtensionBackend)
#    -SkipService  : Servis kurmadan sadece başlat
# ============================================================================

param(
    [string]$InstallDir   = "C:\soc-extension",
    [int]$Port            = 8000,
    [string]$ServiceName  = "SocExtensionBackend",
    [switch]$SkipService
)

# ── UTF-8 (param()'dan sonra gelir) ─────────────────────────────────────────
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$ErrorActionPreference = "Stop"

# ── Bundle kök dizini (bu script neredeyse orası) ───────────────────────────
$BundleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($BundleRoot -like "*\scripts") {
    $BundleRoot = Split-Path -Parent $BundleRoot   # scripts\ içindeyse bir üst
}

# ── Yardımcı Fonksiyonlar ────────────────────────────────────────────────────
function Write-Step  { param($n,$msg) Write-Host "`n>> [$n] $msg" -ForegroundColor Cyan }
function Write-OK    { param($msg)    Write-Host "   [OK]    $msg" -ForegroundColor Green }
function Write-Warn  { param($msg)    Write-Host "   [WARN]  $msg" -ForegroundColor Yellow }
function Write-Err   { param($msg)    Write-Host "   [HATA]  $msg" -ForegroundColor Red; exit 1 }
function Write-Info  { param($msg)    Write-Host "   [INFO]  $msg" -ForegroundColor Gray }

Write-Host ""
Write-Host "=================================================" -ForegroundColor Magenta
Write-Host "  SOC-EXTENSION - Windows Offline Kurulum"        -ForegroundColor Magenta
Write-Host "  Bundle : $BundleRoot"                           -ForegroundColor Magenta
Write-Host "  Hedef  : $InstallDir"                           -ForegroundColor Magenta
Write-Host "  Port   : $Port"                                 -ForegroundColor Magenta
Write-Host "=================================================" -ForegroundColor Magenta

# ── Admin Kontrolü ───────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Err "Bu script Yonetici (Administrator) yetkisiyle calistirilmalidir. PowerShell'i 'Yonetici olarak ac' ile acin."
}
Write-OK "Yonetici yetkisi onaylandi."

# ============================================================================
#  ADIM 1 — Gerekli dosyaları kontrol et
# ============================================================================
Write-Step "1/6" "Bundle dosyalari kontrol ediliyor..."

$WheelsDir   = "$BundleRoot\wheels"
$SourceDir   = "$BundleRoot\source\backend"
$FrontendDir = "$BundleRoot\frontend"
$ConfigDir   = "$BundleRoot\config"
$ReqFile     = "$SourceDir\requirements.txt"

foreach ($path in @($WheelsDir, $SourceDir, $ReqFile)) {
    if (-not (Test-Path $path)) {
        Write-Err "Beklenen dosya/klasor bulunamadi: $path`nBundle dogru acildi mi? MANIFEST.txt dosyasini kontrol edin."
    }
}

$whlCount = (Get-ChildItem "$WheelsDir\*.whl" -ErrorAction SilentlyContinue).Count
Write-OK "wheels\     : $whlCount adet .whl dosyasi bulundu"
Write-OK "source\     : Backend kaynak kodu mevcut"
Write-OK "requirements.txt mevcut"

# ============================================================================
#  ADIM 2 — Python kontrolü
# ============================================================================
Write-Step "2/6" "Python kontrol ediliyor..."

$pythonCmd = $null
foreach ($candidate in @("python", "python3", "py")) {
    try {
        $ver = & $candidate --version 2>&1
        if ($ver -match "Python 3\.") {
            $pythonCmd = $candidate
            Write-OK "Python bulundu: $ver ($candidate)"
            break
        }
    } catch { }
}

if (-not $pythonCmd) {
    Write-Host ""
    Write-Err @"
Python 3 bulunamadi!
Offline sunucuda Python kurulu olmalidir.
Python'u offline kurmak icin:
  1. Baska bir makineden python.org'dan installer indirin (.exe)
  2. Bu sunucuya kopyalayip calistirin (internet gerekmez)
  3. Kurulum sirasinda 'Add Python to PATH' secenegini isaretleyin
"@
}

# ============================================================================
#  ADIM 3 — Kurulum dizinlerini hazırla
# ============================================================================
Write-Step "3/6" "Kurulum dizinleri hazirlaniyor: $InstallDir"

$subDirs = @("backend", "frontend", "venv", "logs", "config")
foreach ($d in $subDirs) {
    New-Item -ItemType Directory -Force -Path "$InstallDir\$d" | Out-Null
}
Write-OK "Dizinler olusturuldu."

# Backend kaynak kodunu kopyala
Write-Info "Backend kaynak kodu kopyalaniyor..."
$excludeNames = @("venv", "__pycache__", ".git", ".env")
Get-ChildItem $SourceDir -Recurse | Where-Object {
    $rel      = $_.FullName.Replace($SourceDir, "").TrimStart("\")
    $topLevel = ($rel -split "\\")[0]
    $excludeNames -notcontains $topLevel -and $_.Name -ne ".env"
} | ForEach-Object {
    $dest = $_.FullName.Replace($SourceDir, "$InstallDir\backend")
    if ($_.PSIsContainer) {
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
    } else {
        Copy-Item $_.FullName -Destination $dest -Force
    }
}
Write-OK "Backend kopyalandi -> $InstallDir\backend\"

# Frontend kopyala
if (Test-Path $FrontendDir) {
    Copy-Item "$FrontendDir\*" "$InstallDir\frontend\" -Recurse -Force
    Write-OK "Frontend kopyalandi -> $InstallDir\frontend\"
}

# ============================================================================
#  ADIM 4 — Virtual Environment + Offline pip kurulum
# ============================================================================
Write-Step "4/6" "Python virtual environment olusturuluyor..."

$VenvPath   = "$InstallDir\venv"
$PythonExe  = "$VenvPath\Scripts\python.exe"
$PipExe     = "$VenvPath\Scripts\pip.exe"
$UvicornExe = "$VenvPath\Scripts\uvicorn.exe"

# venv oluştur (yoksa)
if (-not (Test-Path $PythonExe)) {
    Write-Info "venv olusturuluyor..."
    & $pythonCmd -m venv $VenvPath
    Write-OK "venv olusturuldu: $VenvPath"
} else {
    Write-OK "Mevcut venv kullaniliyor: $VenvPath"
}

# pip, setuptools, wheel araçlarını önce yükle (--no-index)
Write-Info "pip/setuptools/wheel guncelleniyor (offline)..."
& $PipExe install `
    --no-index `
    --find-links="$WheelsDir" `
    --quiet `
    pip setuptools wheel

# Hangi requirements dosyasını kullanacağımıza karar ver
$FallbackReq = "$BundleRoot\config\requirements_fallback.txt"
if (Test-Path $FallbackReq) {
    $ActiveReqFile = $FallbackReq
    Write-Warn "requirements_fallback.txt bulundu (uvicorn[standard] -> uvicorn). Bu kullanilacak."
} else {
    $ActiveReqFile = $ReqFile
}

# Uygulama bağımlılıklarını yükle (tamamen offline)
Write-Info "Uygulama bagimliliklar yukleniyor (--no-index, internet yok)..."
& $PipExe install `
    --no-index `
    --find-links="$WheelsDir" `
    -r "$ActiveReqFile"

if ($LASTEXITCODE -ne 0) {
    # Son çare: uvicorn[standard] -> uvicorn fallback
    Write-Warn "Kurulum basarisiz. uvicorn[standard] -> uvicorn ile tekrar deneniyor..."
    $tmpReq = "$env:TEMP\requirements_deploy_fallback.txt"
    (Get-Content $ActiveReqFile) -replace 'uvicorn\[standard\]','uvicorn' | Set-Content $tmpReq
    & $PipExe install `
        --no-index `
        --find-links="$WheelsDir" `
        -r $tmpReq
    if ($LASTEXITCODE -ne 0) {
        Write-Err "pip install basarisiz. Wheel dosyalari eksik olabilir. $WheelsDir kontrol edin."
    }
    Write-Warn "Uvicorn standart ekstralar olmadan yuklendi (httptools yok, performans biraz dusuk olabilir)."
}

$pkgCount = (& $PipExe list 2>$null | Measure-Object -Line).Lines
Write-OK "$pkgCount paket basariyla yuklendi (offline, internetsiz)."

# ============================================================================
#  ADIM 5 — .env Konfigürasyonu
# ============================================================================
Write-Step "5/6" "Ortam degiskenleri (.env) ayarlaniyor..."

$EnvFile     = "$InstallDir\config\.env"
$EnvTemplate = "$ConfigDir\.env.template"

if (-not (Test-Path $EnvFile)) {
    if (Test-Path $EnvTemplate) {
        Copy-Item $EnvTemplate $EnvFile
        Write-Warn ".env olusturuldu. Lutfen duzenlemeyi unutmayin:"
        Write-Warn "  notepad $EnvFile"
    } else {
        # Şablon yoksa sıfırdan yaz
        @"
BACKEND_HOST=0.0.0.0
BACKEND_PORT=$Port
LOG_LEVEL=info
LLM_BASE_URL=http://localhost:11434
LLM_MODEL=llama3
SECRET_KEY=CHANGE_ME_USE_A_STRONG_RANDOM_KEY
ALLOWED_ORIGINS=http://localhost,http://127.0.0.1
"@ | Set-Content $EnvFile -Encoding UTF8
        Write-Warn ".env sifirdan olusturuldu. SECRET_KEY'i mutlaka degistirin!"
    }
} else {
    Write-OK "Mevcut .env korunuyor: $EnvFile"
}

# .env'yi backend klasörüne symlink / kopya ile bağla
Copy-Item $EnvFile "$InstallDir\backend\.env" -Force
Write-OK ".env backend klasorune kopyalandi."

# ============================================================================
#  ADIM 6 — Uygulamayı Başlat / Windows Service Kur
# ============================================================================
Write-Step "6/6" "Uygulama baslatiliyor..."

# --- Mevcut servisi / prosesi durdur -----------------------------------------
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Info "Mevcut servis durduruluyor: $ServiceName"
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Eski portdaki prosesi öldür
$oldProc = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($oldProc) {
    $pid = $oldProc.OwningProcess
    Write-Warn "Port $Port mesgul (PID: $pid), sonlandiriliyor..."
    Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

# --- Windows Service kurulumu -------------------------------------------------
if (-not $SkipService) {
    Write-Info "Windows Servisi kuruluyor: $ServiceName"

    # Servis başlatma komutu
    $uvicornArgs = "main:app --host 0.0.0.0 --port $Port --workers 2 --log-level info"
    $startupScript = "$InstallDir\start_backend.ps1"

    # Wrapper PS1 oluştur (servis bu scripti çalıştırır)
    @"
# SOC-Extension Backend Starter
Set-Location "$InstallDir\backend"
`$env:PYTHONPATH = "$InstallDir\backend"
Get-Content "$InstallDir\config\.env" | ForEach-Object {
    if (`$_ -match '^([^#][^=]*)=(.*)') {
        [System.Environment]::SetEnvironmentVariable(`$matches[1].Trim(), `$matches[2].Trim())
    }
}
& "$UvicornExe" main:app --host 0.0.0.0 --port $Port --workers 2 --log-level info
"@ | Set-Content $startupScript -Encoding UTF8

    # Servis silinip yeniden oluşturuluyor
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    # Powershell.exe'yi servis olarak kaydet
    $psExe  = (Get-Command powershell.exe).Source
    $binPath = "`"$psExe`" -NonInteractive -ExecutionPolicy Bypass -File `"$startupScript`""

    sc.exe create $ServiceName `
        binPath= $binPath `
        DisplayName= "SOC Extension Backend" `
        start= auto `
        obj= LocalSystem | Out-Null

    sc.exe description $ServiceName "SOC Extension FastAPI Backend (offline deployment)" | Out-Null
    sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/10000/restart/30000 | Out-Null

    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 5

    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -eq "Running") {
        Write-OK "Windows servisi calisiyor: $ServiceName"
    } else {
        Write-Warn "Servis beklenen durumda degil: $($svc.Status)"
        Write-Warn "Log: Get-EventLog -LogName Application -Source $ServiceName -Newest 10"
    }

} else {
    # -SkipService: direkt arkaplanda başlat
    Write-Info "-SkipService: Servis kurulmadan arkaplanda baslatiliyor..."
    $logFile = "$InstallDir\logs\uvicorn.log"
    Start-Process -FilePath $UvicornExe `
        -ArgumentList "main:app --host 0.0.0.0 --port $Port --workers 2" `
        -WorkingDirectory "$InstallDir\backend" `
        -RedirectStandardOutput $logFile `
        -RedirectStandardError "$InstallDir\logs\uvicorn_err.log" `
        -NoNewWindow
    Write-OK "Uvicorn arkaplanda baslatildi. Log: $logFile"
}

# ============================================================================
#  Sağlık Kontrolü
# ============================================================================
Write-Host ""
Write-Info "Saglik kontrolu bekleniyor (15 saniye)..."
Start-Sleep -Seconds 15

try {
    $resp = Invoke-WebRequest -Uri "http://localhost:$Port/health" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    Write-OK "Uygulama saglikli! HTTP $($resp.StatusCode) -> http://localhost:$Port"
} catch {
    Write-Warn "Saglik kontrolu basarisiz. Uygulama henuz hazir olmayabilir."
    Write-Warn "Manuel kontrol: Invoke-WebRequest http://localhost:$Port/health"
    if (-not $SkipService) {
        Write-Warn "Servis logu: Get-EventLog -LogName Application -Source '$ServiceName' -Newest 20"
    }
}

# ============================================================================
#  ÖZET
# ============================================================================
Write-Host ""
Write-Host "=================================================" -ForegroundColor Green
Write-Host "  KURULUM TAMAMLANDI"                             -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Green
Write-Host "  Backend API  : http://localhost:$Port"          -ForegroundColor White
Write-Host "  API Docs     : http://localhost:$Port/docs"     -ForegroundColor White
Write-Host "  Kurulum Dizin: $InstallDir"                     -ForegroundColor White
Write-Host "  .env Dosyasi : $EnvFile"                        -ForegroundColor White
if (-not $SkipService) {
Write-Host "  Servis Yonet : services.msc  (veya asagidaki komutlar)" -ForegroundColor White
Write-Host ""
Write-Host "  Durum   : Get-Service $ServiceName"             -ForegroundColor Gray
Write-Host "  Durdur  : Stop-Service $ServiceName"            -ForegroundColor Gray
Write-Host "  Baslat  : Start-Service $ServiceName"           -ForegroundColor Gray
Write-Host "  Sil     : sc.exe delete $ServiceName"           -ForegroundColor Gray
}
Write-Host "=================================================" -ForegroundColor Green
Write-Host ""
Write-Warn "ONEMLI: $EnvFile icindeki SECRET_KEY degerini degistirmeyi unutmayin!"
Write-Host ""
