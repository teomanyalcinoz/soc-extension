<#
.SYNOPSIS
    TracePoint Projesi Otomatik Kurulum ve Çalıştırma Betiği
#>

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " TracePoint Otomatik Kurulum ve Baslatma Araci " -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# 1. Python Kontrolü
Write-Host "[*] Python kurulumu kontrol ediliyor..." -ForegroundColor Yellow
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[!] HATA: Python yuklu degil veya PATH'e eklenmemis!" -ForegroundColor Red
    Write-Host "[!] Lutfen Python'u (>=3.8) indirip kurun (kurulumda 'Add Python to PATH' secenegini isaretlemeyi unutmayin)." -ForegroundColor Red
    Write-Host "[!] https://www.python.org/downloads/" -ForegroundColor Cyan
    Read-Host "Cikmak icin Enter'a basin..."
    exit
}
Write-Host "[+] Python kurulu." -ForegroundColor Green

# 2. Dizin Kontrolü
$BackendDir = Join-Path -Path $PSScriptRoot -ChildPath "backend"
if (!(Test-Path -Path $BackendDir)) {
    Write-Host "[!] HATA: 'backend' klasoru bulunamadi! Betigi proje ana dizininde calistirdiginizdan emin olun." -ForegroundColor Red
    Read-Host "Cikmak icin Enter'a basin..."
    exit
}

# 3. Virtual Environment (venv) Kontrolü ve Kurulumu
$VenvDir = Join-Path -Path $BackendDir -ChildPath "venv"
if (!(Test-Path -Path $VenvDir)) {
    Write-Host "[*] Sanal ortam (venv) bulunamadi, olusturuluyor..." -ForegroundColor Yellow
    Set-Location -Path $BackendDir
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] HATA: Sanal ortam olusturulamadi!" -ForegroundColor Red
        Read-Host "Cikmak icin Enter'a basin..."
        exit
    }
    Write-Host "[+] Sanal ortam basariyla olusturuldu." -ForegroundColor Green
    Set-Location -Path $PSScriptRoot
} else {
    Write-Host "[+] Sanal ortam zaten mevcut." -ForegroundColor Green
}

# 4. Gereksinimlerin (requirements.txt) Yüklenmesi
Write-Host "[*] Bagimliliklar (requirements) yukleniyor/kontrol ediliyor..." -ForegroundColor Yellow
$PipExe = Join-Path -Path $VenvDir -ChildPath "Scripts\pip.exe"
$RequirementsFile = Join-Path -Path $BackendDir -ChildPath "requirements.txt"

if (Test-Path -Path $RequirementsFile) {
    & $PipExe install -r $RequirementsFile
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] HATA: Bagimliliklar yuklenirken bir sorun olustu!" -ForegroundColor Red
        Read-Host "Cikmak icin Enter'a basin..."
        exit
    }
    Write-Host "[+] Bagimliliklar basariyla yuklendi." -ForegroundColor Green
} else {
    Write-Host "[-] Uyari: requirements.txt bulunamadi." -ForegroundColor DarkYellow
}

# 5. .env Dosyası Kontrolü
$EnvFile = Join-Path -Path $BackendDir -ChildPath ".env"
if (!(Test-Path -Path $EnvFile)) {
    Write-Host "[*] .env dosyasi bulunamadi, ornek bir .env olusturuluyor..." -ForegroundColor Yellow
    $EnvContent = @"
# Splunk Ayarları
SPLUNK_URL=https://your-splunk-instance:8089
SPLUNK_TOKEN=your-splunk-rest-token
SPLUNK_VERIFY_SSL=False

# Azure OpenAI LLM Ayarları
LLM_MODEL=gpt-5.1-ptu
LLM_URL=https://apim-ai-management.azure-api.net/.../chat/completions?api-version=2024-12-01-preview
LLM_API_VERSION=2024-12-01-preview
LLM_API_KEY=your-api-key
"@
    Set-Content -Path $EnvFile -Value $EnvContent
    Write-Host "[+] ornek .env dosyasi olusturuldu. Gerekli API anahtarlarini bu dosyaya girmelisiniz." -ForegroundColor Green
} else {
    Write-Host "[+] .env dosyasi mevcut." -ForegroundColor Green
}

# 6. Sunucuyu Başlatma
Write-Host "[*] FastAPI Sunucusu baslatiliyor..." -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
$PythonExe = Join-Path -Path $VenvDir -ChildPath "Scripts\python.exe"

Set-Location -Path $BackendDir
& $PythonExe main.py
