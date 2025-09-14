# SmartWAF Başlatma Scripti (Windows PowerShell)
Write-Host "🛡️ SmartWAF - Web Application Firewall" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green

# .env dosyası kontrolü
if (-not (Test-Path ".env")) {
    Write-Host "⚠️  .env dosyası bulunamadı!" -ForegroundColor Yellow
    Write-Host "env.example dosyasını .env olarak kopyalayıp düzenleyin" -ForegroundColor Yellow
    exit 1
}

# Python kontrolü
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python mevcut: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python kurulu değil!" -ForegroundColor Red
    exit 1
}

# Virtual Environment kontrolü
if (-not (Test-Path "smartwaf-env")) {
    Write-Host "⚠️  Virtual environment bulunamadı. Oluşturuluyor..." -ForegroundColor Yellow
    python -m venv smartwaf-env
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Virtual environment oluşturuldu" -ForegroundColor Green
    } else {
        Write-Host "❌ Virtual environment oluşturulamadı!" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "✅ Virtual environment mevcut" -ForegroundColor Green
}

# Bağımlılıkları yükle
Write-Host "📦 Python bağımlılıkları yükleniyor..." -ForegroundColor Blue
& "smartwaf-env\Scripts\Activate.ps1"
pip install -r requirements.txt

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Bağımlılıklar başarıyla yüklendi!" -ForegroundColor Green
} else {
    Write-Host "❌ Bağımlılık yükleme hatası!" -ForegroundColor Red
    exit 1
}

# Flask uygulamasını başlat
Write-Host "🚀 SmartWAF başlatılıyor..." -ForegroundColor Blue
Write-Host "📊 Dashboard: http://localhost:3000" -ForegroundColor Cyan
Write-Host "🔍 Test: http://localhost:5000" -ForegroundColor Cyan
Write-Host "⏹️  Durdurmak için: Ctrl+C" -ForegroundColor Yellow

& "smartwaf-env\Scripts\Activate.ps1"
python app.py
