# SmartWAF Startup Script (Windows PowerShell)
Write-Host "🛡️ SmartWAF - Web Application Firewall" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green

# .env file check
if (-not (Test-Path ".env")) {
    Write-Host "⚠️  .env file not found!" -ForegroundColor Yellow
    Write-Host "Copy env.example as .env and edit it" -ForegroundColor Yellow
    exit 1
}

# Python check
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python available: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python not installed!" -ForegroundColor Red
    exit 1
}

# Virtual Environment check
if (-not (Test-Path "smartwaf-env")) {
    Write-Host "⚠️  Virtual environment not found. Creating..." -ForegroundColor Yellow
    python -m venv smartwaf-env
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Virtual environment created" -ForegroundColor Green
    } else {
        Write-Host "❌ Virtual environment could not be created!" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "✅ Virtual environment available" -ForegroundColor Green
}

# Install dependencies
Write-Host "📦 Installing Python dependencies..." -ForegroundColor Blue
& "smartwaf-env\Scripts\Activate.ps1"
pip install -r requirements.txt

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Dependencies installed successfully!" -ForegroundColor Green
} else {
    Write-Host "❌ Dependency installation error!" -ForegroundColor Red
    exit 1
}

# Start Flask application
Write-Host "🚀 Starting SmartWAF..." -ForegroundColor Blue
Write-Host "📊 Dashboard: http://localhost:3000" -ForegroundColor Cyan
Write-Host "🔍 Test: http://localhost:5000" -ForegroundColor Cyan
Write-Host "⏹️  To stop: Ctrl+C" -ForegroundColor Yellow

& "smartwaf-env\Scripts\Activate.ps1"
python app.py
