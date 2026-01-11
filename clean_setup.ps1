# clean_setup.ps1
Write-Host "=== E-Encrypt Pro Clean Setup ===" -ForegroundColor Cyan

# Kill all Python processes
Write-Host "Stopping Python processes..." -ForegroundColor Yellow
taskkill /F /IM python.exe 2>$null
taskkill /F /IM pythonw.exe 2>$null

# Remove old venv if exists
if (Test-Path "venv") {
    Write-Host "Removing old virtual environment..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force venv -ErrorAction SilentlyContinue
}

# Create new venv
Write-Host "Creating new virtual environment..." -ForegroundColor Green
python -m venv venv

# Wait a moment
Start-Sleep -Seconds 2

# Activate
Write-Host "Activating virtual environment..." -ForegroundColor Green
try {
    .\venv\Scripts\Activate.ps1
} catch {
    Write-Host "Trying alternative activation..." -ForegroundColor Yellow
    .\venv\Scripts\activate
}

# Upgrade pip
Write-Host "Upgrading pip..." -ForegroundColor Green
python -m pip install --upgrade pip

# Install packages
Write-Host "`nInstalling packages..." -ForegroundColor Cyan
$packages = @(
    "kivy==2.3.0",
    "cryptography==41.0.7",
    "Pillow==10.1.0",
    "numpy==1.26.4",
    "plyer==2.1.0"
)

foreach ($pkg in $packages) {
    Write-Host "Installing $pkg..." -ForegroundColor Gray
    pip install $pkg
}

Write-Host "`n=== SETUP COMPLETE ===" -ForegroundColor Green
Write-Host "Run: python main.py" -ForegroundColor Yellow
Write-Host "Deactivate: deactivate" -ForegroundColor Cyan