Set-Location $PSScriptRoot
$env:TRUSTNET_CORS_ORIGINS = 'http://localhost:8081,http://127.0.0.1:8081,http://localhost:8080,http://127.0.0.1:8080,http://localhost:5173,http://127.0.0.1:5173'
$env:TRUSTNET_DEMO_ALLOW_NEW_DEVICE = '1'
$env:TRUSTNET_TOTP_KEY = 'local-demo-totp-key-change-this-32-chars'
$env:TRUSTNET_AUDIT_CHECKPOINT_KEY = 'local-demo-audit-key-change-this-32-chars'
$env:TRUSTNET_DB_PATH = 'backend/data/trustnet.db'
$env:TRUSTNET_SMTP_HOST = 'smtp.gmail.com'
$env:TRUSTNET_SMTP_PORT = '587'
$env:TRUSTNET_SMTP_USER = 'sumukhbhat66@gmail.com'
$env:TRUSTNET_SMTP_FROM = 'sumukhbhat66@gmail.com'
$env:TRUSTNET_ALERT_EMAILS = 'sumukhbhat66@gmail.com'
$env:TRUSTNET_NOTIFY_COOLDOWN_MINUTES = '0'
$secure = Read-Host 'Gmail app password for sumukhbhat66@gmail.com' -AsSecureString
$env:TRUSTNET_SMTP_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
& 'C:/Program Files/Python313/python.exe' -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8010
