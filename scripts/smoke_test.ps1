$ErrorActionPreference = 'Stop'
Write-Host "Health:"
Invoke-RestMethod -Uri 'http://127.0.0.1:8000/health' -Method Get | ConvertTo-Json -Depth 5

Write-Host "`nChat:"
$body = @{
  session_id = 'smoke'
  prompt = 'What is Cyranta Retail return policy?'
} | ConvertTo-Json
Invoke-RestMethod -Uri 'http://127.0.0.1:8000/chat' -Method Post -ContentType 'application/json' -Body $body | ConvertTo-Json -Depth 5
