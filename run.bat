@echo off
start "" /b powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=(Get-Date).AddSeconds(60); while ((Get-Date) -lt $d) { try { $c=[Net.Sockets.TcpClient]::new(); $c.Connect('localhost',50677); $c.Dispose(); Start-Process 'http://localhost:50677/'; break } catch { Start-Sleep -Milliseconds 500 } }"
dotnet run --project v2\Blazor
