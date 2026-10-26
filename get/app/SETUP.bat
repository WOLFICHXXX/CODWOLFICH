@echo off
chcp 65001 >nul
cd /d "%~dp0"
title WOLFICH - установка
echo.
echo   WOLFICH · Автопоход - установка / обновление
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $d=(Get-Location).Path; if (-not (Test-Path -LiteralPath (Join-Path $d 'WOLFICH.exe'))) { if (-not (Test-Path -LiteralPath (Join-Path $d 'electron.exe'))) { Write-Host '  Скачиваю Electron с GitHub (около 110 МБ), пара минут...'; $z=Join-Path $d 'electron-download.zip'; Invoke-WebRequest -Uri 'https://github.com/electron/electron/releases/download/v33.4.11/electron-v33.4.11-win32-x64.zip' -OutFile $z -UseBasicParsing; Write-Host '  Распаковываю...'; Expand-Archive -LiteralPath $z -DestinationPath $d -Force; Remove-Item -LiteralPath $z -Force -ErrorAction SilentlyContinue }; Rename-Item -LiteralPath (Join-Path $d 'electron.exe') -NewName 'WOLFICH.exe' } else { Write-Host '  WOLFICH.exe уже есть - обновляю только файлы программы.' }; Remove-Item -LiteralPath (Join-Path $d 'resources\default_app.asar') -Force -ErrorAction SilentlyContinue; $s=(New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'WOLFICH.lnk')); $s.TargetPath=(Join-Path $d 'WOLFICH.exe'); $s.WorkingDirectory=$d; $s.Save()"
if errorlevel 1 (
  echo.
  echo   Не получилось. Проверьте интернет и запустите SETUP.bat ещё раз.
  pause
  exit /b 1
)
echo.
echo   Готово! Ярлык WOLFICH на рабочем столе. Запускаю программу...
explorer.exe "%~dp0WOLFICH.exe"
timeout /t 3 >nul
