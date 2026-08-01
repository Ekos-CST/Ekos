@echo off
title C Antivirus Engine GUI Launcher
color 0A

echo =======================================================
echo     C ANTIVIRUS ENGINE GUI DASHBOARD LAUNCHER
echo =======================================================
echo.

cd /d "%~dp0gui"

echo Node.js backend sunucusu baslatiliyor...
echo Tarayici otomatik olarak http://localhost:3000 adresinde acilacak.
echo.

start "" http://localhost:3000
node server.js

pause
