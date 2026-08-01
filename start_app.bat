@echo off
title Ekos Antivirus Program
color 0A

echo =======================================================
echo             EKOS ANTIVIRUS PROGRAM
echo =======================================================
echo.
echo Ekos Masaustu Uygulamasi Aciliyor...
echo.

cd /d "%~dp0gui"
npx electron .

pause
