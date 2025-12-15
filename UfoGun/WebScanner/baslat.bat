@echo off
title UfoGun Scanner Console
echo [BILGI] Gerekli kutuphaneler kontrol ediliyor...
pip install -r requirements.txt
cls

echo ===================================================
echo   UFOGUN SCANNER SYSTEM BASLATILIYOR
echo ===================================================
echo.
echo [1] Sunucu hazirlaniyor...
echo [2] Internet tarayicisi aciliyor...
echo.

start http://127.0.0.1:5000

echo [3] Sistem hazir. Arayuz uzerinden tarama yapabilirsiniz.
echo [BILGI] Kapatmak icin bu pencereyi kapatin.
echo.

python server.py
pause
