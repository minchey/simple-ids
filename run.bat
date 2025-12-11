@echo off
cd /d "%~dp0"

echo ============================================
echo   Simple IDS Running...
echo ============================================

runtime\bin\java -jar build\libs\simple-ids.jar

pause
