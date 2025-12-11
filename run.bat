@echo off
cd /d "%~dp0"

echo ============================================
echo   Simple IDS 실행중...
echo ============================================

runtime\bin\java -jar build\libs\simple-ids.jar

pause
