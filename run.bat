@echo off
echo ============================================
echo   Simple IDS 실행중...
echo   (Npcap이 설치되어 있어야 합니다)
echo ============================================
echo.

runtime\bin\java -jar untitled-1.0-SNAPSHOT-all.jar

echo.
echo --------------------------------------------
echo   프로그램이 종료되었습니다.
echo   창을 닫으려면 아무 키나 누르세요...
echo --------------------------------------------
pause > nul
