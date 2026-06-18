@echo off
REM ============================================================
REM  Argo - double-click launcher (Windows)
REM  Starts the web app and opens it in your browser.
REM  Keep this window open while using the app; close it to stop.
REM ============================================================
cd /d "%~dp0"
echo.
echo   Starting the Argo web app...
echo   It will open at http://127.0.0.1:8000
echo   (Keep this window open. Close it to stop the server.)
echo.
python -m argo.cli serve --open
echo.
echo   Server stopped.
pause
