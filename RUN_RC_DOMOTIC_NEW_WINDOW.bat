@echo off
setlocal
cd /d "%~dp0"
start "RC DOMOTIC" cmd /k "python -m pip install -r requirements.txt && python app.py"
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:5000"
endlocal
BAT
