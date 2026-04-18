@echo off
setlocal
title RC DOMOTIC - Cotizador

REM === Ir a la carpeta del proyecto (donde está este .bat) ===
cd /d "%~dp0"

REM === Verificar Python ===
where python >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python no esta instalado o no esta en el PATH.
  echo Instala Python 3.10+ y marca "Add python to PATH".
  pause
  exit /b 1
)

REM === (Opcional) entorno virtual ===
if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"

REM === Instalar dependencias ===
if exist "requirements.txt" (
  python -m pip install -r requirements.txt
)

REM === Abrir el navegador (no falla si el servidor tarda) ===
start "" "http://127.0.0.1:5000"

REM === Iniciar servidor (queda en esta misma ventana) ===
echo.
echo Iniciando RC DOMOTIC... (para detener: CTRL + C)
echo.
python app.py

endlocal
BAT
