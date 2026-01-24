@echo off
echo Installing E-Encrypt Complete System...
echo.

REM Create virtual environment if not exists
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

echo Upgrading pip...
python -m pip install --upgrade pip

echo Installing backend dependencies...
pip install fastapi==0.104.0
pip install uvicorn[standard]==0.24.0
pip install sqlalchemy==2.0.23
pip install pycryptodome==3.19.0
pip install PyJWT==2.8.0
pip install python-multipart==0.0.6

echo Installing desktop app dependencies...
pip install kivy==2.3.0
pip install pillow==10.0.0
pip install websocket-client==1.6.4

echo Installing web app dependencies...
pip install streamlit==1.28.0

echo.
echo ✅ Installation complete!
echo.
echo To start the backend:
echo   python backend_api_fixed.py
echo.
echo To start web app:
echo   streamlit run main_web_backend.py
echo.
echo To start desktop app:
echo   python main_desktop_backend.py
echo.
pause