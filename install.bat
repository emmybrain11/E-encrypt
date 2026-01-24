@echo off
echo Installing E-Encrypt Dependencies...
echo.

REM Create virtual environment
python -m venv venv
call venv\Scripts\activate.bat

REM Upgrade pip
python -m pip install --upgrade pip

REM Install requirements
pip install streamlit>=1.28.0
pip install fastapi>=0.104.0
pip install uvicorn>=0.24.0
pip install pillow>=10.0.0
pip install pycryptodome>=3.19.0
pip install numpy>=1.24.0
pip install "python-jose[cryptography]">=3.3.0
pip install "passlib[bcrypt]">=1.7.4
pip install python-multipart>=0.0.6
pip install sqlalchemy>=2.0.0

echo.
echo Installation complete!
echo.
echo To run the web app:
echo   streamlit run main_web.py
echo.
echo To run the backend:
echo   python backend.py
pause