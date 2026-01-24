"""
🚀 E-ENCRYPT LAUNCH SCRIPT
Run both backend and web interface
"""

import subprocess
import sys
import os
import time
from pathlib import Path


def install_requirements():
    """Install required packages"""
    print("📦 Installing requirements...")

    # Backend requirements
    print("Installing backend requirements...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "backend/requirements.txt"])

    # Web requirements
    print("Installing web requirements...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "web/requirements.txt"])

    print("✅ All requirements installed!")


def run_backend():
    """Start the FastAPI backend server"""
    print("🚀 Starting backend server...")
    backend_process = subprocess.Popen(
        [sys.executable, "backend/main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # Wait for backend to start
    time.sleep(3)

    # Check if backend is running
    try:
        import requests
        response = requests.get("http://localhost:8000/api/health", timeout=2)
        if response.status_code == 200:
            print("✅ Backend server is running on http://localhost:8000")
            return backend_process
    except:
        print("❌ Backend failed to start")
        return None


def run_web():
    """Start the Streamlit web interface"""
    print("🌐 Starting web interface...")
    web_process = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "web/app.py", "--server.port", "8501"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # Wait for web to start
    time.sleep(5)
    print("✅ Web interface is running on http://localhost:8501")
    return web_process


def check_dependencies():
    """Check if all dependencies are installed"""
    required_packages = [
        "fastapi", "streamlit", "websockets", "Pillow", "numpy",
        "python-jose", "passlib", "python-multipart", "bcrypt"
    ]

    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
        except ImportError:
            missing_packages.append(package)

    return missing_packages


def main():
    """Main launch function"""
    print("🔐 E-ENCRYPT SECURE MESSENGER")
    print("=" * 40)

    # Check if requirements are installed
    missing = check_dependencies()
    if missing:
        print(f"Missing packages: {', '.join(missing)}")
        install = input("Do you want to install missing packages? (y/n): ")
        if install.lower() == 'y':
            install_requirements()
        else:
            print("Please install requirements manually:")
            print("pip install -r backend/requirements.txt")
            print("pip install -r web/requirements.txt")
            return

    # Create necessary directories
    os.makedirs("uploads", exist_ok=True)

    # Start backend
    backend_proc = run_backend()
    if not backend_proc:
        print("Failed to start backend. Exiting...")
        return

    # Start web interface
    web_proc = run_web()

    print("\n" + "=" * 40)
    print("🎯 E-ENCRYPT IS NOW RUNNING!")
    print("\n🔗 URLs:")
    print("  Backend API: http://localhost:8000")
    print("  Web Interface: http://localhost:8501")
    print("  API Documentation: http://localhost:8000/docs")
    print("\n👤 Test Users (password: password123):")
    print("  - alice, bob, charlie, david, emma")
    print("\n🛑 Press Ctrl+C to stop all servers")
    print("=" * 40)

    try:
        # Keep processes running
        backend_proc.wait()
        web_proc.wait()
    except KeyboardInterrupt:
        print("\n🛑 Stopping servers...")
        backend_proc.terminate()
        web_proc.terminate()
        print("✅ Servers stopped.")


if __name__ == "__main__":
    main()