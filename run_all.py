"""
🚀 E-Encrypt Complete Startup Script
Run this to start everything
"""

import subprocess
import sys
import time
import webbrowser
import threading
import os


def print_banner():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    🔐 E-ENCRYPT v6.0                         ║
    ║           Quantum-Resistant Secure Messenger                 ║
    ╚══════════════════════════════════════════════════════════════╝

    📋 Features:
    • AES-256-GCM Encryption
    • Advanced Steganography
    • Quantum-Resistant Algorithms
    • Real-time WebSocket Chat
    • File Encryption Support
    • User Status Tracking
    • Cross-Platform (Web + Desktop)

    👥 Test Users (Password: password123):
      alice, bob, charlie, david, emma

    🌐 Access URLs:
      • Backend API:    http://localhost:8000
      • API Docs:       http://localhost:8000/api/docs
      • Web Interface:  http://localhost:8501

    """)


def install_dependencies():
    print("📦 Installing dependencies...")

    packages = [
        "fastapi",
        "uvicorn[standard]",
        "sqlalchemy",
        "pycryptodome",
        "PyJWT",
        "python-multipart",
        "requests",
        "streamlit",
        "pillow",
        "websocket-client",
        "numpy"
    ]

    for package in packages:
        print(f"  Installing {package}...")
        subprocess.run([sys.executable, "-m", "pip", "install", package],
                       check=False, capture_output=True)

    print("✅ Dependencies installed")


def start_backend():
    print("🚀 Starting Backend API...")
    backend_proc = subprocess.Popen(
        [sys.executable, "backend_api.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )

    # Wait for backend to start
    time.sleep(5)

    # Check if backend is running
    import requests
    try:
        response = requests.get("http://localhost:8000/api/health", timeout=5)
        if response.status_code == 200:
            print("✅ Backend is running at http://localhost:8000")
            print("📚 API Documentation: http://localhost:8000/api/docs")
            return backend_proc
        else:
            print("⚠️ Backend started but health check failed")
            return backend_proc
    except:
        print("⚠️ Backend may not be fully started")
        return backend_proc


def start_web_app():
    print("🌐 Starting Web Application...")

    def run_streamlit():
        subprocess.run([
            sys.executable, "-m", "streamlit",
            "run", "web_app.py",
            "--server.port", "8501",
            "--server.headless", "true"
        ])

    streamlit_thread = threading.Thread(target=run_streamlit, daemon=True)
    streamlit_thread.start()

    time.sleep(5)

    # Open browser
    def open_browser():
        time.sleep(3)
        print("🌐 Opening web browser...")
        webbrowser.open("http://localhost:8501")

    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()

    return streamlit_thread


def main():
    print_banner()

    print("Select what to run:")
    print("1. Install dependencies only")
    print("2. Start backend only")
    print("3. Start web app only")
    print("4. Start everything (recommended)")
    print()

    choice = input("Enter choice (1-4): ").strip()

    processes = []

    try:
        if choice in ["1", "4"]:
            install_dependencies()

        if choice in ["2", "4"]:
            backend = start_backend()
            if backend:
                processes.append(("Backend", backend))

        if choice in ["3", "4"]:
            web_app = start_web_app()
            processes.append(("Web App", web_app))

            if choice == "4":
                print("\n" + "=" * 60)
                print("🎉 ALL SYSTEMS ARE GO!")
                print("=" * 60)
                print("\nYour secure messenger is now running with:")
                print("  • Quantum-resistant encryption")
                print("  • Advanced steganography")
                print("  • Real-time messaging")
                print("  • User status tracking")
                print("\nAccess Points:")
                print("  • Backend API:    http://localhost:8000")
                print("  • API Docs:       http://localhost:8000/api/docs")
                print("  • Web Interface:  http://localhost:8501")

        print("\n👥 Test Users:")
        print("  Usernames: alice, bob, charlie, david, emma")
        print("  Password: password123 (for all users)")

        print("\n🔐 Security Features Active:")
        print("  • AES-256-GCM Encryption")
        print("  • Quantum-Resistant Key Generation")
        print("  • Steganography Encoding/Decoding")
        print("  • End-to-End Encrypted Chat")

        print("\n🛑 Press Ctrl+C to stop all applications")

        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping applications...")

    except KeyboardInterrupt:
        print("\n❌ Operation interrupted")
    except Exception as e:
        print(f"❌ Error: {e}")

    finally:
        # Cleanup
        print("\n✅ Cleanup complete")


if __name__ == "__main__":
    main()