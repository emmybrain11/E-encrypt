#!/usr/bin/env python3
"""
🚀 E-Encrypt Startup Script
Starts all applications at once
"""

import subprocess
import sys
import os
import time
import webbrowser
from datetime import datetime


def start_backend():
    print("🚀 Starting Backend API...")
    backend_proc = subprocess.Popen(
        [sys.executable, "backend_api.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    time.sleep(3)  # Give backend time to start

    # Check if backend is running
    try:
        import requests
        response = requests.get("http://localhost:8000/api/health", timeout=2)
        if response.status_code == 200:
            print("✅ Backend is running at http://localhost:8000")
            return backend_proc
        else:
            print("⚠️  Backend started but health check failed")
            return backend_proc
    except:
        print("⚠️  Backend may not be fully started")
        return backend_proc


def start_web_app():
    print("🌐 Starting Web Application...")
    web_proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "main_web_backend.py", "--server.port", "8501", "--server.headless",
         "true"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    time.sleep(2)

    # Open browser after delay
    def open_browser():
        time.sleep(3)
        print("🌐 Opening web browser...")
        webbrowser.open("http://localhost:8501")

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    return web_proc


def start_desktop_app():
    print("💻 Starting Desktop Application...")
    desktop_proc = subprocess.Popen(
        [sys.executable, "main_desktop_backend.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )
    time.sleep(1)
    return desktop_proc


def main():
    print("=" * 60)
    print("🔐 E-ENCRYPT - ALL APPLICATIONS")
    print("=" * 60)
    print()
    print("Starting all applications...")
    print("You can access:")
    print("  • Backend API:    http://localhost:8000")
    print("  • Web App:        http://localhost:8501")
    print("  • Desktop App:    Will open automatically")
    print()
    print("Test users: alice, bob, charlie, david, emma")
    print("Password for all: password123")
    print()
    print("Press Ctrl+C to stop all applications")
    print()

    processes = []

    try:
        # Start backend
        backend_proc = start_backend()
        processes.append(("Backend API", backend_proc))

        # Start web app
        web_proc = start_web_app()
        processes.append(("Web App", web_proc))

        # Start desktop app
        desktop_proc = start_desktop_app()
        processes.append(("Desktop App", desktop_proc))

        print()
        print("=" * 60)
        print("✅ ALL APPLICATIONS STARTED!")
        print("=" * 60)
        print()
        print("Applications running:")
        print("  1. Backend API - http://localhost:8000")
        print("  2. Web Interface - http://localhost:8501")
        print("  3. Desktop App - Running in window")
        print()
        print("To stop all applications, press Ctrl+C")
        print()

        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping all applications...")

    except KeyboardInterrupt:
        print("\n🛑 Installation interrupted")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        # Kill all processes
        for name, proc in processes:
            if proc and proc.poll() is None:
                print(f"  Stopping {name}...")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except:
                    proc.kill()

        print()
        print("✅ All applications stopped")
        print("=" * 60)


if __name__ == "__main__":
    main()