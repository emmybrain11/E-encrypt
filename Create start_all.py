#!/usr/bin/env python3
"""
Start All E-Encrypt Services
Run: python start_all.py
"""

import subprocess
import sys
import os
import time
import webbrowser
from pathlib import Path


def check_dependencies():
    """Check if required packages are installed"""
    required = ['requests', 'streamlit', 'websocket-client']
    missing = []

    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)

    return missing


def install_dependencies():
    """Install missing dependencies"""
    print("📦 Installing missing dependencies...")

    packages = ['requests', 'streamlit', 'websocket-client']
    for package in packages:
        print(f"  Installing {package}...")
        subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)

    print("✅ Dependencies installed!")


def start_backend():
    """Start the backend server"""
    print("\n🚀 Starting E-Encrypt Backend...")

    # Check if backend file exists
    if not os.path.exists("backend_api.py"):
        print("❌ backend_api.py not found!")
        print("Please make sure you're in the correct directory.")
        return None

    # Start backend in background
    backend_proc = subprocess.Popen(
        [sys.executable, "backend_api.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    # Wait for backend to start
    print("⏳ Waiting for backend to start...")
    time.sleep(3)

    # Check if backend is running
    import requests
    try:
        response = requests.get("http://localhost:8000/api/health", timeout=5)
        if response.status_code == 200:
            print("✅ Backend started successfully!")
            print(f"   API Docs: http://localhost:8000/api/docs")
            return backend_proc
        else:
            print("⚠️  Backend started but with errors")
            return backend_proc
    except:
        print("❌ Backend failed to start")
        return None


def start_web_app():
    """Start the web app"""
    print("\n🌐 Starting E-Encrypt Web App...")

    if not os.path.exists("main_web_backend.py"):
        print("❌ main_web_backend.py not found!")
        print("Using main_web.py instead...")
        if not os.path.exists("main_web.py"):
            print("❌ No web app found!")
            return None
        web_file = "main_web.py"
    else:
        web_file = "main_web_backend.py"

    # Start web app in background
    web_proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", web_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    print("⏳ Waiting for web app to start...")
    time.sleep(5)

    print("✅ Web app started!")
    print(f"   URL: http://localhost:8501")
    return web_proc


def start_desktop_app():
    """Start the desktop app"""
    print("\n💻 Starting E-Encrypt Desktop App...")

    if not os.path.exists("main_desktop_backend.py"):
        print("❌ main_desktop_backend.py not found!")
        print("Using original desktop app...")
        if not os.path.exists("main_desktop.py"):
            print("❌ No desktop app found!")
            return None
        desktop_file = "main_desktop.py"
    else:
        desktop_file = "main_desktop_backend.py"

    # Start desktop app in foreground
    print("✅ Desktop app starting in new window...")
    print("   (Close the app window to stop it)")

    desktop_proc = subprocess.Popen(
        [sys.executable, desktop_file],
        creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0
    )

    return desktop_proc


def main():
    """Main function"""
    print("=" * 60)
    print("🔐 E-Encrypt - Complete System Startup")
    print("=" * 60)

    # Check dependencies
    missing = check_dependencies()
    if missing:
        print(f"❌ Missing dependencies: {', '.join(missing)}")
        response = input("📦 Install missing dependencies? (y/n): ")
        if response.lower() == 'y':
            install_dependencies()
        else:
            print("⚠️  Some features may not work without dependencies")

    print("\n" + "=" * 60)
    print("Select services to start:")
    print("1. 🔙 Backend API Server (required for others)")
    print("2. 🌐 Web Application")
    print("3. 💻 Desktop Application")
    print("4. 🚀 All services")
    print("5. ❌ Exit")

    choice = input("\nEnter your choice (1-5): ")

    processes = []

    try:
        if choice in ['1', '4']:
            backend_proc = start_backend()
            if backend_proc:
                processes.append(('Backend', backend_proc))

            if choice == '1':
                # Just backend, wait for user to stop
                print("\n✅ Backend running. Press Ctrl+C to stop.")
                webbrowser.open("http://localhost:8000/api/docs")
                backend_proc.wait()

        if choice in ['2', '4']:
            web_proc = start_web_app()
            if web_proc:
                processes.append(('Web App', web_proc))
                webbrowser.open("http://localhost:8501")

        if choice in ['3', '4']:
            desktop_proc = start_desktop_app()
            if desktop_proc:
                processes.append(('Desktop App', desktop_proc))

        if choice == '5':
            print("👋 Goodbye!")
            return

        if choice in ['2', '3', '4'] and processes:
            print("\n" + "=" * 60)
            print("✅ Services started successfully!")
            print("\nRunning services:")
            for name, proc in processes:
                print(f"  • {name}")

            print("\n🔗 Quick Links:")
            if any(name == 'Backend' for name, _ in processes):
                print("  • Backend API: http://localhost:8000")
                print("  • API Docs: http://localhost:8000/api/docs")
            if any(name == 'Web App' for name, _ in processes):
                print("  • Web App: http://localhost:8501")

            print("\n🔑 Test Users (username:password):")
            print("  • alice:password123")
            print("  • bob:password123")
            print("  • charlie:password123")
            print("  • david:password123")
            print("  • emma:password123")

            print("\n" + "=" * 60)
            print("Press Ctrl+C to stop all services")

            # Wait for interrupt
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n🛑 Stopping all services...")

    except KeyboardInterrupt:
        print("\n🛑 Stopping all services...")

    except Exception as e:
        print(f"\n❌ Error: {e}")

    finally:
        # Stop all processes
        for name, proc in processes:
            print(f"  Stopping {name}...")
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except:
                try:
                    proc.kill()
                except:
                    pass

        print("\n👋 All services stopped. Goodbye!")


if __name__ == "__main__":
    main()