#!/usr/bin/env python3
"""
Easy startup script for E-Encrypt Backend
"""

import os
import sys
import subprocess
import webbrowser
from pathlib import Path


def check_dependencies():
    """Check if required dependencies are installed"""
    required = ['fastapi', 'uvicorn', 'sqlalchemy', 'pycryptodome', 'python-jose']
    missing = []

    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)

    return missing


def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements_backend.txt"], check=True)
    print("✅ Dependencies installed successfully!")


def create_directories():
    """Create necessary directories"""
    directories = [
        "./backend",
        "./backend/uploads",
        "./backend/static",
        "./logs"
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"📁 Created directory: {directory}")


def start_server():
    """Start the backend server"""
    print("\n" + "=" * 50)
    print("🚀 Starting E-Encrypt Backend Server")
    print("=" * 50)

    # Set environment variables
    env = os.environ.copy()
    env['PYTHONPATH'] = os.getcwd()

    # Start server
    cmd = [
        sys.executable, "-m", "uvicorn",
        "backend_api:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--reload"
    ]

    try:
        subprocess.run(cmd, env=env)
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)


def main():
    """Main function"""
    print("🔧 E-Encrypt Backend Setup")
    print("=" * 50)

    # Check dependencies
    missing = check_dependencies()
    if missing:
        print(f"❌ Missing dependencies: {', '.join(missing)}")
        response = input("📦 Install missing dependencies? (y/n): ")
        if response.lower() == 'y':
            install_dependencies()
        else:
            print("❌ Cannot proceed without dependencies")
            sys.exit(1)

    # Create directories
    create_directories()

    # Check if backend_api.py exists
    if not os.path.exists("backend_api.py"):
        print("❌ backend_api.py not found!")
        print("Please make sure you're in the correct directory.")
        sys.exit(1)

    # Display info
    print("\n" + "=" * 50)
    print("🌐 Server will start at: http://localhost:8000")
    print("📚 API Documentation: http://localhost:8000/api/docs")
    print("🔑 Test Users:")
    print("   • alice:password123")
    print("   • bob:password123")
    print("   • charlie:password123")
    print("   • david:password123")
    print("   • emma:password123")
    print("=" * 50)

    # Ask to open browser
    response = input("\n🌐 Open API documentation in browser? (y/n): ")
    if response.lower() == 'y':
        webbrowser.open("http://localhost:8000/api/docs")

    # Start server
    start_server()


if __name__ == "__main__":
    main()