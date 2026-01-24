#!/bin/bash

# E-Encrypt Pro Installation Script

echo "🔐 Installing E-Encrypt Pro..."

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is required. Please install Python 3.8+"
    exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create database
echo "🗄️ Creating database..."
python -c "
from src.database import CompleteDatabase
db = CompleteDatabase()
print('✅ Database created successfully')
"

echo ""
echo "🎉 Installation complete!"
echo ""
echo "🚀 To run E-Encrypt Pro:"
echo "   source venv/bin/activate"
echo "   streamlit run src/main.py"
echo ""
echo "🌐 Open browser: http://localhost:8501"
echo "🔑 Default users: alice, bob, charlie, david, emma"
echo "   Password: password123"
echo ""