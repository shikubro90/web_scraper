#!/bin/bash

# Web Scraper Setup Script

echo "================================"
echo "Web Scraper Setup Script"
echo "================================"
echo ""

# Check Python version
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d ' ' -f 2)
    echo "Python version: $PYTHON_VERSION"
else
    echo "Error: Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check Node.js version
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo "Node.js version: $NODE_VERSION"
else
    echo "Error: Node.js is not installed. Please install Node.js 16 or higher."
    exit 1
fi

echo ""
echo "Setting up backend..."
echo "---------------------"

cd backend

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

echo ""
echo "Backend setup complete!"
echo ""
cd ..

echo "Setting up frontend..."
echo "---------------------"

cd frontend

# Install dependencies
if [ ! -d "node_modules" ]; then
    echo "Installing Node dependencies..."
    npm install
else
    echo "Dependencies already installed."
fi

echo ""
echo "Frontend setup complete!"
echo ""
cd ..

echo "================================"
echo "Setup complete!"
echo "================================"
echo ""
echo "To start the application:"
echo ""
echo "1. Start the backend server:"
echo "   cd backend"
echo "   source venv/bin/activate"
echo "   python app.py"
echo ""
echo "2. In a new terminal, start the frontend:"
echo "   cd frontend"
echo "   npm start"
echo ""
echo "3. Open your browser and go to: http://localhost:3000"
echo ""
