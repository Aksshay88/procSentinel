#!/bin/bash

echo "🚀 Starting ProcSentinel Web UI..."
echo ""

# Check if dependencies are installed
echo "📦 Checking dependencies..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python 3."
    exit 1
fi

if ! command -v npm &> /dev/null; then
    echo "❌ npm not found. Please install Node.js and npm."
    exit 1
fi

# Check Python dependencies
echo "🐍 Checking Python dependencies..."
python3 -c "import flask" 2>/dev/null || {
    echo "⚠️  Flask not found. Installing..."
    pip3 install flask flask-cors pyjwt
}

# Check frontend dependencies
if [ ! -d "frontend/node_modules" ]; then
    echo "📦 Installing frontend dependencies..."
    cd frontend && npm install && cd ..
fi

echo ""
echo "✅ All dependencies ready!"
echo ""
echo "🔧 Starting services..."
echo ""

# Start backend in background
echo "Starting backend API on http://localhost:5000..."
python3 api_server.py &
BACKEND_PID=$!

# Wait for backend to start
sleep 3

# Start frontend in background
echo "Starting frontend on http://localhost:5173..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✨ ProcSentinel Web UI is ready!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🌐 Frontend: http://localhost:5173"
echo "🔌 Backend:  http://localhost:5000"
echo ""
echo "👤 Login with:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "Press Ctrl+C to stop all services"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Wait for Ctrl+C
trap "echo ''; echo '🛑 Stopping services...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo '✅ Stopped'; exit 0" SIGINT SIGTERM

wait
