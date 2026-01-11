#!/bin/bash
# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is required but not found!"
    exit 1
fi

# Check if procwatch can be imported
if ! python3 -c "from procwatch.api import run_api_server" 2>/dev/null; then
    echo "❌ ProcWatch modules not found. Make sure you're in the correct directory."
    exit 1
fi

# Default values
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8080}"
CONFIG="${CONFIG:-}"
MODEL="${MODEL:-}"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --config)
            CONFIG="--config $2"
            shift 2
            ;;
        --model)
            MODEL="--model $2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host HOST     Host to bind to (default: 0.0.0.0)"
            echo "  --port PORT     Port to bind to (default: 8080)"
            echo "  --config FILE   Config YAML file"
            echo "  --model FILE    ML model file"
            echo "  --help          Show this help"
            echo ""
            echo "Environment variables:"
            echo "  HOST            Same as --host"
            echo "  PORT            Same as --port"
            echo "  CONFIG          Same as --config"
            echo "  MODEL           Same as --model"
            echo ""
            echo "Examples:"
            echo "  $0"
            echo "  $0 --port 9000"
            echo "  $0 --host localhost --port 8080"
            echo "  PORT=9000 $0"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "📋 Configuration:"
echo "   Host: $HOST"
echo "   Port: $PORT"
echo ""

# Start the server
echo "✅ Starting server..."
python3 procwatch.py api --host "$HOST" --port "$PORT" $CONFIG $MODEL &
SERVER_PID=$!

echo "📡 API Endpoints:"
echo "   http://$HOST:$PORT/api"
echo "   http://$HOST:$PORT/api/stats"
echo "   http://$HOST:$PORT/api/processes"
echo "   http://$HOST:$PORT/api/suspicious"
echo ""
echo "🌐 Web UI:"
echo "   Open webui.html in your browser"
if [ "$HOST" = "0.0.0.0" ]; then
    echo "   (Update API_BASE to http://localhost:$PORT/api if needed)"
else
    echo "   (Update API_BASE to http://$HOST:$PORT/api if needed)"
fi

wait $SERVER_PID
