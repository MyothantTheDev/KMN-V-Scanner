#!/bin/bash

# Create data directory if it doesn't exist
mkdir -p data

# Export environment variables
export NVD_API_KEY="e0f9bf5e-63fb-4c08-9973-be97e45e2669"

# Function to display help message
show_help() {
    echo "Usage: ./manage.sh [command] [options]"
    echo ""
    echo "Commands:"
    echo "  clean         - Clean the vulnerability database"
    echo "  download      - Download vulnerabilities from NVD"
    echo "  run           - Run the web application"
    echo "  scan          - Run port scan and service detection"
    echo "  discover      - Discover active hosts in local network"
    echo "  help         - Show this help message"
    echo ""
    echo "Scan options:"
    echo "  ./manage.sh scan <target> [options]"
    echo "    --start-port N    Start port (default: 1)"
    echo "    --end-port N      End port (default: 65535)"
    echo ""
    echo "Discover options:"
    echo "  ./manage.sh discover <ip-address>"
    echo "    --max-workers N   Maximum concurrent workers (default: 50)"
    echo ""
    echo "Examples:"
    echo "  ./manage.sh scan localhost"
    echo "  ./manage.sh scan example.com --start-port 80 --end-port 443"
    echo "  ./manage.sh discover 192.168.1.1"
}

# Function to check if python virtual environment exists
check_venv() {
    if [ ! -d "venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt
    else
        source venv/bin/activate
    fi
}

# Function to download vulnerabilities
download_vulns() {
    echo "Downloading vulnerabilities..."
    python3 download_vulns.py
}

# Function to run the web interface
run_web() {
    echo "Starting web interface..."
    python3 app.py
}

# Function to clean the database
clean() {
    echo "Cleaning database..."
    rm -f data/vuln.db
    rm -f data/portscan.db
    rm -f data/network.db
}

# Main script logic
case "$1" in
    "download")
        check_venv
        download_vulns
        ;;
    "run")
        check_venv
        run_web
        ;;
    "clean")
        clean
        ;;
    "scan")
        if [ -z "$2" ]; then
            echo "Error: Target is required"
            echo "Usage: ./manage.sh scan <target> [options]"
            exit 1
        fi
        
        check_venv
        
        # Build the command with target and any additional options
        target="$2"
        shift 2  # Remove 'scan' and target from arguments
        
        # Run the scanner with all remaining arguments
        python port_scanner.py "$target" "$@"
        ;;
    
    "discover")
        if [ -z "$2" ]; then
            echo "Error: IP address is required"
            echo "Usage: ./manage.sh discover <ip-address> [options]"
            exit 1
        fi
        
        check_venv
        
        # Build the command with IP and any additional options
        ip="$2"
        shift 2  # Remove 'discover' and IP from arguments
        
        # Run the network discovery with all remaining arguments
        python network_discovery.py "$ip" "$@"
        ;;
    
    "help"|*)
        show_help
        ;;
esac
