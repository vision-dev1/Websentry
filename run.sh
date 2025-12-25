#!/bin/bash

echo "Website Vulnerability Scanner"
echo "============================="
echo ""

if grep -q "Kali" /etc/os-release 2>/dev/null; then
    echo "Detected Kali Linux"
    echo "Make sure you have installed the required packages:"
    echo "sudo apt install python3-requests"
    echo ""
fi

if [ -f "requirements.txt" ]; then
    echo "Found requirements.txt - you can install dependencies with:"
    echo "pip install -r requirements.txt"
    echo ""
fi

echo "Starting Website Vulnerability Scanner on http://localhost:8081..."
echo "Press Ctrl+C to stop the server"
echo ""

python3 scanner.py