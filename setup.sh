#!/bin/bash

# Create virtual environment
python3.9 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Check if running on ARM Mac
if [[ $(uname -m) == "arm64" ]]; then
    echo "Installing for ARM architecture..."
    ARCHFLAGS="-arch arm64" pip install netifaces scapy python-nmap
else
    echo "Installing for standard architecture..."
    pip install python-nmap scapy netifaces
fi

echo "Setup complete! Run 'make run' to start scanning." 