FROM python:3.9-slim

# Install necessary packages
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install python libraries
RUN pip install python-nmap scapy

# Copy the python script
COPY network_scan.py /usr/src/app/network_scan.py

# Set the working directory
WORKDIR /usr/src/app

# Run the script
CMD ["python", "network_scan.py"]
