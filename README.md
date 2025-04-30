# Network Scanner and Monitor

A Python-based network scanning and monitoring tool that discovers devices on your local network, performs port scanning, detects operating systems, and monitors network traffic patterns.

## Features

- 🔍 Network device discovery using ARP
- 🚪 Port scanning with service detection
- 💻 Operating system detection
- 📊 Real-time network traffic monitoring
- 📝 JSON output for both host information and network connections
- 🔄 Continuous monitoring with threading

## Prerequisites

- Python 3.x
- Root/Administrator privileges (for OS detection and packet capture)
- Nmap installed on your system

## Setup Steps

```bash
make setup
```

## Usage

```bash
make run
```

## Security Considerations

- This tool should only be used on networks you own or have permission to scan
- Port scanning and OS detection can be detected by security systems
- Some networks may block scanning attempts
- Use responsibly and in accordance with local laws and regulations

## Limitations

- OS detection accuracy varies depending on network conditions and target systems
- Some firewalls may block scanning attempts
- Requires root/administrator privileges for full functionality
- May not detect all devices on networks with certain security measures
