from scapy.all import ARP, Ether, srp, sniff, IP, TCP, sr1
import netifaces
import ipaddress
import json
from collections import defaultdict
from datetime import datetime
import threading
import time
import nmap  # You'll need to: pip install python-nmap

def get_local_network():
    # Get the default gateway
    gws = netifaces.gateways()

    # Get the network interface name
    iface = gws['default'][netifaces.AF_INET][1]

    # Get the network interface IP address
    ip_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
    ip_address = ip_info['addr']
    netmask = ip_info['netmask']

    # Calculate the network range
    ip_network = ipaddress.IPv4Network(f'{ip_address}/{netmask}', strict=False)
    return str(ip_network)

def scan_ports(ip, ports=None):
    if ports is None:
        ports = [20, 21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080]  # Common ports
    
    nm = nmap.PortScanner()
    # Arguments: -sV for service/version detection, -O for OS detection
    # Note: OS detection requires root privileges
    nm.scan(ip, arguments=f'-sV -O -p{",".join(map(str, ports))}')
    
    try:
        host_info = {
            'ports': [],
            'os': nm[ip].get('osmatch', [{'name': 'Unknown'}])[0]['name'],
            'vendor': nm[ip].get('vendor', {}).get(nm[ip]['addresses'].get('mac', ''), 'Unknown')
        }
        
        for port in nm[ip].all_tcp():
            port_info = nm[ip]['tcp'][port]
            host_info['ports'].append({
                'port': port,
                'state': port_info['state'],
                'service': port_info['name'],
                'version': port_info['version']
            })
        
        return host_info
    except Exception as e:
        return {
            'ports': [],
            'os': 'Unknown',
            'vendor': 'Unknown',
            'error': str(e)
        }

def scan_network(ip_range):
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and get the response
    result = srp(packet, timeout=2, verbose=False)[0]

    # Parse the result and extract information
    hosts = []
    for sent, received in result:
        host = {
            'ip': received.psrc,
            'mac': received.hwsrc,
        }
        # Get additional information about the host
        print(f"Scanning details for {host['ip']}...")
        host_details = scan_ports(host['ip'])
        host.update(host_details)
        hosts.append(host)
    return hosts

def write_to_json(hosts, filename='network_hosts.json'):
    with open(filename, 'w') as file:
        json.dump(hosts, file, indent=4)
    print(f"Hosts information written to {filename}")

class NetworkMonitor:
    def __init__(self):
        self.connections = defaultdict(lambda: defaultdict(int))
        self.is_monitoring = False
        self.monitor_thread = None

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Increment the connection counter
            self.connections[src_ip][dst_ip] += 1

    def start_monitoring(self):
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def _monitor(self):
        while self.is_monitoring:
            sniff(prn=self.packet_callback, store=False, timeout=10)

    def stop_monitoring(self):
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def get_connections(self):
        return dict(self.connections)

def write_connections_to_json(connections, filename='network_connections.json'):
    formatted_connections = {
        'timestamp': datetime.now().isoformat(),
        'connections': connections
    }
    with open(filename, 'w') as file:
        json.dump(formatted_connections, file, indent=4)
    print(f"Connection information written to {filename}")

def main():
    ip_range = get_local_network()
    print(f"Scanning network: {ip_range}")
    hosts = scan_network(ip_range)
    
    print("\nAvailable devices in the network:")
    print("-" * 80)
    for host in hosts:
        print(f"\nIP: {host['ip']}")
        print(f"MAC: {host['mac']}")
        print(f"Vendor: {host['vendor']}")
        print(f"OS: {host['os']}")
        print("Open ports:")
        for port in host['ports']:
            print(f"  {port['port']}/tcp - {port['state']} - {port['service']} {port['version']}")
    
    write_to_json(hosts)

    print("\nStarting network traffic monitoring...")
    monitor = NetworkMonitor()
    monitor.start_monitoring()

    try:
        time.sleep(60) ## temp. Should probably replace with a polling mechanism
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    finally:
        monitor.stop_monitoring()
        connections = monitor.get_connections()
        write_connections_to_json(connections)
        
        print("\nNetwork connections detected:")
        for src_ip, destinations in connections.items():
            print(f"\nSource IP: {src_ip}")
            for dst_ip, count in destinations.items():
                print(f"  → {dst_ip}: {count} packets")

if __name__ == "__main__":
    main()
