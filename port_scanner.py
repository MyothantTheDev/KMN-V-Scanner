import sqlite3
import subprocess
import json
import os
from datetime import datetime
import sys
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import argparse
import time
import socket
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

DB_PATH = 'data/portscan.db'
console = Console()

def is_valid_target(target):
    """Validate target input."""
    try:
        # Try to parse as URL first
        parsed = urlparse(target)
        if parsed.netloc:
            return parsed.netloc
        elif parsed.path:
            return parsed.path
        
        # Try to resolve hostname
        socket.gethostbyname(target)
        return target
    except Exception:
        return None

def is_external_target(target):
    """Check if target is external (not localhost/private IP)."""
    try:
        ip = socket.gethostbyname(target)
        # Check if IP is private
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255')
        ]
        ip_parts = list(map(int, ip.split('.')))
        for start, end in private_ranges:
            start_parts = list(map(int, start.split('.')))
            end_parts = list(map(int, end.split('.')))
            if start_parts <= ip_parts <= end_parts:
                return False
        return True
    except:
        # If resolution fails, assume external
        return True

def get_scan_config(target):
    """Get scan configuration based on target type."""
    is_external = is_external_target(target)
    
    if is_external:
        return {
            'timing': '-T2',  # Slower timing for external targets
            'min_rate': '500',  # Medium packet rate
            'max_retries': '2',
            'host_timeout': '2m'
        }
    else:
        return {
            'timing': '-T4',  # Fast timing
            'min_rate': '1000',
            'max_retries': '2',
            'host_timeout': '30s'
        }

def create_database():
    """Create the port scan database and required tables."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS port_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_time TIMESTAMP NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            version TEXT,
            UNIQUE(target, port, protocol)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            vulnerability TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY(scan_id) REFERENCES port_scans(id)
        )
    ''')
    
    return conn, cursor

def check_nmap_installed():
    """Check if nmap is installed."""
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def run_port_discovery(target, start_port=1, end_port=65535):
    """Run nmap port discovery scan."""
    console.print(f"\n[bold blue]Running port discovery scan on {target}...[/bold blue]")
    console.print(f"[blue]Port range: {start_port}-{end_port}[/blue]")
    
    try:
        cmd = [
            'nmap',
            '-p', f'{start_port}-{end_port}',
            '-Pn',  # Treat all hosts as online
            '--open',  # Show only open ports
            '-T4',  # Faster timing
            '--min-rate', '1000',  # Minimum rate of 1000 packets per second
            '--max-retries', '1',  # Single retry
            '--host-timeout', '5m',  # 5 minute timeout
            '-oX', '-',  # Output in XML format to stdout
            target
        ]
        
        console.print("[cyan]Starting port scan...[/cyan]")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            if "Failed to resolve" in stderr:
                console.print(f"[red]Error: Could not resolve hostname {target}[/red]")
            elif "Permission denied" in stderr:
                console.print("[red]Error: Permission denied. Some scan types may require elevated privileges.[/red]")
            else:
                console.print(f"[red]Error running nmap: {stderr}[/red]")
            return []
        
        root = ET.fromstring(stdout)
        open_ports = []
        
        for host in root.findall('.//host'):
            for port in host.findall('.//port'):
                state = port.find('state').get('state')
                if state == 'open':
                    protocol = port.get('protocol')
                    portid = int(port.get('portid'))
                    open_ports.append((protocol, portid))
                    console.print(f"[green]Found open port: {portid}/{protocol}[/green]")
        
        return open_ports

    except Exception as e:
        console.print(f"[red]Error during port discovery: {e}[/red]")
        return []

def run_service_detection(target, open_ports):
    """Run nmap service version detection on specific ports."""
    if not open_ports:
        console.print("[yellow]No open ports found to scan.[/yellow]")
        return []
    
    try:
        port_list = ','.join(str(port) for _, port in open_ports)
        console.print(f"\n[bold blue]Running service detection on ports: {port_list}[/bold blue]")
        
        cmd = [
            'nmap',
            '-p', port_list,
            '-sV',  # Version detection
            '-Pn',  # Treat all hosts as online
            '-T4',  # Faster timing
            '--version-intensity', '2',  # Lighter version detection
            '--max-retries', '1',  # Single retry
            '--host-timeout', '2m',  # 2 minute timeout
            '-oX', '-',  # Output in XML format to stdout
            target
        ]
        
        console.print("[cyan]Starting service detection...[/cyan]")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            if "Failed to resolve" in stderr:
                console.print(f"[red]Error: Could not resolve hostname {target}[/red]")
            elif "Permission denied" in stderr:
                console.print("[red]Error: Permission denied. Some scan types may require elevated privileges.[/red]")
            else:
                console.print(f"[red]Error running nmap: {stderr}[/red]")
            return []
        
        services = []
        root = ET.fromstring(stdout)
        for host in root.findall('.//host'):
            for port in host.findall('.//port'):
                protocol = port.get('protocol')
                portid = int(port.get('portid'))
                state = port.find('state').get('state')
                
                service_elem = port.find('service')
                if service_elem is not None:
                    service = service_elem.get('name', '')
                    version = service_elem.get('product', '')
                    if service_elem.get('version'):
                        version += ' ' + service_elem.get('version')
                    if service_elem.get('extrainfo'):
                        version += ' ' + service_elem.get('extrainfo')
                else:
                    service = ''
                    version = ''
                
                services.append({
                    'protocol': protocol,
                    'port': portid,
                    'state': state,
                    'service': service,
                    'version': version
                })
                console.print(f"[green]Port {portid}/{protocol}: {service} {version}[/green]")
        
        return services
    
    except Exception as e:
        console.print(f"[red]Error during service detection: {e}[/red]")
        return []

def run_vulnerability_scan(target, open_ports):
    """Run nmap vulnerability scan on specific ports."""
    if not open_ports:
        console.print("[yellow]No open ports found to scan.[/yellow]")
        return []
    
    try:
        port_list = ','.join(str(port) for _, port in open_ports)
        console.print(f"\n[bold blue]Running vulnerability scan on ports: {port_list}[/bold blue]")
        
        cmd = [
            'nmap',
            '-p', port_list,
            '--script', 'vuln',  # Run vulnerability scripts
            '-Pn',  # Treat all hosts as online
            '-T4',  # Faster timing
            '--max-retries', '1',  # Single retry
            '--host-timeout', '5m',  # 5 minute timeout for vuln scans
            '-oX', '-',  # Output in XML format to stdout
            target
        ]
        
        console.print("[cyan]Starting vulnerability scan...[/cyan]")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            if "Failed to resolve" in stderr:
                console.print(f"[red]Error: Could not resolve hostname {target}[/red]")
            elif "Permission denied" in stderr:
                console.print("[red]Error: Permission denied. Vulnerability scanning requires root/sudo privileges.[/red]")
            else:
                console.print(f"[red]Error running nmap: {stderr}[/red]")
            return []
        
        vulnerabilities = []
        root = ET.fromstring(stdout)
        
        for host in root.findall('.//host'):
            for port in host.findall('.//port'):
                portid = int(port.get('portid'))
                protocol = port.get('protocol')
                
                # Look for script output containing vulnerability information
                for script in port.findall('.//script'):
                    script_id = script.get('id')
                    output = script.get('output')
                    if output and output.strip():
                        vulnerabilities.append({
                            'port': portid,
                            'protocol': protocol,
                            'vulnerability': script_id,
                            'details': output.strip()
                        })
                        console.print(f"[red]Found vulnerability on port {portid}/{protocol}: {script_id}[/red]")
        
        return vulnerabilities
        
    except Exception as e:
        console.print(f"[red]Error during vulnerability scan: {e}[/red]")
        return []

def save_scan_results(cursor, target, services, vulnerabilities=None):
    """Save scan results to database."""
    scan_time = datetime.now()
    
    for service in services:
        cursor.execute('''
            INSERT OR REPLACE INTO port_scans (target, scan_time, port, protocol, state, service, version)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (target, scan_time, service['port'], service['protocol'], service['state'],
              service.get('service', ''), service.get('version', '')))
        
        scan_id = cursor.lastrowid
        
        # Save vulnerabilities if present
        if vulnerabilities:
            for vuln in vulnerabilities:
                if vuln['port'] == service['port'] and vuln['protocol'] == service['protocol']:
                    cursor.execute('''
                        INSERT INTO vulnerabilities (scan_id, port, protocol, vulnerability, details)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (scan_id, vuln['port'], vuln['protocol'], vuln['vulnerability'], vuln['details']))

def display_results(services, vulnerabilities=None):
    """Display scan results in a formatted table."""
    if not services:
        return
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Port")
    table.add_column("Protocol")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Version")
    
    for service in services:
        table.add_row(
            str(service['port']),
            service['protocol'],
            service['state'],
            service.get('service', ''),
            service.get('version', '')
        )
    
    console.print("\n[bold]Scan Results:[/bold]")
    console.print(table)
    
    if vulnerabilities:
        vuln_table = Table(show_header=True, header_style="bold red")
        vuln_table.add_column("Port")
        vuln_table.add_column("Protocol")
        vuln_table.add_column("Vulnerability")
        vuln_table.add_column("Details")
        
        for vuln in vulnerabilities:
            vuln_table.add_row(
                str(vuln['port']),
                vuln['protocol'],
                vuln['vulnerability'],
                vuln['details']
            )
        
        console.print("\n[bold red]Vulnerability Results:[/bold red]")
        console.print(vuln_table)

def main(target, start_port=1, end_port=65535):
    """Main function to run port scanning."""
    if not target:
        console.print("[red]Error: Target is required[/red]")
        return
    
    # Validate target
    resolved_target = is_valid_target(target)
    if not resolved_target:
        console.print(f"[red]Error: Invalid target '{target}'. Please provide a valid hostname or IP address.[/red]")
        return
    
    if not check_nmap_installed():
        console.print("[red]Error: nmap is not installed. Please install it first.[/red]")
        console.print("On Ubuntu/Debian: [cyan]sudo apt-get install nmap[/cyan]")
        console.print("On CentOS/RHEL: [cyan]sudo yum install nmap[/cyan]")
        console.print("On macOS: [cyan]brew install nmap[/cyan]")
        return
    
    try:
        conn, cursor = create_database()
        
        # Step 1: Port Discovery
        open_ports = run_port_discovery(resolved_target, start_port, end_port)
        if not open_ports:
            console.print("[yellow]No open ports found.[/yellow]")
            return
        
        # Step 2: Service Detection
        services = run_service_detection(resolved_target, open_ports)
        
        # Step 3: Vulnerability Scan
        vulnerabilities = run_vulnerability_scan(resolved_target, open_ports)
        
        # Save and display results
        save_scan_results(cursor, resolved_target, services, vulnerabilities)
        display_results(services, vulnerabilities)
        conn.commit()
        
    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Port scanner using nmap')
    parser.add_argument('target', help='Target to scan (hostname or IP address)')
    parser.add_argument('--start-port', type=int, default=1, help='Start port (default: 1)')
    parser.add_argument('--end-port', type=int, default=65535, help='End port (default: 65535)')
    
    args = parser.parse_args()
    main(args.target, args.start_port, args.end_port)
