import ipaddress
import subprocess
import concurrent.futures
from rich.console import Console
from rich.table import Table
import socket
import sqlite3
from datetime import datetime
import os
import logging

console = Console()
DB_PATH = 'data/network.db'
logging.basicConfig(level=logging.DEBUG)

def create_database():
    """Create the network discovery database."""
    try:
        # Checking data directory exists
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Drop and recreate the table
        cursor.execute('DROP TABLE IF EXISTS network_hosts')
        
        # Create the network_hosts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_hosts (
                ip_address TEXT,
                hostname TEXT,
                scan_time TEXT,
                status TEXT CHECK(status IN ('active', 'inactive')),
                network_class TEXT CHECK(network_class IN ('A', 'B', 'C')),
                PRIMARY KEY (ip_address, network_class)
            )
        ''')
        
        # Create indexes for better query performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON network_hosts(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_network_class ON network_hosts(network_class)')
        
        conn.commit()
        print("Database created successfully")
        return conn, cursor
        
    except Exception as e:
        print(f"Error creating database: {e}")
        raise

def determine_network_class(ip):
    """Determine the network class and return network information."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:
            return None, "Not a private IP address"
        
        first_octet = int(ip.split('.')[0])
        
        if first_octet <= 127:  # Class A
            network = ipaddress.ip_network(f"{ip.split('.')[0]}.0.0.0/8", strict=False)
            return network, "A"
        elif first_octet <= 191:  # Class B
            network = ipaddress.ip_network(f"{'.'.join(ip.split('.')[:2])}.0.0/16", strict=False)
            return network, "B"
        elif first_octet <= 223:  # Class C
            network = ipaddress.ip_network(f"{'.'.join(ip.split('.')[:3])}.0/24", strict=False)
            return network, "C"
        else:
            return None, "Invalid network class"
    except ValueError:
        return None, "Invalid IP address"

def ping_host(ip):
    """Ping a single host and return its status."""
    try:
        # Use ping with a short timeout
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        if result.returncode == 0:
            try:
                hostname = socket.gethostbyaddr(str(ip))[0]
            except socket.herror:
                hostname = "Unknown"
            return str(ip), hostname, "active"
        return None
    except Exception:
        return None

def save_host_result(cursor, ip_address, hostname, status, network_class):
    """Save host result to database."""
    try:
        scan_time = datetime.now().isoformat()
        cursor.execute('''
            INSERT OR REPLACE INTO network_hosts 
            (ip_address, hostname, scan_time, status, network_class)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip_address, hostname or 'Unknown', scan_time, status, network_class))
        cursor.connection.commit()
        logging.debug(f"Saved host result: IP={ip_address}, Status={status}, Class={network_class}")
    except Exception as e:
        logging.error(f"Error saving host result: {e}")
        raise

def display_results(active_hosts):
    """Display network discovery results in a table."""
    if not active_hosts:
        console.print("\n[yellow]No active hosts found in the network[/yellow]")
        return
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("IP Address")
    table.add_column("Hostname")
    
    for ip, hostname, _ in active_hosts:
        table.add_row(
            ip,
            hostname or "Unknown"
        )
    
    console.print("\n[bold green]Active Hosts:[/bold green]")
    console.print(table)

def discover_network(target_ip, max_workers=50):
    """Perform network discovery using ping sweep."""
    # Determine network class and range
    network, net_class = determine_network_class(target_ip)
    if not network:
        console.print(f"[red]Error: {net_class}[/red]")
        return
    
    print(f"\nStarting network discovery for {target_ip}")
    print(f"Network Class: {net_class}")
    print(f"Network Range: {network}")
    
    try:
        conn, cursor = create_database()
        active_hosts = []
        total_hosts = network.num_addresses
        hosts_scanned = 0
        
        # First, mark all hosts in this network as inactive
        cursor.execute('''
            UPDATE network_hosts 
            SET status = 'inactive', scan_time = ?
            WHERE network_class = ? AND 
                  ip_address LIKE ?
        ''', (datetime.now().isoformat(), net_class, network.network_address.exploded.rsplit('.', 1)[0] + '.%'))
        conn.commit()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {
                executor.submit(ping_host, ip): ip 
                for ip in network.hosts()
            }
            
            for future in concurrent.futures.as_completed(future_to_ip):
                hosts_scanned += 1
                progress = int((hosts_scanned / total_hosts) * 100)
                print(f"Scanning network... {progress}% complete", end='\r')
                
                result = future.result()
                if result:  # Only process active hosts
                    ip, hostname, status = result
                    active_hosts.append((ip, hostname, status))
                    # Save to database
                    save_host_result(cursor, ip, hostname, status, net_class)
        
        print("\n")  # Clear the progress line
        
        # Sort hosts by IP address
        active_hosts.sort(key=lambda x: [int(i) for i in x[0].split('.')])
        
        # Display results
        display_results(active_hosts)
        print(f"\nFound {len(active_hosts)} active hosts in the network")
        
    except Exception as e:
        print(f"Error during network discovery: {e}")
        raise
    
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Network discovery using ping sweep')
    parser.add_argument('target_ip', help='Target IP address to determine network range')
    parser.add_argument('--max-workers', type=int, default=50,
                      help='Maximum number of concurrent workers (default: 50)')
    
    args = parser.parse_args()
    discover_network(args.target_ip, args.max_workers)
