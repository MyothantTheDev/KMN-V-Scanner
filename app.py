from flask import Flask, render_template, request, jsonify, send_file
from datetime import datetime
import sqlite3
import json
import os
import network_discovery
from threading import Thread
import port_scanner
import threading
import queue
import time
import subprocess
import xml.etree.ElementTree as ET
import uuid
import json
from version import __version__, __description__
import nmap

app = Flask(__name__)

# Version info
VERSION = __version__
DESCRIPTION = __description__

# Database paths
VULN_DB = 'data/vuln.db'
PORTSCAN_DB = 'data/portscan.db'
NETWORK_DB = 'data/network.db'

# Store scan status
scan_status = {}
scan_results = {}

# Store network discovery status
discovery_status = {}
discovery_results = {}

# Global dictionaries to store scan progress
port_scan_status = {}
scan_processes = {}

def get_db_connection(db_path):
    """Create database connection."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    
    # Create tables if they don't exist
    cursor = conn.cursor()
    
    if db_path == PORTSCAN_DB:
        # Create scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                start_port INTEGER NOT NULL,
                end_port INTEGER NOT NULL,
                scan_date TEXT NOT NULL,
                results TEXT NOT NULL
            )
        ''')
        
        # Create vulnerabilities table for CVE data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_data (
                id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                published_date TEXT,
                last_modified_date TEXT
            )
        ''')
        
        # Drop old tables if they exist
        cursor.execute('DROP TABLE IF EXISTS port_scans')
        cursor.execute('DROP TABLE IF EXISTS vulnerabilities')
    
    elif db_path == NETWORK_DB:
        # Create network discoveries table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_discoveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                results TEXT NOT NULL
            )
        ''')
    
    conn.commit()
    return conn

@app.route('/')
def index():
    """Render main page."""
    return render_template('index.html', version=VERSION, description=DESCRIPTION)

@app.route('/search_vulns', methods=['POST'])
def search_vulns():
    """Search vulnerabilities in database."""
    query = request.form.get('query', '')
    
    try:
        conn = get_db_connection(VULN_DB)
        cursor = conn.cursor()
        
        # Search in vulnerabilities table with better matching
        cursor.execute('''
            SELECT id, description, cvss_score, published_date, last_modified_date
            FROM cve_data 
            WHERE id LIKE ? 
               OR description LIKE ?
               OR EXISTS (
                   SELECT 1 
                   FROM cve_data AS c2 
                   WHERE c2.id = cve_data.id 
                   AND (
                       c2.description LIKE ? 
                       OR c2.description LIKE ?
                   )
               )
            ORDER BY 
                CASE 
                    WHEN id LIKE ? THEN 1
                    WHEN description LIKE ? THEN 2
                    ELSE 3
                END,
                published_date DESC
            LIMIT 100
        ''', (
            f'%{query}%',  # Direct ID match
            f'%{query}%',  # Direct description match
            f'% {query} %',  # Word boundary match
            f'%{query},%',  # Comma-separated list match
            f'%{query}%',  # ID priority
            f'%{query}%'   # Description priority
        ))
        
        results = cursor.fetchall()
        vulns = []
        for row in results:
            vuln = {
                'id': row[0],
                'description': row[1],
                'cvss_score': row[2],
                'published_date': row[3],
                'last_modified_date': row[4]
            }
            # Format dates
            if vuln['published_date']:
                vuln['published_date'] = datetime.fromisoformat(vuln['published_date'].replace('Z', '+00:00')).strftime('%Y-%m-%d')
            if vuln['last_modified_date']:
                vuln['last_modified_date'] = datetime.fromisoformat(vuln['last_modified_date'].replace('Z', '+00:00')).strftime('%Y-%m-%d')
            vulns.append(vuln)
        
        return jsonify({'vulnerabilities': vulns})
    
    except Exception as e:
        print(f"Error in search_vulns: {str(e)}")  # Add debug print
        return jsonify({'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/scan_ports', methods=['POST'])
def scan_ports():
    data = request.get_json()
    target = data.get('target')
    start_port = int(data.get('start_port', 1))
    end_port = int(data.get('end_port', 65535))
    
    scan_id = str(uuid.uuid4())
    port_scan_status[scan_id] = {
        'status': 'running',
        'target': target,
        'start_port': start_port,
        'end_port': end_port,
        'current_port': start_port,
        'results': [],
        'message': 'Initializing scan...',
        'start_time': time.time()
    }
    
    # Start scan in background
    Thread(target=run_port_scan, args=(scan_id, target, start_port, end_port)).start()
    
    return jsonify({'status': 'started', 'scan_id': scan_id})

def run_port_scan(scan_id, target, start_port, end_port):
    try:
        total_ports = end_port - start_port + 1
        ports_scanned = 0
        
        # Update status to show scan is starting
        port_scan_status[scan_id]['message'] = f'Starting port scan on {target}'
        
        # Create Nmap PortScanner instance
        nm = nmap.PortScanner()
        
        # Split the port range into chunks for progress updates
        chunk_size = 100
        for port_start in range(start_port, end_port + 1, chunk_size):
            port_end = min(port_start + chunk_size - 1, end_port)
            current_chunk = f"{port_start}-{port_end}"
            
            # Update status with current progress
            progress = (ports_scanned / total_ports) * 100
            elapsed_time = time.time() - port_scan_status[scan_id]['start_time']
            port_scan_status[scan_id].update({
                'current_port': port_start,
                'progress': round(progress, 1),
                'message': f'Scanning ports {current_chunk} ({progress:.1f}% complete)',
                'elapsed_time': round(elapsed_time, 1)
            })
            
            # Scan current chunk of ports
            try:
                nm.scan(target, f'{port_start}-{port_end}', arguments='-sV -Pn')
                
                # Process results for this chunk
                if target in nm.all_hosts():
                    for port in nm[target].all_tcp():
                        if port_start <= port <= port_end:
                            port_info = nm[target]['tcp'][port]
                            if port_info['state'] == 'open':
                                result = {
                                    'port': port,
                                    'protocol': 'tcp',
                                    'state': port_info['state'],
                                    'service': port_info['name'],
                                    'version': port_info['version']
                                }
                                port_scan_status[scan_id]['results'].append(result)
                
                # Update scanned ports count
                ports_scanned += min(chunk_size, end_port - port_start + 1)
                
            except Exception as e:
                port_scan_status[scan_id]['message'] = f'Error scanning ports {current_chunk}: {str(e)}'
        
        # Scan complete
        port_scan_status[scan_id].update({
            'status': 'done',
            'progress': 100,
            'message': f'Scan completed. Found {len(port_scan_status[scan_id]["results"])} open ports.',
            'end_time': time.time()
        })
        
    except Exception as e:
        port_scan_status[scan_id].update({
            'status': 'error',
            'message': f'Error during scan: {str(e)}'
        })

@app.route('/scan_status/<scan_id>', methods=['GET'])
def get_port_scan_status(scan_id):
    """Get the status of a port scan."""
    if scan_id not in port_scan_status:
        return jsonify({'status': 'error', 'message': 'Scan not found'})
    return jsonify(port_scan_status[scan_id])

@app.route('/port_scan', methods=['POST'])
def port_scan():
    """Start a port scan."""
    target = request.form.get('target', '').strip()
    start_port = request.form.get('start_port', '1')
    end_port = request.form.get('end_port', '1000')
    
    if not target:
        return jsonify({'status': 'error', 'message': 'Target is required'})
    
    try:
        start_port = int(start_port)
        end_port = int(end_port)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Invalid port numbers'})
    
    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        return jsonify({'status': 'error', 'message': 'Ports must be between 1 and 65535'})
    
    if start_port > end_port:
        return jsonify({'status': 'error', 'message': 'Start port must be less than or equal to end port'})
    
    # Validate target
    if not port_scanner.is_valid_target(target):
        return jsonify({'status': 'error', 'message': 'Invalid target. Please enter a valid hostname, IP address, or URL.'})
    
    try:
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Step 1: Port Discovery
        cmd = [
            'nmap',
            '-p', f'{start_port}-{end_port}',
            '-Pn',  # Treat all hosts as online
            '--open',  # Show only open ports
            '-T4',  # Faster timing
            '--min-rate', '1000',
            '--max-retries', '1',
            '--host-timeout', '5m',
            '-oX', '-',  # Output in XML format to stdout
            target
        ]
        
        # Start scan process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        scan_processes[scan_id] = {
            'process': process,
            'target': target,
            'start_port': start_port,
            'end_port': end_port,
            'stage': 'discovery',  # Track scanning stage
            'open_ports': []  # Store open ports for next stages
        }
        
        return jsonify({
            'status': 'started',
            'scan_id': scan_id,
            'message': f'Starting port scan ({start_port}-{end_port})...'
        })
        
    except Exception as e:
        print(f"Error in port_scan: {str(e)}")  # Add debug print
        return jsonify({
            'status': 'error',
            'message': f'Failed to start scan: {str(e)}'
        })

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    """Get the status of a port scan."""
    if scan_id not in scan_processes:
        return jsonify({'status': 'error', 'message': 'Invalid scan ID'})

    scan_info = scan_processes[scan_id]
    process = scan_info['process']
    stage = scan_info['stage']
    
    # Calculate progress based on stage
    progress = 0
    status_message = ''
    if stage == 'discovery':
        progress = 15
        status_message = 'Discovering open ports...'
    elif stage == 'service':
        progress = 45
        status_message = 'Detecting services on open ports...'
    elif stage == 'vulnerability':
        progress = 75
        status_message = 'Scanning for vulnerabilities...'
    
    if process.poll() is not None:
        # Process completed
        stdout = process.stdout.read() if process.stdout else ''
        stderr = process.stderr.read() if process.stderr else ''
        
        if process.returncode != 0:
            error_msg = stderr or 'Scan failed with unknown error'
            if 'Failed to resolve' in error_msg:
                error_msg = 'Could not resolve hostname. Please check the target and try again.'
            elif 'Permission denied' in error_msg:
                error_msg = 'Permission denied. Some scan types may require elevated privileges.'
            
            # Clean up process
            del scan_processes[scan_id]
            
            return jsonify({
                'status': 'error',
                'message': error_msg
            })
        
        try:
            # Parse XML output
            root = ET.fromstring(stdout)
            
            if stage == 'discovery':
                # Parse port discovery results
                open_ports = []
                for host in root.findall('.//host'):
                    for port in host.findall('.//port'):
                        state = port.find('state').get('state')
                        if state == 'open':
                            protocol = port.get('protocol')
                            portid = int(port.get('portid'))
                            open_ports.append((protocol, portid))
                
                if not open_ports:
                    del scan_processes[scan_id]
                    return jsonify({
                        'status': 'completed',
                        'message': 'No open ports found.',
                        'results': []
                    })
                
                # Update scan info for service detection
                scan_info['open_ports'] = open_ports
                scan_info['stage'] = 'service'
                
                # Start service detection
                ports = ','.join(str(port[1]) for port in open_ports)
                cmd = [
                    'nmap',
                    '-p', ports,
                    '-sV',  # Service detection
                    '-T4',  # Faster timing
                    '--min-rate', '1000',
                    '--max-retries', '1',
                    '--host-timeout', '5m',
                    '-oX', '-',  # Output in XML format to stdout
                    scan_info['target']
                ]
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                scan_info['process'] = process
                
                return jsonify({
                    'status': 'running',
                    'progress': 30,
                    'message': 'Starting service detection...'
                })
                
            elif stage == 'service':
                # Parse service detection results
                services = []
                for host in root.findall('.//host'):
                    for port in host.findall('.//port'):
                        state = port.find('state').get('state')
                        if state == 'open':
                            service = port.find('service')
                            services.append({
                                'port': int(port.get('portid')),
                                'protocol': port.get('protocol'),
                                'service': service.get('name') if service is not None else 'unknown',
                                'version': service.get('version') if service is not None else ''
                            })
                
                # Update scan info for vulnerability scanning
                scan_info['services'] = services
                scan_info['stage'] = 'vulnerability'
                
                # Start vulnerability scan
                ports = ','.join(str(service['port']) for service in services)
                cmd = [
                    'nmap',
                    '-p', ports,
                    '--script', 'vuln',  # Run vulnerability scripts
                    '-T4',  # Faster timing
                    '--min-rate', '1000',
                    '--max-retries', '1',
                    '--host-timeout', '5m',
                    '-oX', '-',  # Output in XML format to stdout
                    scan_info['target']
                ]
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                scan_info['process'] = process
                
                return jsonify({
                    'status': 'running',
                    'progress': 60,
                    'message': 'Starting vulnerability scan...'
                })
                
            elif stage == 'vulnerability':
                # Parse vulnerability scan results
                vulnerabilities = []
                for host in root.findall('.//host'):
                    for port in host.findall('.//port'):
                        scripts = port.findall('.//script')
                        if scripts:
                            for script in scripts:
                                if script.get('id').endswith('-vuln'):
                                    vulnerabilities.append({
                                        'port': int(port.get('portid')),
                                        'protocol': port.get('protocol'),
                                        'vulnerability': script.get('id'),
                                        'details': script.get('output')
                                    })
                
                # Save results to database
                conn = get_db_connection(PORTSCAN_DB)
                try:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO scan_history (
                            target, start_port, end_port, scan_date, results
                        ) VALUES (?, ?, ?, ?, ?)
                    ''', (
                        scan_info['target'],
                        scan_info['start_port'],
                        scan_info['end_port'],
                        datetime.now().isoformat(),
                        str({
                            'services': scan_info['services'],
                            'vulnerabilities': vulnerabilities
                        })
                    ))
                    conn.commit()
                finally:
                    conn.close()
                
                # Clean up process
                del scan_processes[scan_id]
                
                return jsonify({
                    'status': 'completed',
                    'progress': 100,
                    'message': 'Scan completed successfully',
                    'results': {
                        'services': scan_info['services'],
                        'vulnerabilities': vulnerabilities
                    }
                })
        
        except ET.ParseError:
            del scan_processes[scan_id]
            return jsonify({
                'status': 'error',
                'message': 'Failed to parse scan results'
            })
    
    # Process still running
    return jsonify({
        'status': 'running',
        'progress': progress,
        'message': status_message
    })

def run_network_discovery_async(discovery_id, target_ip, max_workers):
    """Run network discovery in background thread."""
    try:
        discovery_status[discovery_id] = {
            'status': 'running',
            'target': target_ip,
            'start_time': datetime.now().isoformat(),
            'active_hosts': []
        }
            
        # Create database connection for this thread
        conn = sqlite3.connect(NETWORK_DB)
        cursor = conn.cursor()
        
        # Run the discovery
        network_discovery.discover_network(target_ip, max_workers)
        
        # Update status
        discovery_status[discovery_id]['status'] = 'done'
        discovery_status[discovery_id]['end_time'] = datetime.now().isoformat()
        
    except Exception as e:
        print(f"Error in network discovery thread: {str(e)}")
        discovery_status[discovery_id]['status'] = 'error'
        discovery_status[discovery_id]['error'] = str(e)
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/start_discovery', methods=['POST'])
def start_discovery():
    """Start network discovery."""
    try:
        data = request.get_json()
        target = data.get('target')
        max_workers = int(data.get('max_workers', 50))
        
        if not target:
            return jsonify({'error': 'No target IP provided'}), 400
            
        print(f"\nStarting network discovery for {target}")
        
        # Create database if it doesn't exist
        if not os.path.exists(NETWORK_DB):
            network_discovery.create_database()
        
        # Generate unique discovery ID
        discovery_id = str(uuid.uuid4())
            
        # Run discovery in a background thread
        thread = Thread(target=run_network_discovery_async, args=(discovery_id, target, max_workers))
        thread.daemon = True
        thread.start()
        
        return jsonify({'status': 'started', 'discovery_id': discovery_id})
        
    except Exception as e:
        print(f"Error starting discovery: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/discovery_status')
def get_discovery_status():
    """Get network discovery status."""
    try:
        # Get the latest discovery ID
        latest_discovery = None
        latest_time = None
        
        for discovery_id, status in discovery_status.items():
            start_time = datetime.fromisoformat(status['start_time'])
            if not latest_time or start_time > latest_time:
                latest_time = start_time
                latest_discovery = discovery_id
        
        if not latest_discovery:
            return jsonify({
                'status': 'none',
                'message': 'No discovery running'
            })
        
        status = discovery_status[latest_discovery]
        
        # Get active hosts from database
        conn = sqlite3.connect(NETWORK_DB)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address, hostname, network_class, scan_time 
            FROM network_hosts 
            WHERE status = 'active'
            ORDER BY ip_address
        ''')
        active_hosts = [
            {
                'ip_address': row[0],
                'hostname': row[1],
                'network_class': row[2],
                'scan_date': row[3]
            }
            for row in cursor.fetchall()
        ]
        conn.close()

        if discovery_status[latest_discovery].get('completed', False):
            return jsonify({
                'status': 'completed',
                'message': 'Network discovery completed',
                'active_hosts': active_hosts
            })

        return jsonify({
            'status': 'running',
            'message': f'Scanning {status["target"]}...',
            'active_hosts': active_hosts
        })
        
    except Exception as e:
        print(f"Error getting discovery status: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/get_scan_history')
def get_scan_history():
    """Get history of port scans."""
    try:
        conn = get_db_connection(PORTSCAN_DB)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT target, scan_date 
            FROM scan_history 
            ORDER BY scan_date DESC
            LIMIT 10
        ''')
        
        results = cursor.fetchall()
        history = []
        for row in results:
            history.append({
                'target': row[0],
                'scan_date': row[1]
            })
        
        return jsonify({'history': history})
    except Exception as e:
        print(f"Error in get_scan_history: {str(e)}")  # Add debug print
        return jsonify({'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/get_discovery_history')
def get_discovery_history():
    """Get network discovery history."""
    print("\n=== Starting get_discovery_history ===")
    try:
        # Create database if it doesn't exist
        if not os.path.exists(NETWORK_DB):
            network_discovery.create_database()
            return jsonify({'history': []})
        
        conn = sqlite3.connect(NETWORK_DB)
        cursor = conn.cursor()

        # Get all active hosts
        cursor.execute('''
            SELECT ip_address, hostname, scan_time, network_class
            FROM network_hosts
            WHERE status = 'active'
            ORDER BY network_class, ip_address
        ''')
        active_hosts = cursor.fetchall()
        print(f"Total active hosts in database: {len(active_hosts)}")
        print("\nAll active hosts:")
        for host in active_hosts:
            print(f"  - {host}")

        # Group hosts by network class
        networks = {}
        for ip, hostname, scan_time, net_class in active_hosts:
            if net_class not in networks:
                networks[net_class] = {
                    'network_class': net_class,
                    'hosts': [],
                    'scan_date': scan_time
                }
            host_data = {
                'ip': ip,
                'hostname': hostname if hostname != 'Unknown' else None,
                'scan_date': scan_time
            }
            print(f"\nAdded host to network class {net_class}:\n  {json.dumps(host_data, indent=2)}")
            networks[net_class]['hosts'].append(host_data)
            networks[net_class]['scan_date'] = max(networks[net_class]['scan_date'], scan_time)

        # Convert to list and sort by network class
        history = []
        for net_class in sorted(networks.keys()):
            network_data = networks[net_class]
            print(f"\nAdded network class {net_class}:\n  {json.dumps(network_data, indent=2)}")
            history.append(network_data)

        response_data = {'history': history}
        print(f"\nFinal response data:\n{json.dumps(response_data, indent=2)}")
        print("=== Finished get_discovery_history ===\n")
        return jsonify(response_data)

    except Exception as e:
        print(f"Error getting discovery history: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/clear_history', methods=['POST'])
def clear_history():
    """Clear all scan history."""
    try:
        # Clear port scan history
        conn = get_db_connection(PORTSCAN_DB)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM scan_history')
        conn.commit()
        conn.close()

        # Clear network discovery history
        conn = get_db_connection(NETWORK_DB)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM network_discoveries')
        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': 'All history cleared successfully'})
    except Exception as e:
        print(f"Error in clear_history: {str(e)}")  # Add debug print
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/update_nvd', methods=['POST'])
def update_nvd():
    """Update NVD database."""
    try:
        import update_nvd
        
        # Initialize update status
        app.update_status = {
            'status': 'starting',
            'current_action': 'Starting update...',
            'current_year': None,
            'total_years': 0,
            'processed_vulns': 0,
            'download_progress': 0,
            'error': None
        }
        
        # Start update in background thread
        def update_thread():
            update_nvd.update_database(force=True)
        
        Thread(target=update_thread).start()
        
        return jsonify({
            'status': 'started',
            'message': 'Database update started'
        })
        
    except Exception as e:
        print(f"Error in update_nvd: {str(e)}")  # Add debug print
        return jsonify({
            'status': 'error',
            'message': f'Error starting update: {str(e)}'
        }), 500

@app.route('/update_status')
def get_update_status():
    """Get the current status of database update."""
    status = getattr(app, 'update_status', {
        'status': 'unknown',
        'current_action': 'No update in progress'
    })
    return jsonify(status)

@app.route('/check_discovery_status', methods=['GET'])
def check_discovery_status():
    if current_discovery_id is None:
        return jsonify({'status': 'error', 'error': 'No active discovery'})

    discovery = discovery_tasks.get(current_discovery_id)
    if discovery is None:
        return jsonify({'status': 'error', 'error': 'Discovery not found'})

    total_hosts = discovery.get('total_hosts', 0)
    scanned_hosts = discovery.get('scanned_hosts', 0)
    progress = (scanned_hosts / total_hosts * 100) if total_hosts > 0 else 0

    # Get active hosts from database
    try:
        conn = get_db_connection(NETWORK_DB)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address, hostname, network_class, scan_time 
            FROM network_hosts 
            WHERE status = 'active'
            ORDER BY ip_address
        ''')
        active_hosts = [
            {
                'ip_address': row[0],
                'hostname': row[1],
                'network_class': row[2],
                'scan_date': row[3]
            }
            for row in cursor.fetchall()
        ]
        conn.close()

        if discovery.get('completed', False):
            return jsonify({
                'status': 'completed',
                'message': 'Network discovery completed',
                'active_hosts': active_hosts
            })

        return jsonify({
            'status': 'running',
            'progress': round(progress, 1),
            'message': f'Scanned {scanned_hosts} of {total_hosts} hosts',
            'active_hosts': active_hosts
        })
    except Exception as e:
        print(f"Error in check_discovery_status: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': 'Database error: ' + str(e)
        })

@app.route('/vuln_scan', methods=['POST'])
def vuln_scan():
    """Perform vulnerability scan on specific port."""
    try:
        data = request.get_json()
        target = data.get('target')
        port = data.get('port')
        
        if not target or not port:
            return jsonify({'error': 'Target and port are required'}), 400
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Prepare Nmap command for vulnerability scan
        cmd = [
            'nmap',
            '-sV',  # Version detection
            '-Pn',  # Treat host as online
            '--script', 'vuln',  # Run vulnerability scripts
            '-p', str(port),  # Scan specific port
            '--max-retries', '2',
            '-T4',  # Faster timing
            '-oX', '-',  # Output in XML format to stdout
            target
        ]
        
        print(f"Running vulnerability scan command: {' '.join(cmd)}")
        
        # Start scan process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        scan_processes[scan_id] = {
            'process': process,
            'start_time': datetime.now().isoformat(),
            'target': target,
            'port': port,
            'status': 'running',
            'results': []
        }
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'message': f'Vulnerability scan started for {target}:{port}'
        })
        
    except Exception as e:
        print(f"Error starting vulnerability scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/vuln_scan_status/<scan_id>')
def vuln_scan_status(scan_id):
    """Get vulnerability scan status and results."""
    try:
        if scan_id not in scan_processes:
            return jsonify({'error': 'Scan not found'}), 404
        
        scan = scan_processes[scan_id]
        process = scan['process']
        
        # Check if process has completed
        if process.poll() is not None:
            # Process has finished
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                print(f"Vulnerability scan failed with error: {stderr}")
                scan['status'] = 'error'
                scan['error'] = stderr
                return jsonify({
                    'status': 'error',
                    'message': f'Scan failed: {stderr}'
                })
            
            try:
                print("Raw scan output:", stdout)
                # Parse XML output
                root = ET.fromstring(stdout)
                
                # Get host information
                host = root.find('.//host')
                if host is None:
                    print("No host information found in scan results")
                    return jsonify({
                        'status': 'done',
                        'message': 'No vulnerability information found',
                        'results': []
                    })
                
                vulns = []
                
                # First check hostscript results (like ms17-010)
                hostscript = host.find('.//hostscript')
                if hostscript is not None:
                    for script in hostscript.findall('.//script'):
                        script_id = script.get('id', '')
                        output = script.get('output', '').strip()
                        
                        # Get detailed vulnerability information if available
                        tables = []
                        for table in script.findall('.//table'):
                            table_dict = {}
                            for elem in table.findall('.//elem'):
                                key = elem.get('key', '')
                                value = elem.text or ''
                                if key and value:
                                    table_dict[key] = value
                            if table_dict:
                                tables.append(table_dict)
                        
                        if output or tables:
                            vuln_info = {
                                'id': script_id,
                                'output': output,
                            }
                            if tables:
                                formatted_output = []
                                for table in tables:
                                    if 'state' in table and table['state'] == 'VULNERABLE':
                                        formatted_output.extend([
                                            f"VULNERABLE:",
                                            f"  State: {table.get('state', '')}",
                                            f"  Risk factor: {table.get('risk factor', 'Unknown')}",
                                            "",
                                            table.get('description', '').strip(),
                                            "",
                                            "References:",
                                        ])
                                        # Add CVE IDs
                                        if 'ids' in table:
                                            for cve in table['ids'].split('\n'):
                                                formatted_output.append(f"  {cve.strip()}")
                                        # Add URLs
                                        if 'refs' in table:
                                            for ref in table['refs'].split('\n'):
                                                formatted_output.append(f"  {ref.strip()}")
                                vuln_info['output'] = '\n'.join(formatted_output)
                            vulns.append(vuln_info)
                
                # Then check port script results
                port_elem = host.find(f'.//port[@portid="{scan["port"]}"]')
                if port_elem is not None:
                    for script in port_elem.findall('.//script'):
                        script_id = script.get('id', '')
                        output = script.get('output', '').strip()
                        if output:
                            vulns.append({
                                'id': script_id,
                                'output': output
                            })
                
                print(f"Found {len(vulns)} vulnerability results")
                for vuln in vulns:
                    print(f"Script {vuln['id']}:")
                    print(vuln['output'])
                    print("-" * 40)
                
                scan['status'] = 'done'
                scan['results'] = vulns
                
                return jsonify({
                    'status': 'done',
                    'message': f'Found {len(vulns)} vulnerability scan results',
                    'results': vulns
                })
                
            except ET.ParseError as e:
                print(f"Failed to parse scan results: {str(e)}")
                scan['status'] = 'error'
                scan['error'] = f'Failed to parse scan results: {str(e)}'
                return jsonify({
                    'status': 'error',
                    'message': f'Failed to parse scan results: {str(e)}'
                })
        
        # Process still running
        return jsonify({
            'status': 'running',
            'message': 'Scan in progress...'
        })
        
    except Exception as e:
        print(f"Error checking vulnerability scan status: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2025, debug=True)
