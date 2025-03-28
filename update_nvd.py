#!/usr/bin/env python3
import requests
import json
import sqlite3
import os
import gzip
from datetime import datetime, timedelta
import time
from flask import current_app

# Database path
VULN_DB = 'data/vuln.db'

def get_db_connection():
    """Create database connection and tables."""
    os.makedirs(os.path.dirname(VULN_DB), exist_ok=True)
    conn = sqlite3.connect(VULN_DB)
    conn.row_factory = sqlite3.Row
    
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_data (
            id TEXT PRIMARY KEY,
            description TEXT,
            cvss_score REAL,
            published_date TEXT,
            last_modified_date TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nvd_meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    
    conn.commit()
    return conn

def download_nvd_feed(year):
    """Download NVD feed for a specific year."""
    url = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz'
    
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # Get total size for progress tracking
        total_size = int(response.headers.get('content-length', 0))
        block_size = 8192
        downloaded = 0
        
        # Download in chunks and update progress
        chunks = []
        for data in response.iter_content(block_size):
            chunks.append(data)
            downloaded += len(data)
            progress = (downloaded / total_size) * 100 if total_size > 0 else 0
            
            # Update download progress
            if current_app:
                current_app.update_status.update({
                    'current_action': f'Downloading {year} data...',
                    'download_progress': round(progress, 1)
                })
        
        content = b''.join(chunks)
        decompressed = gzip.decompress(content)
        return json.loads(decompressed)
    except Exception as e:
        print(f'Error downloading feed for {year}: {e}')
        return None

def update_database(force=False):
    """Update the vulnerability database."""
    if current_app:
        current_app.update_status = {
            'status': 'running',
            'current_action': 'Starting update...',
            'current_year': None,
            'total_years': 0,
            'processed_vulns': 0,
            'download_progress': 0,
            'error': None,
            'logs': []  # Add logs array
        }
    
    def log_message(message):
        """Log a message to both console and status."""
        print(message)
        if current_app:
            current_app.update_status['logs'].append(message)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get last update time
        cursor.execute('SELECT value FROM nvd_meta WHERE key = "last_update"')
        result = cursor.fetchone()
        last_update = datetime.fromisoformat(result['value']) if result else None
        
        # If database is older than 24 hours or doesn't exist, or force update
        if force or not last_update or (datetime.now() - last_update) > timedelta(hours=24):
            # Get all years from 2004 to current year
            current_year = datetime.now().year
            years = list(range(2004, current_year + 1))
            total_years = len(years)
            
            if current_app:
                current_app.update_status.update({
                    'total_years': total_years
                })
            
            for i, year in enumerate(years, 1):
                log_message(f'Processing year {year} ({i}/{total_years})...')
                
                if current_app:
                    current_app.update_status.update({
                        'current_year': year,
                        'current_action': f'Processing year {year} ({i}/{total_years})'
                    })
                
                log_message(f'Downloading NVD feed for {year}...')
                data = download_nvd_feed(year)
                if data:
                    vulns = data.get('CVE_Items', [])
                    total_vulns = len(vulns)
                    log_message(f'Processing {total_vulns} vulnerabilities from {year}...')
                    
                    for j, item in enumerate(vulns, 1):
                        cve = item.get('cve', {})
                        impact = item.get('impact', {})
                        
                        # Get CVE ID
                        cve_id = cve.get('CVE_data_meta', {}).get('ID')
                        if not cve_id:
                            continue
                        
                        # Get description
                        description = ''
                        for desc in cve.get('description', {}).get('description_data', []):
                            if desc.get('lang') == 'en':
                                description = desc.get('value', '')
                                break
                        
                        # Get CVSS score
                        cvss_score = None
                        if 'baseMetricV3' in impact:
                            cvss_score = impact['baseMetricV3'].get('cvssV3', {}).get('baseScore')
                        elif 'baseMetricV2' in impact:
                            cvss_score = impact['baseMetricV2'].get('cvssV2', {}).get('baseScore')
                        
                        # Get dates
                        published_date = item.get('publishedDate')
                        last_modified_date = item.get('lastModifiedDate')
                        
                        # Insert or update database
                        cursor.execute('''
                            INSERT OR REPLACE INTO cve_data (
                                id, description, cvss_score, published_date, last_modified_date
                            ) VALUES (?, ?, ?, ?, ?)
                        ''', (
                            cve_id,
                            description,
                            cvss_score,
                            published_date,
                            last_modified_date
                        ))
                        
                        if current_app:
                            current_app.update_status.update({
                                'processed_vulns': j,
                                'total_vulns': total_vulns,
                                'current_action': f'Processing {year}: {j}/{total_vulns} vulnerabilities'
                            })
                    
                    conn.commit()
                    log_message(f'Processed {total_vulns} vulnerabilities from {year}')
                time.sleep(6)  # Rate limiting - NVD allows 10 requests per minute
            
            # Update last update time
            cursor.execute('''
                INSERT OR REPLACE INTO nvd_meta (key, value)
                VALUES ("last_update", ?)
            ''', (datetime.now().isoformat(),))
            conn.commit()
            
            log_message('Database update completed successfully')
            if current_app:
                current_app.update_status.update({
                    'status': 'completed',
                    'current_action': 'Update completed successfully'
                })
            return True
            
        else:
            log_message('Database is already up to date')
            if current_app:
                current_app.update_status.update({
                    'status': 'completed',
                    'current_action': 'Database is already up to date'
                })
            return True
            
    except Exception as e:
        error_msg = str(e)
        log_message(f'Error updating database: {error_msg}')
        if current_app:
            current_app.update_status.update({
                'status': 'error',
                'error': error_msg,
                'current_action': f'Error: {error_msg}'
            })
        conn.rollback()
        return False
    finally:
        conn.close()

if __name__ == '__main__':
    update_database(force=True)
