import json
import sqlite3
import requests
import os
import tempfile
from datetime import datetime, timedelta, timezone
import time
import shutil

API_KEY = os.getenv('NVD_API_KEY')
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # Changed to API 2.0
FINAL_DB_PATH = 'data/vuln.db'

def create_database():
    try:
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        temp_db_path = os.path.join(temp_dir, 'vuln.db')
        
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_data (
                id TEXT PRIMARY KEY,
                description TEXT,
                published_date TEXT,
                modified_date TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                vendor TEXT,
                product TEXT,
                version_affected TEXT,
                attack_vector TEXT,
                attack_complexity TEXT,
                privileges_required TEXT,
                user_interaction TEXT,
                scope TEXT,
                confidentiality_impact TEXT,
                integrity_impact TEXT,
                availability_impact TEXT
            )
        ''')
        
        return conn, cursor, temp_dir, temp_db_path
    except Exception as e:
        print(f"Error creating database: {e}")
        raise

def fetch_vulnerabilities(start_index=0):
    headers = {
        'apiKey': API_KEY
    }
    
    params = {
        'resultsPerPage': 2000,
        'startIndex': start_index
    }
    
    try:
        print(f"\nMaking request with startIndex={start_index}")
        print(f"Request URL: {BASE_URL}")
        print(f"Request params: {params}")
        
        response = requests.get(BASE_URL, headers=headers, params=params, timeout=30)
        
        if response.status_code == 403:
            print("Error: Invalid API key or API key has expired")
            return None
        elif response.status_code == 429:
            print("Rate limit exceeded. Waiting 60 seconds...")
            time.sleep(60)
            return fetch_vulnerabilities(start_index)
        elif response.status_code == 404:
            print(f"API Request URL: {response.url}")
            print("Error: Invalid API endpoint or parameters")
            return None
        
        response.raise_for_status()
        data = response.json()
        
        total_results = data.get('totalResults', 0)
        results_per_page = data.get('resultsPerPage', 0)
        start_index = data.get('startIndex', 0)
        
        print(f"Total results: {total_results}")
        if total_results > 0:
            print(f"Current page: {start_index // results_per_page + 1} of {(total_results + results_per_page - 1) // results_per_page}")
            print(f"Results in this page: {len(data.get('vulnerabilities', []))}")
        
        return data
    except requests.exceptions.Timeout:
        print("Request timed out. Retrying in 5 seconds...")
        time.sleep(5)
        return fetch_vulnerabilities(start_index)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response text: {e.response.text}")
            print(f"Request URL: {e.response.url}")
        return None

def extract_vendor_product(cve):
    vendors = set()
    products = set()
    versions = set()
    
    try:
        if 'configurations' in cve:
            nodes = cve['configurations']
            if isinstance(nodes, dict) and 'nodes' in nodes:
                for node in nodes['nodes']:
                    if 'cpeMatch' in node:
                        for match in node['cpeMatch']:
                            if 'criteria' in match:
                                cpe = match['criteria']
                                parts = cpe.split(':')
                                if len(parts) > 4:
                                    vendors.add(parts[3])
                                    products.add(parts[4])
                                    if len(parts) > 5:
                                        versions.add(parts[5])
    except Exception as e:
        print(f"Error extracting vendor/product: {e}")
    
    return (
        ','.join(sorted(vendors)) if vendors else "",
        ','.join(sorted(products)) if products else "",
        ','.join(sorted(versions)) if versions else ""
    )

def extract_cvss_metrics(metrics):
    if not metrics:
        return {
            'score': None,
            'vector': None,
            'attack_vector': None,
            'attack_complexity': None,
            'privileges_required': None,
            'user_interaction': None,
            'scope': None,
            'confidentiality_impact': None,
            'integrity_impact': None,
            'availability_impact': None
        }
    
    cvss_data = None
    if 'cvssMetricV31' in metrics:
        cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
    elif 'cvssMetricV2' in metrics:
        cvss_data = metrics['cvssMetricV2'][0].get('cvssData', {})
    
    if not cvss_data:
        return {
            'score': None,
            'vector': None,
            'attack_vector': None,
            'attack_complexity': None,
            'privileges_required': None,
            'user_interaction': None,
            'scope': None,
            'confidentiality_impact': None,
            'integrity_impact': None,
            'availability_impact': None
        }
    
    return {
        'score': cvss_data.get('baseScore'),
        'vector': cvss_data.get('vectorString'),
        'attack_vector': cvss_data.get('attackVector'),
        'attack_complexity': cvss_data.get('attackComplexity'),
        'privileges_required': cvss_data.get('privilegesRequired'),
        'user_interaction': cvss_data.get('userInteraction'),
        'scope': cvss_data.get('scope'),
        'confidentiality_impact': cvss_data.get('confidentialityImpact'),
        'integrity_impact': cvss_data.get('integrityImpact'),
        'availability_impact': cvss_data.get('availabilityImpact')
    }

def process_vulnerabilities(data, cursor, conn):
    if not data or 'vulnerabilities' not in data:
        return 0
    
    count = 0
    for vuln in data['vulnerabilities']:
        try:
            cve = vuln['cve']
            cve_id = cve['id']
            
            description = ""
            if 'descriptions' in cve:
                for desc in cve['descriptions']:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
            
            published_date = cve.get('published', '')
            modified_date = cve.get('lastModified', '')
            
            metrics = cve.get('metrics', {})
            cvss_metrics = extract_cvss_metrics(metrics)
            
            vendor, product, version = extract_vendor_product(cve)
            
            cursor.execute('''
                INSERT OR REPLACE INTO cve_data 
                (id, description, published_date, modified_date, cvss_score, cvss_vector,
                vendor, product, version_affected, attack_vector, attack_complexity,
                privileges_required, user_interaction, scope, confidentiality_impact,
                integrity_impact, availability_impact)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_id, description, published_date, modified_date,
                cvss_metrics['score'], cvss_metrics['vector'],
                vendor, product, version,
                cvss_metrics['attack_vector'], cvss_metrics['attack_complexity'],
                cvss_metrics['privileges_required'], cvss_metrics['user_interaction'],
                cvss_metrics['scope'], cvss_metrics['confidentiality_impact'],
                cvss_metrics['integrity_impact'], cvss_metrics['availability_impact']
            ))
            count += 1
            
            if count % 100 == 0:
                print(f"Processed {count} vulnerabilities in current batch")
                conn.commit()  # Commit every 100 records
        
        except Exception as e:
            print(f"Error processing vulnerability {cve_id if 'cve_id' in locals() else 'unknown'}: {e}")
            continue
    
    conn.commit()  # Final commit for remaining records
    return count

def main():
    if not API_KEY:
        print("Error: NVD_API_KEY environment variable not set")
        return
    
    temp_dir = None
    try:
        conn, cursor, temp_dir, temp_db_path = create_database()
        total_count = 0
        start_index = 0
        
        print("\nFetching all vulnerabilities...")
        
        while True:
            data = fetch_vulnerabilities(start_index)
            if not data:
                print("Error fetching data. Stopping.")
                break
            
            if 'vulnerabilities' not in data:
                print("No vulnerabilities found in response")
                break
            
            count = process_vulnerabilities(data, cursor, conn)
            if count > 0:
                total_count += count
                print(f"\nImported {count} vulnerabilities (Total: {total_count})")
            
            if count < 2000:  # Less than full page, we've reached the end
                break
            
            start_index += 2000
            time.sleep(6)  # Rate limit compliance: 10 requests per minute
        
        # Close database connection
        conn.close()
        
        # Move the database to its final location
        os.makedirs(os.path.dirname(FINAL_DB_PATH), exist_ok=True)
        if os.path.exists(FINAL_DB_PATH):
            os.remove(FINAL_DB_PATH)
        shutil.move(temp_db_path, FINAL_DB_PATH)
        
        print(f"\nSuccessfully imported {total_count} vulnerabilities into the database!")
    
    except Exception as e:
        print(f"Error during import: {e}")
    
    finally:
        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

if __name__ == "__main__":
    main()
