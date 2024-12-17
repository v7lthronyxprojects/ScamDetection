import requests
import pandas as pd
import json
import os
import tldextract
import hashlib
from datetime import datetime, timedelta
from ratelimit import limits, sleep_and_retry
from urllib.parse import urlparse
from dotenv import load_dotenv
import aiohttp
import asyncio
import backoff
from typing import List, Dict, Optional
from aiohttp import ClientTimeout, ClientSession, TCPConnector
from OTXv2 import OTXv2
import urllib3
import sys

load_dotenv()

from scanner import logger

DATASET_FILE = 'scam_dataset.csv'
FEEDBACK_FILE = 'feedback.json'

PHISHTANK_API_URL = "https://data.phishtank.com/data/online-valid.json"
PHISHTANK_API_KEY = os.getenv('PHISHTANK_API_KEY')

OPENPHISH_API_URL = "https://openphish.com/feed.txt"

URLSCAN_API_URL = os.getenv('URLSCAN_API_URL')
URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY')
VIRUSTOTAL_API_URL = os.getenv('VIRUSTOTAL_API_URL')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
SAFE_BROWSING_API_URL = os.getenv('SAFE_BROWSING_API_URL')
SAFE_BROWSING_KEY = os.getenv('SAFE_BROWSING_KEY')
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/blacklist"
ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY')
TALOS_API_URL = os.getenv('TALOS_API_URL')
MALWARE_DOMAIN_LIST = "https://www.malwaredomainlist.com/hostslist/hosts.txt"
OTX_API_KEY = os.getenv('OTX_API_KEY')
UMBRELLA_API_URL = os.getenv('UMBRELLA_API_URL')
UMBRELLA_KEY = os.getenv('UMBRELLA_KEY')
METADEFENDER_API_URL = os.getenv('METADEFENDER_API_URL')
METADEFENDER_KEY = os.getenv('METADEFENDER_KEY')

ONE_MINUTE = 60
@sleep_and_retry
@limits(calls=30, period=ONE_MINUTE)
def rate_limited_request(url, headers=None, params=None):
    return requests.get(url, headers=headers, params=params, timeout=30)

def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def enrich_url_data(url):
    extracted = tldextract.extract(url)
    domain_hash = hashlib.sha256(extracted.domain.encode()).hexdigest()
    return {
        'url': url,
        'domain': f"{extracted.domain}.{extracted.suffix}",
        'subdomain': extracted.subdomain,
        'domain_hash': domain_hash,
        'tld': extracted.suffix
    }

def fetch_urlscan_data():
    try:
        headers = {'API-Key': URLSCAN_API_KEY}
        response = rate_limited_request(URLSCAN_API_URL, headers=headers)
        response.raise_for_status()
        data = response.json()
        return [result['page']['url'] for result in data.get('results', [])]
    except Exception as e:
        logger.error(f"Error fetching URLScan data: {e}")
        return []

def fetch_phishtank_urls(api_key=PHISHTANK_API_KEY):
    try:
        logger.info("Fetching scam URLs from PhishTank...")
        headers = {'Content-Type': 'application/json'}
        params = {'format': 'json', 'app_key': api_key}
        response = requests.get(PHISHTANK_API_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        scam_urls = [entry['url'] for entry in data]
        logger.info(f"Fetched {len(scam_urls)} URLs from PhishTank.")
        return scam_urls
    except Exception as e:
        logger.error(f"Error fetching PhishTank data: {e}")
        return []

def fetch_openphish_urls():
    try:
        logger.info("Fetching scam URLs from OpenPhish...")
        response = requests.get(OPENPHISH_API_URL, timeout=10)
        response.raise_for_status()
        data = response.text.splitlines()
        scam_urls = [url.strip() for url in data if url.strip()]
        logger.info(f"Fetched {len(scam_urls)} URLs from OpenPhish.")
        return scam_urls
    except Exception as e:
        logger.error(f"Error fetching OpenPhish data: {e}")
        return []

def load_existing_dataset(file_path=DATASET_FILE):
    if os.path.exists(file_path):
        try:
            df = pd.read_csv(file_path)
            existing_urls = set(df['url'].str.lower())
            logger.info(f"Loaded {len(existing_urls)} existing URLs from dataset.")
            return df, existing_urls
        except Exception as e:
            logger.error(f"Error loading existing dataset: {e}")
            return pd.DataFrame(columns=['url', 'label', 'timestamp']), set()
    else:
        logger.info("Dataset file does not exist. Creating a new one.")
        return pd.DataFrame(columns=['url', 'label', 'timestamp']), set()

def append_new_urls(df, new_urls, existing_urls):
    new_entries = []
    for url in new_urls:
        if not validate_url(url):
            continue
        
        normalized_url = url.lower()
        if normalized_url not in existing_urls:
            url_data = enrich_url_data(url)
            url_data.update({
                'label': 'Scam',
                'timestamp': datetime.now().isoformat(),
                'confidence_score': 0.9,
                'last_verified': datetime.now().isoformat()
            })
            new_entries.append(url_data)
            existing_urls.add(normalized_url)
    
    if new_entries:
        new_df = pd.DataFrame(new_entries)
        df = pd.concat([df, new_df], ignore_index=True)
        logger.info(f"Added {len(new_entries)} new scam URLs to the dataset.")
    
    return df

def clean_dataset(df):
    df = df.drop_duplicates(subset=['domain_hash'], keep='last')
    cutoff_date = datetime.now() - timedelta(days=90)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df[df['timestamp'] > cutoff_date]
    df = df.sort_values('timestamp', ascending=False)
    return df

def save_dataset(df, file_path=DATASET_FILE):
    try:
        df.to_csv(file_path, index=False)
        logger.info(f"Dataset saved to {file_path}. Total entries: {len(df)}.")
    except Exception as e:
        logger.error(f"Error saving dataset: {e}")

def load_and_append_feedback(df, existing_urls, feedback_file=FEEDBACK_FILE):
    if os.path.exists(feedback_file):
        try:
            with open(feedback_file, 'r', encoding='utf-8') as f:
                feedback = json.load(f)
            new_entries = []
            for entry in feedback:
                url = entry.get('url', '').strip()
                label = entry.get('label', '').strip()
                if url and label and url.lower() not in existing_urls:
                    new_entries.append({
                        'url': url,
                        'label': label,
                        'timestamp': entry.get('timestamp', datetime.now().isoformat())
                    })
                    existing_urls.add(url.lower())
            if new_entries:
                new_df = pd.DataFrame(new_entries)
                df = pd.concat([df, new_df], ignore_index=True)
                logger.info(f"Added {len(new_entries)} URLs from feedback to the dataset.")
                with open(feedback_file, 'w', encoding='utf-8') as f:
                    json.dump([], f, ensure_ascii=False, indent=4)
            else:
                logger.info("No new feedback URLs to add.")
            return df
        except Exception as e:
            logger.error(f"Error loading feedback: {e}")
            return df
    else:
        logger.info("No feedback file found.")
        return df

@backoff.on_exception(backoff.expo, aiohttp.ClientError, max_tries=3)
async def fetch_url_async(session: ClientSession, url: str, headers: Optional[Dict] = None) -> Optional[str]:
    timeout = ClientTimeout(total=30)
    try:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            response.raise_for_status()
            return await response.text()
    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        return None

async def fetch_safe_browsing_data():
    payload = {
        "client": {
            "clientId": "your-client-id",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": "http://example.com"}]
        }
    }
    headers = {"Content-Type": "application/json"}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{SAFE_BROWSING_API_URL}?key={SAFE_BROWSING_KEY}",
                json=payload,
                headers=headers
            ) as response:
                data = await response.json()
                return [match['threat']['url'] for match in data.get('matches', [])]
    except Exception as e:
        logger.error(f"Error fetching Safe Browsing data: {e}")
        return []

async def fetch_abuseipdb_data():
    headers = {'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(ABUSEIPDB_API_URL, headers=headers) as response:
                data = await response.json()
                return [f"http://{ip}" for ip in data.get('data', [])]
    except Exception as e:
        logger.error(f"Error fetching AbuseIPDB data: {e}")
        return []

async def fetch_umbrella_data():
    headers = {'Authorization': f'Bearer {UMBRELLA_KEY}'}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(UMBRELLA_API_URL, headers=headers) as response:
                data = await response.json()
                return [entry['url'] for entry in data.get('domains', [])]
    except Exception as e:
        logger.error(f"Error fetching Umbrella data: {e}")
        return []

async def fetch_metadefender_data():
    headers = {'apikey': METADEFENDER_KEY}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(METADEFENDER_API_URL, headers=headers) as response:
                data = await response.json()
                return [url['url'] for url in data.get('urls', [])]
    except Exception as e:
        logger.error(f"Error fetching MetaDefender data: {e}")
        return []

async def fetch_malware_domain_list():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(MALWARE_DOMAIN_LIST) as response:
                text = await response.text()
                return [line.split()[1] for line in text.splitlines() 
                       if line and not line.startswith('#')]
    except Exception as e:
        logger.error(f"Error fetching Malware Domain List: {e}")
        return []

def fetch_otx_data():
    try:
        otx = OTXv2(OTX_API_KEY)
        urls = []
        pulses = otx.getall_iter()
        for pulse in pulses:
            if pulse.get('indicators'):
                for indicator in pulse['indicators']:
                    if indicator.get('type') in ['URL', 'hostname', 'domain']:
                        urls.append(indicator.get('indicator'))
        return list(set(urls))
    except Exception as e:
        logger.error(f"Error fetching OTX data: {e}")
        return []

async def fetch_all_sources() -> List[str]:
    connector = TCPConnector(limit=10)
    async with ClientSession(connector=connector) as session:
        tasks = [
            fetch_safe_browsing_data(),
            fetch_abuseipdb_data(),
            fetch_malware_domain_list(),
            fetch_umbrella_data(),
            fetch_metadefender_data()
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    all_urls = []
    all_urls.extend(fetch_phishtank_urls())
    all_urls.extend(fetch_openphish_urls())
    all_urls.extend(fetch_otx_data())
    
    for result in results:
        if isinstance(result, list):
            all_urls.extend(result)
        elif isinstance(result, Exception):
            logger.error(f"Error in async fetch: {result}")
    
    return list(set(all_urls))

class UpdateError(Exception):
    pass

def safe_update():
    backup_file = None
    try:
        if os.path.exists(DATASET_FILE):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = f"{DATASET_FILE}.{timestamp}.bak"
            os.rename(DATASET_FILE, backup_file)
            logger.info(f"Created backup: {backup_file}")

        main()
        
        if backup_file and os.path.exists(backup_file):
            os.remove(backup_file)
            logger.info("Update successful, removed backup file")
            
    except Exception as e:
        logger.error(f"Update failed: {e}")
        if backup_file and os.path.exists(backup_file):
            os.rename(backup_file, DATASET_FILE)
            logger.info("Restored from backup")
        raise UpdateError(f"Dataset update failed: {str(e)}")

def main():
    all_urls = asyncio.run(fetch_all_sources())
    logger.info(f"Fetched total of {len(all_urls)} URLs from all sources")
    
    df, existing_urls = load_existing_dataset()
    df = append_new_urls(df, all_urls, existing_urls)
    df = load_and_append_feedback(df, existing_urls)
    df = clean_dataset(df)
    
    if os.path.exists(DATASET_FILE):
        backup_file = f"{DATASET_FILE}.{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
        os.rename(DATASET_FILE, backup_file)
    
    save_dataset(df)

if __name__ == "__main__":
    try:
        safe_update()
    except UpdateError as e:
        logger.error(str(e))
        sys.exit(1)
